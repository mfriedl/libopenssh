/* $OpenBSD: sftp-server.c,v 1.94 2011/06/17 21:46:16 djm Exp $ */
/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "ssh_api.h"
#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"
#include "myproposal.h"

static void
connect_to_server(char *path, char **args, int *in, int *out)
{
	int c_in, c_out;
	pid_t pid;

	int inout[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];

	if ((pid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	else if (pid == 0) {
		if ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*in);
		close(*out);
		close(c_in);
		close(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_DFL);
		execvp(path, args);
		fprintf(stderr, "exec: %s: %s\n", path, strerror(errno));
		_exit(1);
	}

	close(c_in);
	close(c_out);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-s] [-h hostkey] [-l log_level] [-f log_facility]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	fd_set *rset, *wset;
	int in, out, max, ch, type, fd, skipargs = 0, log_stderr = 1;
	int send_ignore = 0, userauth_sent = 0;
	int is_server = 0;
	ssize_t len, olen, set_size;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_DEBUG3;
	char buf[4*4096];	/* shrink in order to trigger bugs */
	char keybuf[8*1024];
	char *obuf, *hostkey_file = NULL;
	struct ssh *ssh;
	struct kex_params kex_params;

	extern char *optarg;
	extern char *__progname;

	log_init(__progname, log_level, log_facility, log_stderr);

	while (!skipargs && (ch = getopt(argc, argv, "ef:il:h:s")) != -1) {
		switch (ch) {
		case 'e':
			log_stderr = 1;
			break;
		case 'f':
			log_stderr = 0;
			log_facility = log_facility_number(optarg);
			if (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			break;
		case 'h':
			hostkey_file = optarg;
			break;
		case 'i':
			send_ignore = 10;
			break;
		case 's':
			is_server = 1;
			break;
		case 'l':
			log_stderr = 0;
			log_level = log_level_number(optarg);
			if (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		default:
			usage();
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	if (is_server) {
		in = STDIN_FILENO;
		out = STDOUT_FILENO;
	} else
		connect_to_server(argv[optind], argv+optind, &in, &out);

	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;

	set_size = howmany(max + 1, NFDBITS) * sizeof(fd_mask);
	rset = (fd_set *)xmalloc(set_size);
	wset = (fd_set *)xmalloc(set_size);

	memcpy(kex_params.proposal, myproposal, sizeof(kex_params.proposal));
#if 0
	kex_params.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = "ssh-rsa";
#endif
	ssh = ssh_init(is_server, &kex_params);

	if (hostkey_file) {
		if ((fd = open(hostkey_file, O_RDONLY, 0)) < 0)
			fatal("open: %s %s", hostkey_file, strerror(errno));
		if ((len = read(fd, keybuf, sizeof(keybuf))) < 0)
			fatal("read: %s %s", hostkey_file, strerror(errno));
		keybuf[len] = '\0';
		if (ssh_add_hostkey(ssh, keybuf) < 0)
			fatal("could not load hostkey");
		bzero(keybuf, sizeof(keybuf));
	}

	for (;;) {
		/* Process requests packets */
		type = ssh_packet_get(ssh);
		debug("got message type %d session id len %d done %d",
		    type, ssh->kex->session_id_len, ssh->kex->done);

		/* send some test messages */
		if (ssh->kex->done) {
			while (send_ignore) {
				ssh_packet_start(ssh, SSH2_MSG_IGNORE);
				ssh_packet_put_cstring(ssh, "markus");
				ssh_packet_send(ssh);
				send_ignore--;
			}
			if (is_server) {
			} else if (!userauth_sent) {
				ssh_packet_start(ssh, SSH2_MSG_SERVICE_REQUEST);
				ssh_packet_put_cstring(ssh, "ssh-userauth");
				ssh_packet_send(ssh);
				userauth_sent = 1;
			} else if (type == SSH2_MSG_SERVICE_ACCEPT) {
				debug("got a service accept");
			}
		}

		memset(rset, 0, set_size);
		memset(wset, 0, set_size);

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		if (ssh_input_space(ssh, sizeof(buf)) &&
		    ssh_output_space(ssh, 32*1024))
			FD_SET(in, rset);

		obuf = ssh_output_ptr(ssh, (u_int *)&olen);
		if (olen > 0) {
			debug("olen: %lu", olen);
			FD_SET(out, wset);
		}

		if (select(max+1, rset, wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			error("select: %s", strerror(errno));
			exit(2);
		}

		/* copy stdin to input */
		if (FD_ISSET(in, rset)) {
			len = read(in, buf, sizeof buf);
			if (len == 0) {
				debug("read eof");
				exit(0);
			} else if (len < 0) {
				error("read: %s", strerror(errno));
				exit(1);
			} else {
				ssh_input_append(ssh, buf, len);
			}
		}
		/* send output to stdout */
		if (FD_ISSET(out, wset)) {
			len = write(out, obuf, olen);
			if (len < 0) {
				error("write: %s", strerror(errno));
				exit(1);
			} else {
				ssh_output_consume(ssh, len);
			}
		}

	}
}
