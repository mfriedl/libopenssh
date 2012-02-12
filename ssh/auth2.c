/* $OpenBSD: auth2.c,v 1.124 2011/12/07 05:44:38 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "ssh2.h"
#include "packet.h"
#include "log.h"
#include "buffer.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "dispatch.h"
#include "pathnames.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "err.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;

/* methods */

extern Authmethod method_none;
extern Authmethod method_pubkey;
extern Authmethod method_passwd;
extern Authmethod method_kbdint;
extern Authmethod method_hostbased;
#ifdef GSSAPI
extern Authmethod method_gssapi;
#endif
#ifdef JPAKE
extern Authmethod method_jpake;
#endif

Authmethod *authmethods[] = {
	&method_none,
	&method_pubkey,
#ifdef GSSAPI
	&method_gssapi,
#endif
#ifdef JPAKE
	&method_jpake,
#endif
	&method_passwd,
	&method_kbdint,
	&method_hostbased,
	NULL
};

/* protocol */

static int input_service_request(int, u_int32_t, struct ssh *);
static int input_userauth_request(int, u_int32_t, struct ssh *);

/* helper */
static Authmethod *authmethod_lookup(const char *);
static char *authmethods_get(void);

char *
auth2_read_banner(void)
{
	struct stat st;
	char *banner = NULL;
	size_t len, n;
	int fd;

	if ((fd = open(options.banner, O_RDONLY)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1) {
		close(fd);
		return (NULL);
	}
	if (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		return (NULL);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(read, fd, banner, len);
	close(fd);

	if (n != len) {
		xfree(banner);
		return (NULL);
	}
	banner[n] = '\0';

	return (banner);
}

static void
userauth_banner(struct ssh *ssh)
{
	char *banner = NULL;

	if (options.banner == NULL ||
	    strcasecmp(options.banner, "none") == 0 ||
	    (ssh->compat & SSH_BUG_BANNER) != 0)
		return;

	if ((banner = PRIVSEP(auth2_read_banner())) == NULL)
		goto done;

	ssh_packet_start(ssh, SSH2_MSG_USERAUTH_BANNER);
	ssh_packet_put_cstring(ssh, banner);
	ssh_packet_put_cstring(ssh, "");		/* language, unused */
	ssh_packet_send(ssh);
	debug("userauth_banner: sent");
done:
	if (banner)
		xfree(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
void
do_authentication2(Authctxt *authctxt)
{
	struct ssh *ssh = active_state;		/* XXX */
	int r;

	ssh->authctxt = authctxt;		/* XXX move to caller */
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	if ((r = ssh_dispatch_run(ssh, DISPATCH_BLOCK, &authctxt->success)) != 0)
		fatal("%s: ssh_dispatch_run failed: %s", __func__, ssh_err(r));
	ssh->authctxt = NULL;
}

/*ARGSUSED*/
static int
input_service_request(int type, u_int32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	u_int len;
	int acceptit = 0;
	char *service = ssh_packet_get_cstring(ssh, &len);
	ssh_packet_check_eom(ssh);

	if (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	if (strcmp(service, "ssh-userauth") == 0) {
		if (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST, &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	if (acceptit) {
		ssh_packet_start(ssh, SSH2_MSG_SERVICE_ACCEPT);
		ssh_packet_put_cstring(ssh, service);
		ssh_packet_send(ssh);
		ssh_packet_write_wait(ssh);
	} else {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	xfree(service);
	return 0;
}

/*ARGSUSED*/
static int
input_userauth_request(int type, u_int32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	char *user, *service, *method, *style = NULL;
	int authenticated = 0;

	if (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	user = ssh_packet_get_cstring(ssh, NULL);
	service = ssh_packet_get_cstring(ssh, NULL);
	method = ssh_packet_get_cstring(ssh, NULL);
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	if ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	if (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = PRIVSEP(getpwnamallow(user));
		if (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2("input_userauth_request: setting up authctxt for %s", user);
		} else {
			logit("input_userauth_request: invalid user %s", user);
			authctxt->pw = fakepw();
		}
		setproctitle("%s%s", authctxt->valid ? user : "unknown",
		    use_privsep ? " [net]" : "");
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		if (use_privsep)
			mm_inform_authserv(service, style);
		userauth_banner(ssh);
	} else if (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service not allowed: "
		    "(%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);
#ifdef JPAKE
	auth2_jpake_stop(ssh);
#endif

#ifdef GSSAPI
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
#endif

	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;

	/* try to authenticate user */
	m = authmethod_lookup(method);
	if (m != NULL && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh);
	}
	userauth_finish(ssh, authenticated, method);

	xfree(service);
	xfree(user);
	xfree(method);
	return 0;
}

void
userauth_finish(struct ssh *ssh, int authenticated, char *method)
{
	Authctxt *authctxt = ssh->authctxt;
	char *methods;

	if (!authctxt->valid && authenticated)
		fatal("INTERNAL ERROR: authenticated invalid user %s",
		    authctxt->user);

	/* Special handling for root */
	if (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(method))
		authenticated = 0;

	/* Log before sending the reply */
	auth_log(authctxt, authenticated, method, " ssh2");

	if (authctxt->postponed)
		return;

	/* XXX todo: check if multiple auth methods are needed */
	if (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST, &dispatch_protocol_ignore);
		ssh_packet_start(ssh, SSH2_MSG_USERAUTH_SUCCESS);
		ssh_packet_send(ssh);
		ssh_packet_write_wait(ssh);
		/* now we can break out */
		authctxt->success = 1;
	} else {
		/* Allow initial try of "none" auth without failure penalty */
		if (!authctxt->server_caused_failure &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		if (authctxt->failures >= options.max_authtries)
			ssh_packet_disconnect(ssh, AUTH_FAIL_MSG, authctxt->user);
		methods = authmethods_get();
		ssh_packet_start(ssh, SSH2_MSG_USERAUTH_FAILURE);
		ssh_packet_put_cstring(ssh, methods);
		ssh_packet_put_char(ssh, 0);	/* XXX partial success, unused */
		ssh_packet_send(ssh);
		ssh_packet_write_wait(ssh);
		xfree(methods);
	}
}

static char *
authmethods_get(void)
{
	Buffer b;
	char *list;
	int i;

	buffer_init(&b);
	for (i = 0; authmethods[i] != NULL; i++) {
		if (strcmp(authmethods[i]->name, "none") == 0)
			continue;
		if (authmethods[i]->enabled != NULL &&
		    *(authmethods[i]->enabled) != 0) {
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			buffer_append(&b, authmethods[i]->name,
			    strlen(authmethods[i]->name));
		}
	}
	buffer_append(&b, "\0", 1);
	list = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	return list;
}

static Authmethod *
authmethod_lookup(const char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; authmethods[i] != NULL; i++)
			if (authmethods[i]->enabled != NULL &&
			    *(authmethods[i]->enabled) != 0 &&
			    strcmp(name, authmethods[i]->name) == 0)
				return authmethods[i];
	debug2("Unrecognized authentication method name: %s",
	    name ? name : "NULL");
	return NULL;
}

