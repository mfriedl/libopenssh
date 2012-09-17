/* $OpenBSD: packet.c,v 1.176 2012/01/25 19:40:09 markus Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <zlib.h>

#include "xmalloc.h"
#include "buffer.h"
#include "crc32.h"
#include "deattack.h"
#include "compat.h"
#include "ssh1.h"
#include "ssh2.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "mac.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"
#include "ssh.h"
#include "packet.h"
#include "roaming.h"
#include "err.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

struct packet_state {
	u_int32_t seqnr;
	u_int32_t packets;
	u_int64_t blocks;
	u_int64_t bytes;
};

struct packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	struct sshbuf *payload;
};

struct session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	int connection_in;
	int connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	CipherContext receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	CipherContext send_context;

	/* Buffer for raw input data from the socket. */
	struct sshbuf *input;

	/* Buffer for raw output data going to the socket. */
	struct sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	struct sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	struct sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	struct sshbuf *compression_buffer;

	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
	int compression_in_started;
	int compression_out_started;
	int compression_in_failures;
	int compression_out_failures;

	/*
	 * Flag indicating whether packet compression/decompression is
	 * enabled.
	 */
	int packet_compression;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	int initialized;

	/* Set to true if the connection is interactive. */
	int interactive_mode;

	/* Set to true if we are the server side. */
	int server_side;

	/* Set to true if we are authenticated. */
	int after_authentication;

	int keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	int packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	Newkeys *newkeys[MODE_MAX];
	struct packet_state p_read, p_send;

	u_int64_t max_blocks_in, max_blocks_out;
	u_int32_t rekey_limit;

	/* Session key for protocol v1 */
	u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
	u_int ssh1_keylen;

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	Mac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	int rekeying;

	/* Used in packet_set_interactive */
	int set_interactive_called;

	/* Used in packet_set_maxsize */
	int set_maxsize_called;

	/* One-off warning about weak ciphers */
	int cipher_warning_done;

	/* SSH1 CRC compensation attack detector */
	struct deattack_ctx deattack;

	TAILQ_HEAD(, packet) outgoing;
};

struct ssh *
ssh_alloc_session_state(void)
{
	struct ssh *ssh;
	struct session_state *state;

	if ((ssh = calloc(1, sizeof(*ssh))) == NULL ||
	    (ssh->state = state = calloc(1, sizeof(*state))) == NULL) {
		if (ssh)
			free(ssh);
		return NULL;
	}
	state->connection_in = -1;
	state->connection_out = -1;
	state->max_packet_size = 32768;
	state->packet_timeout_ms = -1;
	if (!state->initialized) {
		if ((state->input = sshbuf_new()) == NULL ||
		    (state->output = sshbuf_new()) == NULL ||
		    (state->outgoing_packet = sshbuf_new()) == NULL ||
		    (state->incoming_packet = sshbuf_new()) == NULL)
			goto fail;
		TAILQ_INIT(&state->outgoing);
		TAILQ_INIT(&ssh->private_keys);
		TAILQ_INIT(&ssh->public_keys);
		state->p_send.packets = state->p_read.packets = 0;
		state->initialized = 1;
	}
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	return ssh;
 fail:
	if (state->input)
		sshbuf_free(state->input);
	if (state->output)
		sshbuf_free(state->output);
	if (state->incoming_packet)
		sshbuf_free(state->incoming_packet);
	if (state->outgoing_packet)
		sshbuf_free(state->outgoing_packet);
	state->input = NULL;
	state->output = NULL;
	state->incoming_packet = NULL;
	state->outgoing_packet = NULL;
	free(ssh);
	free(state);
	return NULL;
}

/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
struct ssh *
ssh_packet_set_connection(struct ssh *ssh, int fd_in, int fd_out)
{
	struct session_state *state;
	Cipher *none = cipher_by_name("none");
	int r;

	if (none == NULL)
		fatal("%s: cannot load cipher 'none'", __func__);
	if (ssh == NULL)
		ssh = ssh_alloc_session_state();
	if (ssh == NULL)
		fatal("%s: cound not allocate state", __func__);
	state = ssh->state;
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	if ((r = cipher_init(&state->send_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_DECRYPT)) != 0)
		fatal("%s: cipher_init failed: %s", __func__, ssh_err(r));
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = NULL;
	deattack_init(&state->deattack);
	return ssh;
}

void
ssh_packet_set_timeout(struct ssh *ssh, int timeout, int count)
{
	struct session_state *state = ssh->state;

	if (timeout <= 0 || count <= 0) {
		state->packet_timeout_ms = -1;
		return;
	}
	if ((INT_MAX / 1000) / count < timeout)
		state->packet_timeout_ms = INT_MAX;
	else
		state->packet_timeout_ms = timeout * count * 1000;
}

int
ssh_packet_stop_discard(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	int r;

	if (state->packet_discard_mac) {
		char buf[1024];
		
		memset(buf, 'a', sizeof(buf));
		while (sshbuf_len(state->incoming_packet) <
		    PACKET_MAX_SIZE)
			if ((r = sshbuf_put(state->incoming_packet, buf,
			    sizeof(buf))) != 0)
				return r;
		(void) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), PACKET_MAX_SIZE,
		    NULL, 0);
	}
	logit("Finished discarding for %.200s", ssh_remote_ipaddr(ssh));
	return SSH_ERR_MAC_INVALID;
}

int
ssh_packet_start_discard(struct ssh *ssh, Enc *enc, Mac *mac,
    u_int packet_length, u_int discard)
{
	struct session_state *state = ssh->state;
	int r;

	if (enc == NULL || !cipher_is_cbc(enc->cipher)) {
		if ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			return r;
		return SSH_ERR_MAC_INVALID;
	}
	if (packet_length != PACKET_MAX_SIZE && mac && mac->enabled)
		state->packet_discard_mac = mac;
	if (sshbuf_len(state->input) >= discard &&
	   (r = ssh_packet_stop_discard(ssh)) != 0)
		return r;
	state->packet_discard = discard - sshbuf_len(state->input);
	return 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

int
ssh_packet_connection_is_on_socket(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	/* filedescriptors in and out are the same, so it's a socket */
	if (state->connection_in == state->connection_out)
		return 1;
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(state->connection_in, (struct sockaddr *)&from,
	    &fromlen) < 0)
		return 0;
	tolen = sizeof(to);
	memset(&to, 0, sizeof(to));
	if (getpeername(state->connection_out, (struct sockaddr *)&to,
	    &tolen) < 0)
		return 0;
	if (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		return 0;
	if (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		return 0;
	return 1;
}

void
ssh_packet_get_bytes(struct ssh *ssh, u_int64_t *ibytes, u_int64_t *obytes)
{
	if (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	if (obytes)
		*obytes = ssh->state->p_send.bytes;
}

/* Serialise compression state into a blob for privsep */
static int
ssh_packet_get_compress_state(struct sshbuf *m, struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct sshbuf *b;
	int r;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (state->compression_in_started) {
		if ((r = sshbuf_put_string(b, &state->compression_in_stream,
		    sizeof(state->compression_in_stream))) != 0)
			goto out;
	} else if ((r = sshbuf_put_string(b, NULL, 0)) != 0)
		goto out;
	if (state->compression_out_started) {
		if ((r = sshbuf_put_string(b, &state->compression_out_stream,
		    sizeof(state->compression_out_stream))) != 0)
			goto out;
	} else if ((r = sshbuf_put_string(b, NULL, 0)) != 0)
		goto out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	return r;
}

/* Deserialise compression state from a blob for privsep */
static int
ssh_packet_set_compress_state(struct ssh *ssh, struct sshbuf *m)
{
	struct session_state *state = ssh->state;
	struct sshbuf *b;
	int r;
	const u_char *inblob, *outblob;
	size_t inl, outl;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_stringb(m, b)) != 0)
		goto out;
	if ((r = sshbuf_get_string_direct(b, &inblob, &inl)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &outblob, &outl)) != 0)
		goto out;
	if (inl == 0)
		state->compression_in_started = 0;
	else if (inl != sizeof(state->compression_in_stream)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	} else {
		state->compression_in_started = 1;
		memcpy(&state->compression_in_stream, inblob, inl);
	}
	if (outl == 0)
		state->compression_out_started = 0;
	else if (outl != sizeof(state->compression_out_stream)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	} else {
		state->compression_out_started = 1;
		memcpy(&state->compression_out_stream, outblob, outl);
	}
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

void
ssh_packet_set_compress_hooks(struct ssh *ssh, void *ctx,
    void *(*allocfunc)(void *, u_int, u_int),
    void (*freefunc)(void *, void *))
{
	ssh->state->compression_out_stream.zalloc = (alloc_func)allocfunc;
	ssh->state->compression_out_stream.zfree = (free_func)freefunc;
	ssh->state->compression_out_stream.opaque = ctx;
	ssh->state->compression_in_stream.zalloc = (alloc_func)allocfunc;
	ssh->state->compression_in_stream.zfree = (free_func)freefunc;
	ssh->state->compression_in_stream.opaque = ctx;
}


int
ssh_packet_connection_af(struct ssh *ssh)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	if (getsockname(ssh->state->connection_out, (struct sockaddr *)&to,
	    &tolen) < 0)
		return 0;
	return to.ss_family;
}

/* Sets the connection into non-blocking mode. */

void
ssh_packet_set_nonblocking(struct ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	if (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

int
ssh_packet_get_connection_in(struct ssh *ssh)
{
	return ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

int
ssh_packet_get_connection_out(struct ssh *ssh)
{
	return ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

const char *
ssh_remote_ipaddr(struct ssh *ssh)
{
	/* Check whether we have cached the ipaddr. */
	if (ssh->remote_ipaddr == NULL)
		ssh->remote_ipaddr = ssh_packet_connection_is_on_socket(ssh) ?
		    get_peer_ipaddr(ssh->state->connection_in) :
		    strdup("UNKNOWN");
	if (ssh->remote_ipaddr == NULL)
		return "UNKNOWN";
	return ssh->remote_ipaddr;
}

/* Closes the connection and clears and frees internal data structures. */

void
ssh_packet_close(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	int r;
	u_int mode;

	if (!state->initialized)
		return;
	state->initialized = 0;
	if (state->connection_in == state->connection_out) {
		shutdown(state->connection_out, SHUT_RDWR);
		close(state->connection_out);
	} else {
		close(state->connection_in);
		close(state->connection_out);
	}
	sshbuf_free(state->input);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	for (mode = 0; mode < MODE_MAX; mode++)
		kex_free_newkeys(state->newkeys[mode]);
	if (state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		if (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
		    		(unsigned long long)stream->total_in,
		    		(unsigned long long)stream->total_out,
		    		stream->total_in == 0 ? 0.0 :
		    		(double) stream->total_out / stream->total_in);
			if (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		if (state->compression_in_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (double) stream->total_in / stream->total_out);
			if (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
	if ((r = cipher_cleanup(&state->send_context)) != 0)
		error("%s: cipher_cleanup failed: %s", __func__, ssh_err(r));
	if ((r = cipher_cleanup(&state->receive_context)) != 0)
		error("%s: cipher_cleanup failed: %s", __func__, ssh_err(r));
	if (ssh->remote_ipaddr) {
		free(ssh->remote_ipaddr);
		ssh->remote_ipaddr = NULL;
	}
	free(ssh->state);
	ssh->state = NULL;
}

/* Sets remote side protocol flags. */

void
ssh_packet_set_protocol_flags(struct ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(struct ssh *ssh)
{
	return ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

static int
ssh_packet_init_compression(struct ssh *ssh)
{
	if (!ssh->state->compression_buffer &&
	   ((ssh->state->compression_buffer = sshbuf_new()) == NULL))
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

static int
start_compression_out(struct ssh *ssh, int level)
{
	if (level < 1 || level > 9)
		return SSH_ERR_INVALID_ARGUMENT;
	debug("Enabling compression at level %d.", level);
	if (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	switch (deflateInit(&ssh->state->compression_out_stream, level)) {
	case Z_OK:
		ssh->state->compression_out_started = 1;
		break;
	case Z_MEM_ERROR:
		return SSH_ERR_ALLOC_FAIL;
	default:
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

static int
start_compression_in(struct ssh *ssh)
{
	if (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	switch (inflateInit(&ssh->state->compression_in_stream)) {
	case Z_OK:
		ssh->state->compression_in_started = 1;
		break;
	case Z_MEM_ERROR:
		return SSH_ERR_ALLOC_FAIL;
	default:
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

int
ssh_packet_start_compression(struct ssh *ssh, int level)
{
	int r;

	if (ssh->state->packet_compression && !compat20)
		return SSH_ERR_INTERNAL_ERROR;
	ssh->state->packet_compression = 1;
	if ((r = ssh_packet_init_compression(ssh)) != 0 ||
	    (r = start_compression_in(ssh)) != 0 ||
	    (r = start_compression_out(ssh, level)) != 0)
		return r;
	return 0;
}

/* XXX remove need for separate compression buffer */
static int
compress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	u_char buf[4096];
	int r, status;

	if (ssh->state->compression_out_started != 1)
		return SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	if (sshbuf_len(in) == 0)
		return 0;

	/* Input is the contents of the input buffer. */
	ssh->state->compression_out_stream.next_in = sshbuf_ptr(in);
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	do {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = sizeof(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_MEM_ERROR:
			return SSH_ERR_ALLOC_FAIL;
		case Z_OK:
			/* Append compressed data to output_buffer. */
			if ((r = sshbuf_put(out, buf, sizeof(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				return r;
			break;
		case Z_STREAM_ERROR:
		default:
			ssh->state->compression_out_failures++;
			return SSH_ERR_INVALID_FORMAT;
		}
	} while (ssh->state->compression_out_stream.avail_out == 0);
	return 0;
}

static int
uncompress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	u_char buf[4096];
	int r, status;

	if (ssh->state->compression_in_started != 1)
		return SSH_ERR_INTERNAL_ERROR;

	ssh->state->compression_in_stream.next_in = sshbuf_ptr(in);
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	for (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = sizeof(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_OK:
			if ((r = sshbuf_put(out, buf, sizeof(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				return r;
			break;
		case Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			return 0;
		case Z_DATA_ERROR:
			return SSH_ERR_INVALID_FORMAT;
		case Z_MEM_ERROR:
			return SSH_ERR_ALLOC_FAIL;
		case Z_STREAM_ERROR:
		default:
			ssh->state->compression_in_failures++;
			return SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

/*
 * Causes any further packets to be encrypted using the given key.  The same
 * key is used for both sending and reception.  However, both directions are
 * encrypted independently of each other.
 */

void
ssh_packet_set_encryption_key(struct ssh *ssh, const u_char *key, u_int keylen, int number)
{
	struct session_state *state = ssh->state;
	Cipher *cipher = cipher_by_number(number);
	int r;
	const char *wmsg;

	if (cipher == NULL)
		fatal("%s: unknown cipher number %d", __func__, number);
	if (keylen < 20)
		fatal("%s: keylen too small: %d", __func__, keylen);
	if (keylen > SSH_SESSION_KEY_LENGTH)
		fatal("%s: keylen too big: %d", __func__, keylen);
	memcpy(state->ssh1_key, key, keylen);
	state->ssh1_keylen = keylen;
	if ((r = cipher_init(&state->send_context, cipher, key, keylen,
	    NULL, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, cipher, key, keylen,
	    NULL, 0, CIPHER_DECRYPT) != 0))
		fatal("%s: cipher_init failed: %s", __func__, ssh_err(r));
	if (!state->cipher_warning_done &&
	    ((wmsg = cipher_warning_message(&state->send_context)) != NULL ||
	    (wmsg = cipher_warning_message(&state->send_context)) != NULL)) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
}

/* Start constructing a packet to send. */
void
ssh_packet_start(struct ssh *ssh, u_char type)
{
	int r;

	if ((r = sshpkt_start(ssh, type)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

/* Append payload. */
void
ssh_packet_put_char(struct ssh *ssh, int value)
{
	char ch = value;
	int r;

	if ((r = sshbuf_put(ssh->state->outgoing_packet, &ch, 1)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_int(struct ssh *ssh, u_int value)
{
	int r;

	if ((r = sshpkt_put_u32(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_int64(struct ssh *ssh, u_int64_t value)
{
	int r;

	if ((r = sshpkt_put_u64(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_string(struct ssh *ssh, const void *buf, u_int len)
{
	int r;

	if ((r = sshpkt_put_string(ssh, buf, len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_cstring(struct ssh *ssh, const char *str)
{
	int r;

	if ((r = sshpkt_put_cstring(ssh, str)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_raw(struct ssh *ssh, const void *buf, u_int len)
{
	int r;

	if ((r = sshpkt_put(ssh, buf, len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_bignum(struct ssh *ssh, BIGNUM * value)
{
	int r;

	if ((r = sshpkt_put_bignum1(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_bignum2(struct ssh *ssh, BIGNUM * value)
{
	int r;

	if ((r = sshpkt_put_bignum2(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_put_ecpoint(struct ssh *ssh, const EC_GROUP *curve, const EC_POINT *point)
{
	int r;

	if ((r = sshpkt_put_ec(ssh, point, curve)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

int
ssh_packet_send1(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_char buf[8], *cp;
	int r, i, padding, len;
	u_int checksum;
	u_int32_t rnd = 0;

	/*
	 * If using packet compression, compress the payload of the outgoing
	 * packet.
	 */
	if (state->packet_compression) {
		sshbuf_reset(state->compression_buffer);
		/* Skip padding. */
		if ((r = sshbuf_consume(state->outgoing_packet, 8)) != 0)
			goto out;
		/* padding */
		if ((r = sshbuf_put(state->compression_buffer,
		    "\0\0\0\0\0\0\0\0", 8)) != 0)
			goto out;
		if ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->outgoing_packet);
                if ((r = sshbuf_putb(state->outgoing_packet,
                    state->compression_buffer)) != 0)
			goto out;
	}
	/* Compute packet length without padding (add checksum, remove padding). */
	len = sshbuf_len(state->outgoing_packet) + 4 - 8;

	/* Insert padding. Initialized to zero in packet_start1() */
	padding = 8 - len % 8;
	if (!state->send_context.plaintext) {
		cp = sshbuf_ptr(state->outgoing_packet);
		for (i = 0; i < padding; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[7 - i] = rnd & 0xff;
			rnd >>= 8;
		}
	}
	if ((r = sshbuf_consume(state->outgoing_packet, 8 - padding)) != 0)
		goto out;

	/* Add check bytes. */
	checksum = ssh_crc32(sshbuf_ptr(state->outgoing_packet),
	    sshbuf_len(state->outgoing_packet));
	POKE_U32(buf, checksum);
	if ((r = sshbuf_put(state->outgoing_packet, buf, 4)) != 0)
		goto out;

#ifdef PACKET_DEBUG
	fprintf(stderr, "packet_send plain: ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	/* Append to output. */
	POKE_U32(buf, len);
	if ((r = sshbuf_put(state->output, buf, 4)) != 0)
		goto out;
	if ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet), &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(&state->send_context, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    sshbuf_len(state->outgoing_packet))) != 0)
		goto out;

#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	state->p_send.packets++;
	state->p_send.bytes += len +
	    sshbuf_len(state->outgoing_packet);
	sshbuf_reset(state->outgoing_packet);

	/*
	 * Note that the packet is now only buffered in output.  It won't be
	 * actually sent until packet_write_wait or packet_write_poll is
	 * called.
	 */
	r = 0;
 out:
	return r;
}

int
ssh_set_newkeys(struct ssh *ssh, int mode)
{
	struct session_state *state = ssh->state;
	Enc *enc;
	Mac *mac;
	Comp *comp;
	CipherContext *cc;
	u_int64_t *max_blocks;
	int crypt_type, r;
	const char *wmsg;

	debug2("set_newkeys: mode %d", mode);

	if (mode == MODE_OUT) {
		cc = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		state->p_send.packets = state->p_send.blocks = 0;
		max_blocks = &state->max_blocks_out;
	} else {
		cc = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		state->p_read.packets = state->p_read.blocks = 0;
		max_blocks = &state->max_blocks_in;
	}
	if (state->newkeys[mode] != NULL) {
		debug("set_newkeys: rekeying");
		if ((r = cipher_cleanup(cc)) != 0)
			return r;
		enc  = &state->newkeys[mode]->enc;
		mac  = &state->newkeys[mode]->mac;
		comp = &state->newkeys[mode]->comp;
		mac_clear(mac);
		free(enc->name);
		free(enc->iv);
		free(enc->key);
		free(mac->name);
		free(mac->key);
		free(comp->name);
		free(state->newkeys[mode]);
	}
	state->newkeys[mode] = kex_get_newkeys(ssh, mode);
	if (state->newkeys[mode] == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	if ((r = mac_init(mac)) != 0)
		return r;
	mac->enabled = 1;
	DBG(debug("cipher_init_context: %d", mode));
	if ((r = cipher_init(cc, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->block_size, crypt_type)) != 0)
		return r;
	if (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(cc)) != NULL) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* memset(enc->iv,  0, enc->block_size);
	   memset(enc->key, 0, enc->key_len);
	   memset(mac->key, 0, mac->key_len); */
	if ((comp->type == COMP_ZLIB ||
	    (comp->type == COMP_DELAYED &&
	     state->after_authentication)) && comp->enabled == 0) {
		if ((r = ssh_packet_init_compression(ssh)) < 0)
			return r;
		if (mode == MODE_OUT) {
			if ((r = start_compression_out(ssh, 6)) != 0)
				return r;
		} else {
			if ((r = start_compression_in(ssh)) != 0)
				return r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * blowfish, etc, so enforce a 1GB limit for small blocksizes.
	 */
	if (enc->block_size >= 16)
		*max_blocks = (u_int64_t)1 << (enc->block_size*2);
	else
		*max_blocks = ((u_int64_t)1 << 30) / enc->block_size;
	if (state->rekey_limit)
		*max_blocks = MIN(*max_blocks,
		    state->rekey_limit / enc->block_size);
	return 0;
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
static int
ssh_packet_enable_delayed_compress(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	Comp *comp = NULL;
	int r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	for (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		if (state->newkeys[mode] == NULL)
			continue;
		comp = &state->newkeys[mode]->comp;
		if (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			if ((r = ssh_packet_init_compression(ssh)) != 0)
				return r;
			if (mode == MODE_OUT) {
				if ((r = start_compression_out(ssh, 6)) != 0)
					return r;
			} else {
				if ((r = start_compression_in(ssh)) != 0)
					return r;
			}
			comp->enabled = 1;
		}
	}
	return 0;
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
int
ssh_packet_send2_wrapped(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_char type, *cp, macbuf[MAC_DIGEST_LEN_MAX];
	u_char padlen, pad;
	u_int packet_length = 0;
	u_int i, len;
	u_int32_t rnd = 0;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int r, block_size;

	if (state->newkeys[MODE_OUT] != NULL) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
	}
	block_size = enc ? enc->block_size : 8;

	cp = sshbuf_ptr(state->outgoing_packet);
	type = cp[5];

#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	if (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		if ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			goto out;
		sshbuf_reset(state->compression_buffer);
		if ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->outgoing_packet);
		if ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		DBG(debug("compression: raw %d compressed %zd", len,
		    sshbuf_len(state->outgoing_packet)));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = sshbuf_len(state->outgoing_packet);

	/*
	 * calc size of padding, alloc space, get random data,
	 * minimum padding is 4 bytes
	 */
	padlen = block_size - (len % block_size);
	if (padlen < 4)
		padlen += block_size;
	if (state->extra_pad) {
		/* will wrap if extra_pad+padlen > 255 */
		state->extra_pad =
		    roundup(state->extra_pad, block_size);
		pad = state->extra_pad -
		    ((len + padlen) % state->extra_pad);
		debug3("packet_send2: adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad);
		padlen += pad;
		state->extra_pad = 0;
	}
	if ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		goto out;
	if (enc && !state->send_context.plaintext) {
		/* random padding */
		for (i = 0; i < padlen; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[i] = rnd & 0xff;
			rnd >>= 8;
		}
	} else {
		/* clear padding */
		memset(cp, 0, padlen);
	}
	/* packet_length includes payload, padding and padding length field */
	packet_length = sshbuf_len(state->outgoing_packet) - 4;
	cp = sshbuf_ptr(state->outgoing_packet);
	POKE_U32(cp, packet_length);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d)", packet_length+4, padlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	if (mac && mac->enabled) {
		if ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet),
		    sshbuf_len(state->outgoing_packet),
		    macbuf, sizeof(macbuf))) != 0)
			goto out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	if ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet), &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(&state->send_context, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    sshbuf_len(state->outgoing_packet))) != 0)
		goto out;
	/* append unencrypted MAC */
	if (mac && mac->enabled)
		if ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			goto out;
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	if (++state->p_send.seqnr == 0)
		logit("outgoing seqnr wraps around");
	if (++state->p_send.packets == 0)
		if (!(ssh->compat & SSH_BUG_NOREKEY))
			return SSH_ERR_NEED_REKEY;
	state->p_send.blocks += (packet_length + 4) / block_size;
	state->p_send.bytes += packet_length + 4;
	sshbuf_reset(state->outgoing_packet);

	if (type == SSH2_MSG_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	else
		r = 0;
 out:
	return r;
}

int
ssh_packet_send2(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct packet *p;
	u_char type, *cp;
	int r;

	cp = sshbuf_ptr(state->outgoing_packet);
	type = cp[5];

	/* during rekeying we can only send key exchange messages */
	if (state->rekeying) {
		if ((type < SSH2_MSG_TRANSPORT_MIN) ||
		    (type > SSH2_MSG_TRANSPORT_MAX) ||
		    (type == SSH2_MSG_SERVICE_REQUEST) ||
		    (type == SSH2_MSG_SERVICE_ACCEPT)) {
			debug("enqueue packet: %u", type);
			p = calloc(1, sizeof(*p));
			if (p == NULL)
				return SSH_ERR_ALLOC_FAIL;
			p->type = type;
			p->payload = state->outgoing_packet;
			TAILQ_INSERT_TAIL(&state->outgoing, p, next);
			state->outgoing_packet = sshbuf_new();
			if (state->outgoing_packet == NULL)
				return SSH_ERR_ALLOC_FAIL;
			return 0;
		}
	}

	/* rekeying starts with sending KEXINIT */
	if (type == SSH2_MSG_KEXINIT)
		state->rekeying = 1;

	if ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		return r;

	/* after a NEWKEYS message we can send the complete queue */
	if (type == SSH2_MSG_NEWKEYS) {
		state->rekeying = 0;
		while ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			free(p);
			if ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				return r;
		}
	}
	return 0;
}

void
ssh_packet_send(struct ssh *ssh)
{
	int r;

	if ((r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	DBG(debug("packet_send done"));
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

int
ssh_packet_read_seqnr(struct ssh *ssh, u_char *typep, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	int len, r, ms_remain, cont;
	fd_set *setp;
	char buf[8192];
	struct timeval timeout, start, *timeoutp = NULL;

	DBG(debug("packet_read()"));

	setp = (fd_set *)calloc(howmany(state->connection_in + 1,
	    NFDBITS), sizeof(fd_mask));
	if (setp == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* Since we are blocking, ensure that all written packets have been sent. */
	ssh_packet_write_wait(ssh);

	/* Stay in the loop until we have received a complete packet. */
	for (;;) {
		/* Try to read a packet from the buffer. */
		r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p);
		if (r != 0) {
			free(setp);
			return r;
		}
		if (!compat20 && (
		    *typep == SSH_SMSG_SUCCESS
		    || *typep == SSH_SMSG_FAILURE
		    || *typep == SSH_CMSG_EOF
		    || *typep == SSH_CMSG_EXIT_CONFIRMATION))
			ssh_packet_check_eom(ssh);
		/* If we got a packet, return it. */
		if (*typep != SSH_MSG_NONE) {
			free(setp);
			return 0;
		}
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		memset(setp, 0, howmany(state->connection_in + 1,
		    NFDBITS) * sizeof(fd_mask));
		FD_SET(state->connection_in, setp);

		if (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timeoutp = &timeout;
		}
		/* Wait for some data to arrive. */
		for (;;) {
			if (state->packet_timeout_ms != -1) {
				ms_to_timeval(&timeout, ms_remain);
				gettimeofday(&start, NULL);
			}
			if ((r = select(state->connection_in + 1, setp,
			    NULL, NULL, timeoutp)) >= 0)
				break;
			if (errno != EAGAIN && errno != EINTR)
				break;
			if (state->packet_timeout_ms == -1)
				continue;
			ms_subtract_diff(&start, &ms_remain);
			if (ms_remain <= 0) {
				r = 0;
				break;
			}
		}
		if (r == 0) {
			logit("Connection to %.200s timed out while "
			    "waiting to read", ssh_remote_ipaddr(ssh));
			cleanup_exit(255);
		}
		/* Read data from the socket. */
		do {
			cont = 0;
			len = roaming_read(state->connection_in, buf,
			    sizeof(buf), &cont);
		} while (len == 0 && cont);
		if (len == 0) {
			logit("Connection closed by %.200s",
			    ssh_remote_ipaddr(ssh));
			cleanup_exit(255);
		}
		if (len < 0)
			fatal("Read from socket failed: %.100s", strerror(errno));
		/* Append it to the buffer. */
		ssh_packet_process_incoming(ssh, buf, len);
	}
	/* NOTREACHED */
}

int
ssh_packet_read(struct ssh *ssh)
{
	u_char type;
	int r;

	if ((r = ssh_packet_read_seqnr(ssh, &type, NULL)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return type;
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
ssh_packet_read_expect(struct ssh *ssh, int expected_type)
{
	int type;

	type = ssh_packet_read(ssh);
	if (type != expected_type)
		ssh_packet_disconnect(ssh,
		    "Protocol error: expected packet type %d, got %d",
		    expected_type, type);
}

/* Checks if a full packet is available in the data received so far via
 * packet_process_incoming.  If so, reads the packet; otherwise returns
 * SSH_MSG_NONE.  This does not wait for data from the connection.
 *
 * SSH_MSG_DISCONNECT is handled specially here.  Also,
 * SSH_MSG_IGNORE messages are skipped by this function and are never returned
 * to higher levels.
 */

int
ssh_packet_read_poll1(struct ssh *ssh, u_char *typep)
{
	struct session_state *state = ssh->state;
	u_int len, padded_len;
	u_char *cp;
	u_int checksum, stored_checksum;
	int r;

	*typep = SSH_MSG_NONE;

	/* Check if input size is less than minimum packet size. */
	if (sshbuf_len(state->input) < 4 + 8)
		return 0;
	/* Get length of incoming packet. */
	cp = sshbuf_ptr(state->input);
	len = PEEK_U32(cp);
	if (len < 1 + 2 + 2 || len > 256 * 1024)
		ssh_packet_disconnect(ssh, "Bad packet length %u.",
		    len);
	padded_len = (len + 8) & ~7;

	/* Check if the packet has been entirely received. */
	if (sshbuf_len(state->input) < 4 + padded_len)
		return 0;

	/* The entire packet is in buffer. */

	/* Consume packet length. */
	if ((r = sshbuf_consume(state->input, 4)) != 0)
		goto out;

	/*
	 * Cryptographic attack detector for ssh
	 * (C)1998 CORE-SDI, Buenos Aires Argentina
	 * Ariel Futoransky(futo@core-sdi.com)
	 */
	if (!state->receive_context.plaintext) {
		switch (detect_attack(&state->deattack,
		    sshbuf_ptr(state->input), padded_len)) {
		case DEATTACK_OK:
			break;
		case DEATTACK_DETECTED:
			ssh_packet_disconnect(ssh,
			    "crc32 compensation attack: network attack detected"
			);
		case DEATTACK_DOS_DETECTED:
			ssh_packet_disconnect(ssh,
			    "deattack denial of service detected");
		default:
			ssh_packet_disconnect(ssh, "deattack error");
		}
	}

	/* Decrypt data to incoming_packet. */
	sshbuf_reset(state->incoming_packet);
	if ((r = sshbuf_reserve(state->incoming_packet, padded_len, &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(&state->receive_context, cp,
	    sshbuf_ptr(state->input), padded_len)) != 0)
		goto out;

	if ((r = sshbuf_consume(state->input, padded_len)) != 0)
		goto out;

#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll plain: ");
	sshbuf_dump(state->incoming_packet, stderr);
#endif

	/* Compute packet checksum. */
	checksum = ssh_crc32(sshbuf_ptr(state->incoming_packet),
	    sshbuf_len(state->incoming_packet) - 4);

	/* Skip padding. */
	if ((r = sshbuf_consume(state->incoming_packet, 8 - len % 8)) != 0)
		goto out;

	/* Test check bytes. */
	if (len != sshbuf_len(state->incoming_packet))
		ssh_packet_disconnect(ssh,
		    "packet_read_poll1: len %d != sshbuf_len %zd.",
		    len, sshbuf_len(state->incoming_packet));

	cp = (u_char *)sshbuf_ptr(state->incoming_packet) + len - 4;
	stored_checksum = PEEK_U32(cp);
	if (checksum != stored_checksum)
		ssh_packet_disconnect(ssh,
		    "Corrupted check bytes on input.");
	if ((r = sshbuf_consume_end(state->incoming_packet, 4)) < 0)
		goto out;

	if (state->packet_compression) {
		sshbuf_reset(state->compression_buffer);
		if ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->incoming_packet);
		if ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
	}
	state->p_read.packets++;
	state->p_read.bytes += padded_len + 4;
	if ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		goto out;
	if (*typep < SSH_MSG_MIN || *typep > SSH_MSG_MAX)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh1 packet type: %d", *typep);
	r = 0;
 out:
	return r;
}

int
ssh_packet_read_poll2(struct ssh *ssh, u_char *typep, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int padlen, need;
	u_char macbuf[MAC_DIGEST_LEN_MAX], *cp;
	u_int maclen, block_size;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int r;

	*typep = SSH_MSG_NONE;

	if (state->packet_discard)
		return 0;

	if (state->newkeys[MODE_IN] != NULL) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;

	if (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		if (sshbuf_len(state->input) < block_size)
			return 0;
		sshbuf_reset(state->incoming_packet);
		if ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			goto out;
		if ((r = cipher_crypt(&state->receive_context, cp,
		    sshbuf_ptr(state->input), block_size)) != 0)
			goto out;
		cp = sshbuf_ptr(state->incoming_packet);
		state->packlen = PEEK_U32(cp);
		if (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->input, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			return ssh_packet_start_discard(ssh, enc, mac,
			    state->packlen, PACKET_MAX_SIZE);
		}
		DBG(debug("input: packet len %u", state->packlen+4));
		if ((r = sshbuf_consume(state->input, block_size)) != 0)
			goto out;
	}
	/* we have a partial packet of block_size bytes */
	need = 4 + state->packlen - block_size;
	DBG(debug("partial packet %d, need %d, maclen %d", block_size,
	    need, maclen));
	if (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		return ssh_packet_start_discard(ssh, enc, mac,
		    state->packlen, PACKET_MAX_SIZE - block_size);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet
	 */
	if (sshbuf_len(state->input) < need + maclen)
		return 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->input, stderr);
#endif
	if ((r = sshbuf_reserve(state->incoming_packet, need, &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(&state->receive_context, cp,
	    sshbuf_ptr(state->input), need)) != 0)
		goto out;
	if ((r = sshbuf_consume(state->input, need)) != 0)
		goto out;
	/*
	 * compute MAC over seqnr and packet,
	 * increment sequence number for incoming packet
	 */
	if (mac && mac->enabled) {
		if ((r = mac_compute(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    macbuf, sizeof(macbuf))) != 0)
			goto out;
		if (timingsafe_bcmp(macbuf, sshbuf_ptr(state->input),
		    mac->mac_len) != 0) {
			logit("Corrupted MAC on input.");
			if (need > PACKET_MAX_SIZE)
				return SSH_ERR_INTERNAL_ERROR;
			return ssh_packet_start_discard(ssh, enc, mac,
			    state->packlen, PACKET_MAX_SIZE - need);
		}
				
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		if ((r = sshbuf_consume(state->input, mac->mac_len)) != 0)
			goto out;
	}
	/* XXX now it's safe to use fatal/packet_disconnect */
	if (seqnr_p != NULL)
		*seqnr_p = state->p_read.seqnr;
	if (++state->p_read.seqnr == 0)
		logit("incoming seqnr wraps around");
	if (++state->p_read.packets == 0)
		if (!(ssh->compat & SSH_BUG_NOREKEY))
			return SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	cp = sshbuf_ptr(state->incoming_packet);
	padlen = cp[4];
	DBG(debug("input: padlen %d", padlen));
	if (padlen < 4)
		ssh_packet_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen);

	/* skip packet size + padlen, discard padding */
	if ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		goto out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	if (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		if ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->incoming_packet);
		if ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	if ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		goto out;
	if (*typep < SSH2_MSG_MIN || *typep >= SSH2_MSG_LOCAL_MIN)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep);
	if (*typep == SSH2_MSG_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_IN);
	else if (*typep == SSH2_MSG_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	else
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
 out:
	return r;
}

int
ssh_packet_read_poll_seqnr(struct ssh *ssh, u_char *typep, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int reason, seqnr;
	int r;
	u_char *msg;

	for (;;) {
		msg = NULL;
		if (compat20) {
			r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
			if (r != 0)
				return r;
			if (*typep) {
				state->keep_alive_timeouts = 0;
				DBG(debug("received packet type %d", *typep));
			}
			switch (*typep) {
			case SSH2_MSG_IGNORE:
				debug3("Received SSH2_MSG_IGNORE");
				break;
			case SSH2_MSG_DEBUG:
				if ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||
				    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0 ||
				    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
					if (msg)
						free(msg);
					return r;
				}
				debug("Remote: %.900s", msg);
				free(msg);
				break;
			case SSH2_MSG_DISCONNECT:
				if ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
				    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0)
					return r;
				logit("Received disconnect from %s: %u: %.400s",
				    ssh_remote_ipaddr(ssh), reason, msg);
				free(msg);
				return SSH_ERR_DISCONNECTED;
			case SSH2_MSG_UNIMPLEMENTED:
				if ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
					return r;
				debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
				    seqnr);
				break;
			default:
				return 0;
			}
		} else {
			r = ssh_packet_read_poll1(ssh, typep);
			switch (*typep) {
			case SSH_MSG_IGNORE:
				break;
			case SSH_MSG_DEBUG:
				if ((r = sshpkt_get_string(ssh, &msg, NULL)) != 0)
					return r;
				debug("Remote: %.900s", msg);
				free(msg);
				break;
			case SSH_MSG_DISCONNECT:
				if ((r = sshpkt_get_string(ssh, &msg, NULL)) != 0)
					return r;
				logit("Received disconnect from %s: %.400s",
				    ssh_remote_ipaddr(ssh), msg);
				free(msg);
				return SSH_ERR_DISCONNECTED;
				break;
			default:
				if (*typep)
					DBG(debug("received packet type %d", *typep));
				return 0;
			}
		}
	}
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
ssh_packet_process_incoming(struct ssh *ssh, const char *buf, u_int len)
{
	struct session_state *state = ssh->state;
	int r;

	if (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		if (len >= state->packet_discard) {
			if ((r = ssh_packet_stop_discard(ssh)) != 0)
				fatal("%s: %s", __func__, ssh_err(r));
			cleanup_exit(255);
		}
		state->packet_discard -= len;
		return;
	}
	if ((r = sshbuf_put(ssh->state->input, buf, len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

/* Returns a character from the packet. */

u_int
ssh_packet_get_char(struct ssh *ssh)
{
	u_char ch;
	int r;

	if ((r = sshpkt_get_u8(ssh, &ch)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return ch;
}

/* Returns an integer from the packet data. */

u_int
ssh_packet_get_int(struct ssh *ssh)
{
	u_int val;
	int r;

	if ((r = sshpkt_get_u32(ssh, &val)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return val;
}

/* Returns an 64 bit integer from the packet data. */

u_int64_t
ssh_packet_get_int64(struct ssh *ssh)
{
	u_int64_t val;
	int r;

	if ((r = sshpkt_get_u64(ssh, &val)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return val;
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
ssh_packet_get_bignum(struct ssh *ssh, BIGNUM * value)
{
	int r;

	if ((r = sshpkt_get_bignum1(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_get_bignum2(struct ssh *ssh, BIGNUM * value)
{
	int r;

	if ((r = sshpkt_get_bignum2(ssh, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

void
ssh_packet_get_ecpoint(struct ssh *ssh, const EC_GROUP *curve, EC_POINT *point)
{
	int r;

	if ((r = sshpkt_get_ec(ssh, point, curve)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
}

int
ssh_packet_remaining(struct ssh *ssh)
{
	return sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * malloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
ssh_packet_get_string(struct ssh *ssh, u_int *length_ptr)
{
	int r;
	size_t len;
	u_char *val;

	if ((r = sshpkt_get_string(ssh, &val, &len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	if (length_ptr != NULL)
		*length_ptr = (u_int)len;
	return val;
}

const void *
ssh_packet_get_string_ptr(struct ssh *ssh, u_int *length_ptr)
{
	int r;
	size_t len;
	const u_char *val;

	if ((r = sshpkt_get_string_direct(ssh, &val, &len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	if (length_ptr != NULL)
		*length_ptr = (u_int)len;
	return val;
}

/* Ensures the returned string has no embedded \0 characters in it. */
char *
ssh_packet_get_cstring(struct ssh *ssh, u_int *length_ptr)
{
	int r;
	size_t len;
	char *val;

	if ((r = sshpkt_get_cstring(ssh, &val, &len)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	if (length_ptr != NULL)
		*length_ptr = (u_int)len;
	return val;
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call packet_write_wait.
 */

void
ssh_packet_send_debug(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024];
	va_list args;

	if (compat20 && (ssh->compat & SSH_BUG_DEBUG))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (compat20) {
		ssh_packet_start(ssh, SSH2_MSG_DEBUG);
		ssh_packet_put_char(ssh, 0); /* bool: always display */
		ssh_packet_put_cstring(ssh, buf);
		ssh_packet_put_cstring(ssh, "");
	} else {
		ssh_packet_start(ssh, SSH_MSG_DEBUG);
		ssh_packet_put_cstring(ssh, buf);
	}
	ssh_packet_send(ssh);
	ssh_packet_write_wait(ssh);
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */

void
ssh_packet_disconnect(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024];
	va_list args;
	static int disconnecting = 0;

	if (disconnecting)	/* Guard against recursive invocations. */
		fatal("packet_disconnect called recursively.");
	disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting: %.100s", buf);

	/* Send the disconnect message to the other side, and wait for it to get sent. */
	if (compat20) {
		ssh_packet_start(ssh, SSH2_MSG_DISCONNECT);
		ssh_packet_put_int(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR);
		ssh_packet_put_cstring(ssh, buf);
		ssh_packet_put_cstring(ssh, "");
	} else {
		ssh_packet_start(ssh, SSH_MSG_DISCONNECT);
		ssh_packet_put_cstring(ssh, buf);
	}
	ssh_packet_send(ssh);
	ssh_packet_write_wait(ssh);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void
ssh_packet_write_poll(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	int len = sshbuf_len(state->output);
	int cont, r;

	if (len > 0) {
		cont = 0;
		len = roaming_write(state->connection_out,
		    sshbuf_ptr(state->output), len, &cont);
		if (len == -1) {
			if (errno == EINTR || errno == EAGAIN)
				return;
			fatal("Write failed: %.100s", strerror(errno));
		}
		if (len == 0 && !cont)
			fatal("Write connection closed");
		if ((r = sshbuf_consume(state->output, len)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
	}
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */

void
ssh_packet_write_wait(struct ssh *ssh)
{
	fd_set *setp;
	int ret, ms_remain;
	struct timeval start, timeout, *timeoutp = NULL;
	struct session_state *state = ssh->state;

	setp = (fd_set *)calloc(howmany(state->connection_out + 1,
	    NFDBITS), sizeof(fd_mask));
	if (setp == NULL)
		fatal("%s: calloc failed", __func__);
	ssh_packet_write_poll(ssh);
	while (ssh_packet_have_data_to_write(ssh)) {
		memset(setp, 0, howmany(state->connection_out + 1,
		    NFDBITS) * sizeof(fd_mask));
		FD_SET(state->connection_out, setp);

		if (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timeoutp = &timeout;
		}
		for (;;) {
			if (state->packet_timeout_ms != -1) {
				ms_to_timeval(&timeout, ms_remain);
				gettimeofday(&start, NULL);
			}
			if ((ret = select(state->connection_out + 1,
			    NULL, setp, NULL, timeoutp)) >= 0)
				break;
			if (errno != EAGAIN && errno != EINTR)
				break;
			if (state->packet_timeout_ms == -1)
				continue;
			ms_subtract_diff(&start, &ms_remain);
			if (ms_remain <= 0) {
				ret = 0;
				break;
			}
		}
		if (ret == 0) {
			logit("Connection to %.200s timed out while "
			    "waiting to write", ssh_remote_ipaddr(ssh));
			cleanup_exit(255);
		}
		ssh_packet_write_poll(ssh);
	}
	free(setp);
}

/* Returns true if there is buffered data to write to the connection. */

int
ssh_packet_have_data_to_write(struct ssh *ssh)
{
	return sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

int
ssh_packet_not_very_much_data_to_write(struct ssh *ssh)
{
	if (ssh->state->interactive_mode)
		return sshbuf_len(ssh->state->output) < 16384;
	else
		return sshbuf_len(ssh->state->output) < 128 * 1024;
}

void
ssh_packet_set_tos(struct ssh *ssh, int tos)
{
	if (!ssh_packet_connection_is_on_socket(ssh))
		return;
	switch (ssh_packet_connection_af(ssh)) {
	case AF_INET:
		debug3("%s: set IP_TOS 0x%02x", __func__, tos);
		if (setsockopt(ssh->state->connection_in,
		    IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0)
			error("setsockopt IP_TOS %d: %.100s:",
			    tos, strerror(errno));
		break;
	case AF_INET6:
		debug3("%s: set IPV6_TCLASS 0x%02x", __func__, tos);
		if (setsockopt(ssh->state->connection_in,
		    IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0)
			error("setsockopt IPV6_TCLASS %d: %.100s:",
			    tos, strerror(errno));
		break;
	}
}

/* Informs that the current session is interactive.  Sets IP flags for that. */

void
ssh_packet_set_interactive(struct ssh *ssh, int interactive, int qos_interactive, int qos_bulk)
{
	struct session_state *state = ssh->state;

	if (state->set_interactive_called)
		return;
	state->set_interactive_called = 1;

	/* Record that we are in interactive mode. */
	state->interactive_mode = interactive;

	/* Only set socket options if using a socket.  */
	if (!ssh_packet_connection_is_on_socket(ssh))
		return;
	set_nodelay(state->connection_in);
	ssh_packet_set_tos(ssh, interactive ? qos_interactive :
	    qos_bulk);
}

/* Returns true if the current connection is interactive. */

int
ssh_packet_is_interactive(struct ssh *ssh)
{
	return ssh->state->interactive_mode;
}

int
ssh_packet_set_maxsize(struct ssh *ssh, u_int s)
{
	struct session_state *state = ssh->state;

	if (state->set_maxsize_called) {
		logit("packet_set_maxsize: called twice: old %d new %d",
		    state->max_packet_size, s);
		return -1;
	}
	if (s < 4 * 1024 || s > 1024 * 1024) {
		logit("packet_set_maxsize: bad size %d", s);
		return -1;
	}
	state->set_maxsize_called = 1;
	debug("packet_set_maxsize: setting to %d", s);
	state->max_packet_size = s;
	return s;
}

int
ssh_packet_inc_alive_timeouts(struct ssh *ssh)
{
	return ++ssh->state->keep_alive_timeouts;
}

void
ssh_packet_set_alive_timeouts(struct ssh *ssh, int ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(struct ssh *ssh)
{
	return ssh->state->max_packet_size;
}

/* roundup current message to pad bytes */
void
ssh_packet_add_padding(struct ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
}

/*
 * 9.2.  Ignored Data Message
 *
 *   byte      SSH_MSG_IGNORE
 *   string    data
 *
 * All implementations MUST understand (and ignore) this message at any
 * time (after receiving the protocol version). No implementation is
 * required to send them. This message can be used as an additional
 * protection measure against advanced traffic analysis techniques.
 */
void
ssh_packet_send_ignore(struct ssh *ssh, int nbytes)
{
	u_int32_t rnd = 0;
	int i;

	ssh_packet_start(ssh, compat20 ? SSH2_MSG_IGNORE :
	    SSH_MSG_IGNORE);
	ssh_packet_put_int(ssh, nbytes);
	for (i = 0; i < nbytes; i++) {
		if (i % 4 == 0)
			rnd = arc4random();
		ssh_packet_put_char(ssh, (u_char)rnd & 0xff);
		rnd >>= 8;
	}
}

#define MAX_PACKETS	(1U<<31)
int
ssh_packet_need_rekeying(struct ssh *ssh)
{
	struct session_state *state = ssh->state;

	if (ssh->compat & SSH_BUG_NOREKEY)
		return 0;
	return
	    (state->p_send.packets > MAX_PACKETS) ||
	    (state->p_read.packets > MAX_PACKETS) ||
	    (state->max_blocks_out &&
	        (state->p_send.blocks > state->max_blocks_out)) ||
	    (state->max_blocks_in &&
	        (state->p_read.blocks > state->max_blocks_in));
}

void
ssh_packet_set_rekey_limit(struct ssh *ssh, u_int32_t bytes)
{
	ssh->state->rekey_limit = bytes;
}

void
ssh_packet_set_server(struct ssh *ssh)
{
	ssh->state->server_side = 1;
}

void
ssh_packet_set_authenticated(struct ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

void *
ssh_packet_get_input(struct ssh *ssh)
{
	return (void *)ssh->state->input;
}

void *
ssh_packet_get_output(struct ssh *ssh)
{
	return (void *)ssh->state->output;
}

/* XXX FIXME FIXME FIXME */
/*
 * Save the state for the real connection, and use a separate state when
 * resuming a suspended connection.
 */
void
ssh_packet_backup_state(struct ssh *ssh,
    struct ssh *backup_state)
{
	struct ssh *tmp;

	close(ssh->state->connection_in);
	ssh->state->connection_in = -1;
	close(ssh->state->connection_out);
	ssh->state->connection_out = -1;
	if (backup_state)
		tmp = backup_state;
	else
		tmp = ssh_alloc_session_state();
	backup_state = ssh;
	ssh = tmp;
}

/* XXX FIXME FIXME FIXME */
/*
 * Swap in the old state when resuming a connecion.
 */
void
ssh_packet_restore_state(struct ssh *ssh,
    struct ssh *backup_state)
{
	struct ssh *tmp;
	void *buf;
	u_int len;
	int r;

	tmp = backup_state;
	backup_state = ssh;
	ssh = tmp;
	ssh->state->connection_in = backup_state->state->connection_in;
	backup_state->state->connection_in = -1;
	ssh->state->connection_out = backup_state->state->connection_out;
	backup_state->state->connection_out = -1;
	len = sshbuf_len(backup_state->state->input);
	if (len > 0) {
		buf = sshbuf_ptr(backup_state->state->input);
		if ((r = sshbuf_put(ssh->state->input, buf, len)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		sshbuf_reset(backup_state->state->input);
		add_recv_bytes(len);
	}
}

/* Reset after_authentication and reset compression in post-auth privsep */
static int
ssh_packet_set_postauth(struct ssh *ssh)
{
	Comp *comp;
	int r, mode;

	debug("%s: called", __func__);
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	for (mode = 0; mode < MODE_MAX; mode++) {
		if (ssh->state->newkeys[mode] == NULL)
			continue;
		comp = &ssh->state->newkeys[mode]->comp;
		if (comp && comp->enabled &&
		    (r = ssh_packet_init_compression(ssh)) != 0)
			return r;
	}
	return 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
static int
kex_to_blob(Buffer *m, Kex *kex)
{
	int r;

	if ((r = sshbuf_put_string(m, kex->session_id,
	    kex->session_id_len)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->client_version_string)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->server_version_string)) != 0)
		return r;
	return 0;
}

/* turn key exchange results into a blob for packet state serialization */
static int
newkeys_to_blob(struct sshbuf *m, struct ssh *ssh, int mode)
{
	struct sshbuf *b;
	CipherContext *cc;
	Comp *comp;
	Enc *enc;
	Mac *mac;
	Newkeys *newkey;
	int r;

	if ((newkey = ssh->state->newkeys[mode]) == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? &ssh->state->send_context :
	    &ssh->state->receive_context;
	if ((r = cipher_get_keyiv(cc, enc->iv, enc->block_size)) != 0)
		return r;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	/* The cipher struct is constant and shared, you export pointer */
	if ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put(b, &enc->cipher, sizeof(enc->cipher))) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->key, enc->key_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->block_size)) != 0 ||
	    (r = sshbuf_put_cstring(b, mac->name)) != 0 ||
	    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
	    (r = sshbuf_put_string(b, mac->key, mac->key_len)) != 0 ||
	    (r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_u32(b, comp->enabled)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		goto out;
	r = sshbuf_put_stringb(m, b);
 out:
	if (b != NULL)
		sshbuf_free(b);
	return r;
}

/* serialize packet state into a blob */
int
ssh_packet_get_state(struct ssh *ssh, struct sshbuf *m)
{
	struct session_state *state = ssh->state;
	u_char *p;
	size_t slen, rlen;
	int r, ssh1cipher;

	if (!compat20) {
		ssh1cipher = cipher_get_number(state->receive_context.cipher);
		slen = cipher_get_keyiv_len(&state->send_context);
		rlen = cipher_get_keyiv_len(&state->receive_context);
		if ((r = sshbuf_put_u32(m, state->remote_protocol_flags)) != 0 ||
		    (r = sshbuf_put_u32(m, ssh1cipher)) != 0 ||
		    (r = sshbuf_put_string(m, state->ssh1_key, state->ssh1_keylen)) != 0 ||
		    (r = sshbuf_put_u32(m, slen)) != 0 ||
		    (r = sshbuf_reserve(m, slen, &p)) != 0 ||
		    (r = cipher_get_keyiv(&state->send_context, p, slen)) != 0 ||
		    (r = sshbuf_put_u32(m, rlen)) != 0 ||
		    (r = sshbuf_reserve(m, rlen, &p)) != 0 ||
		    (r = cipher_get_keyiv(&state->receive_context, p, rlen)) != 0)
			return r;
	} else {
		if ((r = kex_to_blob(m, ssh->kex)) != 0 ||
		    (r = newkeys_to_blob(m, ssh, MODE_OUT)) != 0 ||
		    (r = newkeys_to_blob(m, ssh, MODE_IN)) != 0 ||
		    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
		    (r = sshbuf_put_u64(m, state->p_send.blocks)) != 0 ||
		    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
		    (r = sshbuf_put_u64(m, state->p_send.bytes)) != 0 ||
		    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
		    (r = sshbuf_put_u64(m, state->p_read.blocks)) != 0 ||
		    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
		    (r = sshbuf_put_u64(m, state->p_read.bytes)) != 0)
			return r;
	}

	slen = cipher_get_keycontext(&state->send_context, NULL);
	rlen = cipher_get_keycontext(&state->receive_context, NULL);
	if ((r = sshbuf_put_u32(m, slen)) != 0 ||
	    (r = sshbuf_reserve(m, slen, &p)) != 0)
		return r;
	if (cipher_get_keycontext(&state->send_context, p) != (int)slen)
		return SSH_ERR_INTERNAL_ERROR;
	if ((r = sshbuf_put_u32(m, rlen)) != 0 ||
	    (r = sshbuf_reserve(m, rlen, &p)) != 0)
		return r;
	if (cipher_get_keycontext(&state->receive_context, p) != (int)rlen)
		return SSH_ERR_INTERNAL_ERROR;

	if ((r = ssh_packet_get_compress_state(m, ssh)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->input)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0)
		return r;

	if (compat20) {
		if ((r = sshbuf_put_u64(m, get_sent_bytes())) != 0 ||
		    (r = sshbuf_put_u64(m, get_recv_bytes())) != 0)
			return r;
	}
	return 0;
}

/* restore key exchange results from blob for packet state de-serialization */
static int
newkeys_from_blob(struct sshbuf *m, struct ssh *ssh, int mode)
{
	struct sshbuf *b = NULL;
	Comp *comp;
	Enc *enc;
	Mac *mac;
	Newkeys *newkey = NULL;
	size_t keylen, ivlen, maclen;
	int r;

	if ((b = sshbuf_new()) == NULL ||
	    (newkey = calloc(1, sizeof(*newkey))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_stringb(m, b)) != 0)
		goto out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	if ((r = sshbuf_get_cstring(b, &enc->name, NULL)) != 0 ||
	    (r = sshbuf_get(b, &enc->cipher, sizeof(enc->cipher))) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->key, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &mac->name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(b, &mac->enabled)) != 0 ||
	    (r = sshbuf_get_string(b, &mac->key, &maclen)) != 0 ||
	    (r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_u32(b, &comp->enabled)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, NULL)) != 0)
		goto out;
	if (enc->name == NULL || mac->name == NULL ||
	    ivlen != enc->block_size ||
	    cipher_by_name(enc->name) != enc->cipher) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = mac_setup(mac, mac->name)) != 0)
		goto out;
	if (maclen > mac->key_len || sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	enc->key_len = keylen;
	ssh->current_keys[mode] = newkey;
	newkey = NULL;
	r = 0;
 out:
	if (newkey != NULL)
		free(newkey);
	if (b != NULL)
		sshbuf_free(b);
	return r;
}

/* restore kex from blob for packet state de-serialization */
static int
kex_from_blob(Buffer *m, Kex **kexp)
{
	Kex *kex;
	int r;

	if ((kex = calloc(1, sizeof(Kex))) == NULL ||
	    (kex->my = sshbuf_new()) == NULL ||
	    (kex->peer = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_string(m, &kex->session_id, &kex->session_id_len)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->client_version_string, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->server_version_string, NULL)) != 0)
		goto out;
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	if (r != 0 || kexp == NULL) {
		if (kex != NULL) {
			if (kex->my != NULL)
				sshbuf_free(kex->my);
			if (kex->peer != NULL)
				sshbuf_free(kex->peer);
			free(kex);
		}
		if (kexp != NULL)
			*kexp = NULL;
	} else {
		*kexp = kex;
	}
	return r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
int
ssh_packet_set_state(struct ssh *ssh, struct sshbuf *m)
{
	struct session_state *state = ssh->state;
	const u_char *ssh1key, *ivin, *ivout, *keyin, *keyout, *input, *output;
	size_t ssh1keylen, rlen, slen, ilen, olen;
	int r, ssh1cipher = 0;
	u_int64_t sent_bytes = 0, recv_bytes = 0;

	if (!compat20) {
		if ((r = sshbuf_get_u32(m, &state->remote_protocol_flags)) != 0 ||
		    (r = sshbuf_get_u32(m, &ssh1cipher)) != 0 ||
		    (r = sshbuf_get_string_direct(m, &ssh1key, &ssh1keylen)) != 0 ||
		    (r = sshbuf_get_string_direct(m, &ivout, &slen)) != 0 ||
		    (r = sshbuf_get_string_direct(m, &ivin, &rlen)) != 0)
			return r;
		ssh_packet_set_encryption_key(ssh, ssh1key, ssh1keylen,
		    ssh1cipher);
		if (cipher_get_keyiv_len(&state->send_context) != (int)slen ||
		    cipher_get_keyiv_len(&state->receive_context) != (int)rlen)
			return SSH_ERR_INVALID_FORMAT;
		if ((r = cipher_set_keyiv(&state->send_context, ivout)) != 0 ||
		    (r = cipher_set_keyiv(&state->receive_context, ivin)) != 0)
			return r;
	} else {
		if ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
		    (r = newkeys_from_blob(m, ssh, MODE_OUT)) != 0 ||
		    (r = newkeys_from_blob(m, ssh, MODE_IN)) != 0 ||
		    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
		    (r = sshbuf_get_u64(m, &state->p_send.blocks)) != 0 ||
		    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
		    (r = sshbuf_get_u64(m, &state->p_send.bytes)) != 0 ||
		    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
		    (r = sshbuf_get_u64(m, &state->p_read.blocks)) != 0 ||
		    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
		    (r = sshbuf_get_u64(m, &state->p_read.bytes)) != 0)
			return r;
		if ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
		    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
			return r;
	}
	if ((r = sshbuf_get_string_direct(m, &keyout, &slen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &keyin, &rlen)) != 0)
		return r;
	if (cipher_get_keycontext(&state->send_context, NULL) != (int)slen ||
	    cipher_get_keycontext(&state->receive_context, NULL) != (int)rlen)
		return SSH_ERR_INVALID_FORMAT;
	cipher_set_keycontext(&state->send_context, keyout);
	cipher_set_keycontext(&state->receive_context, keyin);

	if ((r = ssh_packet_set_compress_state(ssh, m)) != 0 ||
	    (r = ssh_packet_set_postauth(ssh)) != 0)
		return r;

	sshbuf_reset(state->input);
	sshbuf_reset(state->output);
	if ((r = sshbuf_get_string_direct(m, &input, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->input, input, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		return r;

	if (compat20) {
		if ((r = sshbuf_get_u64(m, &sent_bytes)) != 0 ||
		    (r = sshbuf_get_u64(m, &recv_bytes)) != 0)
			return r;
		roam_set_bytes(sent_bytes, recv_bytes);
	}
	if (sshbuf_len(m))
		return SSH_ERR_INVALID_FORMAT;
	debug3("%s: done", __func__);
	return 0;
}

/* NEW API */

/* put data to the outgoing packet */

int
sshpkt_put(struct ssh *ssh, const void *v, size_t len)
{
	return sshbuf_put(ssh->state->outgoing_packet, v, len);
}

int
sshpkt_put_u8(struct ssh *ssh, u_char val)
{
	return sshbuf_put_u8(ssh->state->incoming_packet, val);
}

int
sshpkt_put_u32(struct ssh *ssh, u_int32_t val)
{
	return sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

int
sshpkt_put_u64(struct ssh *ssh, u_int64_t val)
{
	return sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

int
sshpkt_put_string(struct ssh *ssh, const void *v, size_t len)
{
	return sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

int
sshpkt_put_cstring(struct ssh *ssh, const void *v)
{
	return sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

int
sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g)
{
	return sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

int
sshpkt_put_bignum1(struct ssh *ssh, const BIGNUM *v)
{
	return sshbuf_put_bignum1(ssh->state->outgoing_packet, v);
}

int
sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v)
{
	return sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}

/* fetch data from the incoming packet */

int
sshpkt_get_u8(struct ssh *ssh, u_char *valp)
{
	return sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

int
sshpkt_get_u32(struct ssh *ssh, u_int32_t *valp)
{
	return sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

int
sshpkt_get_u64(struct ssh *ssh, u_int64_t *valp)
{
	return sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

int
sshpkt_get_string(struct ssh *ssh, u_char **valp, size_t *lenp)
{
	return sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

int
sshpkt_get_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp)
{
	return sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

int
sshpkt_get_cstring(struct ssh *ssh, char **valp, size_t *lenp)
{
	return sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

int
sshpkt_get_ec(struct ssh *ssh, EC_POINT *v, const EC_GROUP *g)
{
	return sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

int
sshpkt_get_bignum1(struct ssh *ssh, BIGNUM *v)
{
	return sshbuf_get_bignum1(ssh->state->incoming_packet, v);
}

int
sshpkt_get_bignum2(struct ssh *ssh, BIGNUM *v)
{
	return sshbuf_get_bignum2(ssh->state->incoming_packet, v);
}

int
sshpkt_get_end(struct ssh *ssh)
{
	if (sshbuf_len(ssh->state->incoming_packet) > 0)
		return SSH_ERR_UNEXPECTED_TRAILING_DATA;
	return 0;
}

u_char *
sshpkt_ptr(struct ssh *ssh, size_t *lenp)
{
        if (lenp != NULL)
                *lenp = sshbuf_len(ssh->state->incoming_packet);
        return sshbuf_ptr(ssh->state->incoming_packet);
}


/* start a new packet */

int
sshpkt_start(struct ssh *ssh, u_char type)
{
	u_char buf[9];
	int len;

	DBG(debug("packet_start[%d]", type));
	len = compat20 ? 6 : 9;
	memset(buf, 0, len - 1);
	buf[len - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	return sshbuf_put(ssh->state->outgoing_packet, buf, len);
}

/* send it */

int
sshpkt_send(struct ssh *ssh)
{
	if (compat20)
		return ssh_packet_send2(ssh);
	else
		return ssh_packet_send1(ssh);
}

int
sshpkt_disconnect(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024];
	va_list args;
	int r;

	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (compat20) {
		if ((r = sshpkt_start(ssh, SSH2_MSG_DISCONNECT)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			return r;
	} else {
		if ((r = sshpkt_start(ssh, SSH_MSG_DISCONNECT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			return r;
	}
	return 0;
}
