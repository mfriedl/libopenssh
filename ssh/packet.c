/* $OpenBSD: packet.c,v 1.174 2011/12/07 05:44:38 djm Exp $ */
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

#include "xmalloc.h"
#include "buffer.h"
#include "crc32.h"
#include "compress.h"
#include "deattack.h"
#include "channels.h"
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
	Buffer payload;
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
	Buffer input;

	/* Buffer for raw output data going to the socket. */
	Buffer output;

	/* Buffer for the partial outgoing packet being constructed. */
	Buffer outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	Buffer incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	Buffer compression_buffer;
	int compression_buffer_ready;

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

	TAILQ_HEAD(, packet) outgoing;
};

struct ssh *
ssh_alloc_session_state(void)
{
	struct ssh *ssh = xcalloc(1, sizeof(*ssh));
	struct session_state *state = xcalloc(1, sizeof(*state));

	state->connection_in = -1;
	state->connection_out = -1;
	state->max_packet_size = 32768;
	state->packet_timeout_ms = -1;
	ssh->state = state;
	return ssh;
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
	state = ssh->state;
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	if ((r = cipher_init(&state->send_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_DECRYPT)) != 0)
		fatal("%s: cipher_init failed: %s", __func__, ssh_err(r));
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = NULL;
	if (!state->initialized) {
		state->initialized = 1;
		buffer_init(&state->input);
		buffer_init(&state->output);
		buffer_init(&state->outgoing_packet);
		buffer_init(&state->incoming_packet);
		TAILQ_INIT(&state->outgoing);
		TAILQ_INIT(&ssh->private_keys);
		TAILQ_INIT(&ssh->public_keys);
		state->p_send.packets = state->p_read.packets = 0;
	}

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

void
ssh_packet_stop_discard(struct ssh *ssh)
{
	struct session_state *state = ssh->state;

	if (state->packet_discard_mac) {
		char buf[1024];
		
		memset(buf, 'a', sizeof(buf));
		while (buffer_len(&state->incoming_packet) <
		    PACKET_MAX_SIZE)
			buffer_append(&state->incoming_packet, buf,
			    sizeof(buf));
		(void) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    buffer_ptr(&state->incoming_packet),
		    PACKET_MAX_SIZE);
	}
	logit("Finished discarding for %.200s", get_remote_ipaddr());
	cleanup_exit(255);
}

void
ssh_packet_start_discard(struct ssh *ssh, Enc *enc, Mac *mac,
    u_int packet_length, u_int discard)
{
	struct session_state *state = ssh->state;

	if (enc == NULL || !cipher_is_cbc(enc->cipher))
		ssh_packet_disconnect(ssh, "Packet corrupt");
	if (packet_length != PACKET_MAX_SIZE && mac && mac->enabled)
		state->packet_discard_mac = mac;
	if (buffer_len(&state->input) >= discard)
		ssh_packet_stop_discard(ssh);
	state->packet_discard = discard -
	    buffer_len(&state->input);
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

/*
 * Exports an IV from the CipherContext required to export the key
 * state back from the unprivileged child to the privileged parent
 * process.
 */

void
ssh_packet_get_keyiv(struct ssh *ssh, int mode, u_char *iv,
    u_int len)
{
	CipherContext *cc;
	int r;

	if (mode == MODE_OUT)
		cc = &ssh->state->send_context;
	else
		cc = &ssh->state->receive_context;

	if ((r = cipher_get_keyiv(cc, iv, len)) != 0)
		fatal("%s: cipher_get_keyiv failed: %s", __func__, ssh_err(r));
}

int
ssh_packet_get_keycontext(struct ssh *ssh, int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->state->send_context;
	else
		cc = &ssh->state->receive_context;

	return (cipher_get_keycontext(cc, dat));
}

void
ssh_packet_set_keycontext(struct ssh *ssh, int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->state->send_context;
	else
		cc = &ssh->state->receive_context;

	cipher_set_keycontext(cc, dat);
}

int
ssh_packet_get_keyiv_len(struct ssh *ssh, int mode)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->state->send_context;
	else
		cc = &ssh->state->receive_context;

	return (cipher_get_keyiv_len(cc));
}

void
ssh_packet_set_iv(struct ssh *ssh, int mode, u_char *dat)
{
	CipherContext *cc;
	int r;

	if (mode == MODE_OUT)
		cc = &ssh->state->send_context;
	else
		cc = &ssh->state->receive_context;

	if ((r = cipher_set_keyiv(cc, dat)) != 0)
		fatal("%s: cipher_set_keyiv failed: %s", __func__, ssh_err(r));
}

int
ssh_packet_get_ssh1_cipher(struct ssh *ssh)
{
	return (cipher_get_number(ssh->state->receive_context.cipher));
}

void
ssh_packet_get_state(struct ssh *ssh, int mode, u_int32_t *seqnr, u_int64_t *blocks,
    u_int32_t *packets, u_int64_t *bytes)
{
	struct packet_state *pstate;

	pstate = (mode == MODE_IN) ?
	    &ssh->state->p_read : &ssh->state->p_send;
	if (seqnr)
		*seqnr = pstate->seqnr;
	if (blocks)
		*blocks = pstate->blocks;
	if (packets)
		*packets = pstate->packets;
	if (bytes)
		*bytes = pstate->bytes;
}

void
ssh_packet_set_state(struct ssh *ssh, int mode, u_int32_t seqnr, u_int64_t blocks, u_int32_t packets,
    u_int64_t bytes)
{
	struct packet_state *pstate;

	pstate = (mode == MODE_IN) ?
	    &ssh->state->p_read : &ssh->state->p_send;
	pstate->seqnr = seqnr;
	pstate->blocks = blocks;
	pstate->packets = packets;
	pstate->bytes = bytes;
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

/* Closes the connection and clears and frees internal data structures. */

void
ssh_packet_close(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	int r;

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
	buffer_free(&state->input);
	buffer_free(&state->output);
	buffer_free(&state->outgoing_packet);
	buffer_free(&state->incoming_packet);
	if (state->compression_buffer_ready) {
		buffer_free(&state->compression_buffer);
		buffer_compress_uninit();
	}
	if ((r = cipher_cleanup(&state->send_context)) != 0 ||
	    (r = cipher_cleanup(&state->receive_context)) != 0)
		fatal("%s: cipher_cleanup failed: %s", __func__, ssh_err(r));
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

void
ssh_packet_init_compression(struct ssh *ssh)
{
	if (ssh->state->compression_buffer_ready == 1)
		return;
	ssh->state->compression_buffer_ready = 1;
	buffer_init(&ssh->state->compression_buffer);
}

void
ssh_packet_start_compression(struct ssh *ssh, int level)
{
	if (ssh->state->packet_compression && !compat20)
		fatal("Compression already enabled.");
	ssh->state->packet_compression = 1;
	ssh_packet_init_compression(ssh);
	buffer_compress_init_send(level);
	buffer_compress_init_recv();
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
	if (!ssh->cipher_warning_done &&
	    ((wmsg = cipher_warning_message(&state->send_context)) != NULL ||
	    (wmsg = cipher_warning_message(&state->send_context)) != NULL)) {
		error("Warning: %s", wmsg);
		ssh->cipher_warning_done = 1;
	}
}

u_int
ssh_packet_get_encryption_key(struct ssh *ssh, u_char *key)
{
	if (key == NULL)
		return (ssh->state->ssh1_keylen);
	memcpy(key, ssh->state->ssh1_key, ssh->state->ssh1_keylen);
	return (ssh->state->ssh1_keylen);
}

/* Start constructing a packet to send. */
void
ssh_packet_start(struct ssh *ssh, u_char type)
{
	u_char buf[9];
	int len;

	DBG(debug("packet_start[%d]", type));
	len = compat20 ? 6 : 9;
	memset(buf, 0, len - 1);
	buf[len - 1] = type;
	buffer_clear(&ssh->state->outgoing_packet);
	buffer_append(&ssh->state->outgoing_packet, buf, len);
}

/* Append payload. */
void
ssh_packet_put_char(struct ssh *ssh, int value)
{
	char ch = value;

	buffer_append(&ssh->state->outgoing_packet, &ch, 1);
}

void
ssh_packet_put_int(struct ssh *ssh, u_int value)
{
	buffer_put_int(&ssh->state->outgoing_packet, value);
}

void
ssh_packet_put_int64(struct ssh *ssh, u_int64_t value)
{
	buffer_put_int64(&ssh->state->outgoing_packet, value);
}

void
ssh_packet_put_string(struct ssh *ssh, const void *buf, u_int len)
{
	buffer_put_string(&ssh->state->outgoing_packet, buf, len);
}

void
ssh_packet_put_cstring(struct ssh *ssh, const char *str)
{
	buffer_put_cstring(&ssh->state->outgoing_packet, str);
}

void
ssh_packet_put_raw(struct ssh *ssh, const void *buf, u_int len)
{
	buffer_append(&ssh->state->outgoing_packet, buf, len);
}

void
ssh_packet_put_bignum(struct ssh *ssh, BIGNUM * value)
{
	buffer_put_bignum(&ssh->state->outgoing_packet, value);
}

void
ssh_packet_put_bignum2(struct ssh *ssh, BIGNUM * value)
{
	buffer_put_bignum2(&ssh->state->outgoing_packet, value);
}

void
ssh_packet_put_ecpoint(struct ssh *ssh, const EC_GROUP *curve, const EC_POINT *point)
{
	buffer_put_ecpoint(&ssh->state->outgoing_packet, curve, point);
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

void
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
		buffer_clear(&state->compression_buffer);
		/* Skip padding. */
		buffer_consume(&state->outgoing_packet, 8);
		/* padding */
		buffer_append(&state->compression_buffer,
		    "\0\0\0\0\0\0\0\0", 8);
		buffer_compress(&state->outgoing_packet,
		    &state->compression_buffer);
		buffer_clear(&state->outgoing_packet);
		buffer_append(&state->outgoing_packet,
		    buffer_ptr(&state->compression_buffer),
		    buffer_len(&state->compression_buffer));
	}
	/* Compute packet length without padding (add checksum, remove padding). */
	len = buffer_len(&state->outgoing_packet) + 4 - 8;

	/* Insert padding. Initialized to zero in packet_start1() */
	padding = 8 - len % 8;
	if (!state->send_context.plaintext) {
		cp = buffer_ptr(&state->outgoing_packet);
		for (i = 0; i < padding; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[7 - i] = rnd & 0xff;
			rnd >>= 8;
		}
	}
	buffer_consume(&state->outgoing_packet, 8 - padding);

	/* Add check bytes. */
	checksum = ssh_crc32(buffer_ptr(&state->outgoing_packet),
	    buffer_len(&state->outgoing_packet));
	put_u32(buf, checksum);
	buffer_append(&state->outgoing_packet, buf, 4);

#ifdef PACKET_DEBUG
	fprintf(stderr, "packet_send plain: ");
	buffer_dump(&state->outgoing_packet);
#endif

	/* Append to output. */
	put_u32(buf, len);
	buffer_append(&state->output, buf, 4);
	cp = buffer_append_space(&state->output,
	    buffer_len(&state->outgoing_packet));
	if ((r = cipher_crypt(&state->send_context, cp,
	    buffer_ptr(&state->outgoing_packet),
	    buffer_len(&state->outgoing_packet))) != 0)
		fatal("%s: cipher_crypt failed: %s", __func__, ssh_err(r));

#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&state->output);
#endif
	state->p_send.packets++;
	state->p_send.bytes += len +
	    buffer_len(&state->outgoing_packet);
	buffer_clear(&state->outgoing_packet);

	/*
	 * Note that the packet is now only buffered in output.  It won't be
	 * actually sent until packet_write_wait or packet_write_poll is
	 * called.
	 */
}

void
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
			fatal("%s: cipher_cleanup failed: %s",
			    __func__, ssh_err(r));
		enc  = &state->newkeys[mode]->enc;
		mac  = &state->newkeys[mode]->mac;
		comp = &state->newkeys[mode]->comp;
		mac_clear(mac);
		xfree(enc->name);
		xfree(enc->iv);
		xfree(enc->key);
		xfree(mac->name);
		xfree(mac->key);
		xfree(comp->name);
		xfree(state->newkeys[mode]);
	}
	state->newkeys[mode] = kex_get_newkeys(ssh, mode);
	if (state->newkeys[mode] == NULL)
		fatal("newkeys: no keys for mode %d", mode);
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	if (mac_init(mac) == 0)
		mac->enabled = 1;
	DBG(debug("cipher_init_context: %d", mode));
	if ((r = cipher_init(cc, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->block_size, crypt_type)) != 0)
		fatal("%s: cipher_init failed: %s", __func__, ssh_err(r));
	if (!ssh->cipher_warning_done &&
	    (wmsg = cipher_warning_message(cc)) != NULL) {
		error("Warning: %s", wmsg);
		ssh->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* memset(enc->iv,  0, enc->block_size);
	   memset(enc->key, 0, enc->key_len);
	   memset(mac->key, 0, mac->key_len); */
	if ((comp->type == COMP_ZLIB ||
	    (comp->type == COMP_DELAYED &&
	     state->after_authentication)) && comp->enabled == 0) {
		ssh_packet_init_compression(ssh);
		if (mode == MODE_OUT)
			buffer_compress_init_send(6);
		else
			buffer_compress_init_recv();
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
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
void
ssh_packet_enable_delayed_compress(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	Comp *comp = NULL;
	int mode;

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
			ssh_packet_init_compression(ssh);
			if (mode == MODE_OUT)
				buffer_compress_init_send(6);
			else
				buffer_compress_init_recv();
			comp->enabled = 1;
		}
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
void
ssh_packet_send2_wrapped(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_char type, *cp, *macbuf = NULL;
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

	cp = buffer_ptr(&state->outgoing_packet);
	type = cp[5];

#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	buffer_dump(&state->outgoing_packet);
#endif

	if (comp && comp->enabled) {
		len = buffer_len(&state->outgoing_packet);
		/* skip header, compress only payload */
		buffer_consume(&state->outgoing_packet, 5);
		buffer_clear(&state->compression_buffer);
		buffer_compress(&state->outgoing_packet,
		    &state->compression_buffer);
		buffer_clear(&state->outgoing_packet);
		buffer_append(&state->outgoing_packet, "\0\0\0\0\0", 5);
		buffer_append(&state->outgoing_packet,
		    buffer_ptr(&state->compression_buffer),
		    buffer_len(&state->compression_buffer));
		DBG(debug("compression: raw %d compressed %d", len,
		    buffer_len(&state->outgoing_packet)));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = buffer_len(&state->outgoing_packet);

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
	cp = buffer_append_space(&state->outgoing_packet, padlen);
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
	packet_length = buffer_len(&state->outgoing_packet) - 4;
	cp = buffer_ptr(&state->outgoing_packet);
	put_u32(cp, packet_length);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d)", packet_length+4, padlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, state->p_send.seqnr,
		    buffer_ptr(&state->outgoing_packet),
		    buffer_len(&state->outgoing_packet));
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	cp = buffer_append_space(&state->output,
	    buffer_len(&state->outgoing_packet));
	if ((r = cipher_crypt(&state->send_context, cp,
	    buffer_ptr(&state->outgoing_packet),
	    buffer_len(&state->outgoing_packet))) != 0)
		fatal("%s: cipher_crypt failed: %s", __func__, ssh_err(r));
	/* append unencrypted MAC */
	if (mac && mac->enabled)
		buffer_append(&state->output, macbuf, mac->mac_len);
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&state->output);
#endif
	/* increment sequence number for outgoing packets */
	if (++state->p_send.seqnr == 0)
		logit("outgoing seqnr wraps around");
	if (++state->p_send.packets == 0)
		if (!(ssh->datafellows & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	state->p_send.blocks += (packet_length + 4) / block_size;
	state->p_send.bytes += packet_length + 4;
	buffer_clear(&state->outgoing_packet);

	if (type == SSH2_MSG_NEWKEYS)
		ssh_set_newkeys(ssh, MODE_OUT);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS && state->server_side)
		ssh_packet_enable_delayed_compress(ssh);
}

void
ssh_packet_send2(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct packet *p;
	u_char type, *cp;

	cp = buffer_ptr(&state->outgoing_packet);
	type = cp[5];

	/* during rekeying we can only send key exchange messages */
	if (state->rekeying) {
		if ((type < SSH2_MSG_TRANSPORT_MIN) ||
		    (type > SSH2_MSG_TRANSPORT_MAX) ||
		    (type == SSH2_MSG_SERVICE_REQUEST) ||
		    (type == SSH2_MSG_SERVICE_ACCEPT)) {
			debug("enqueue packet: %u", type);
			p = xmalloc(sizeof(*p));
			p->type = type;
			memcpy(&p->payload, &state->outgoing_packet,
			    sizeof(Buffer));
			buffer_init(&state->outgoing_packet);
			TAILQ_INSERT_TAIL(&state->outgoing, p, next);
			return;
		}
	}

	/* rekeying starts with sending KEXINIT */
	if (type == SSH2_MSG_KEXINIT)
		state->rekeying = 1;

	ssh_packet_send2_wrapped(ssh);

	/* after a NEWKEYS message we can send the complete queue */
	if (type == SSH2_MSG_NEWKEYS) {
		state->rekeying = 0;
		while ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			debug("dequeue packet: %u", type);
			buffer_free(&state->outgoing_packet);
			memcpy(&state->outgoing_packet, &p->payload,
			    sizeof(Buffer));
			TAILQ_REMOVE(&state->outgoing, p, next);
			xfree(p);
			ssh_packet_send2_wrapped(ssh);
		}
	}
}

void
ssh_packet_send(struct ssh *ssh)
{
	if (compat20)
		ssh_packet_send2(ssh);
	else
		ssh_packet_send1(ssh);
	DBG(debug("packet_send done"));
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

int
ssh_packet_read_seqnr(struct ssh *ssh, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	int type, len, ret, ms_remain, cont;
	fd_set *setp;
	char buf[8192];
	struct timeval timeout, start, *timeoutp = NULL;

	DBG(debug("packet_read()"));

	setp = (fd_set *)xcalloc(howmany(state->connection_in + 1,
	    NFDBITS), sizeof(fd_mask));

	/* Since we are blocking, ensure that all written packets have been sent. */
	ssh_packet_write_wait(ssh);

	/* Stay in the loop until we have received a complete packet. */
	for (;;) {
		/* Try to read a packet from the buffer. */
		type = ssh_packet_read_poll_seqnr(ssh, seqnr_p);
		if (!compat20 && (
		    type == SSH_SMSG_SUCCESS
		    || type == SSH_SMSG_FAILURE
		    || type == SSH_CMSG_EOF
		    || type == SSH_CMSG_EXIT_CONFIRMATION))
			ssh_packet_check_eom(ssh);
		/* If we got a packet, return it. */
		if (type != SSH_MSG_NONE) {
			xfree(setp);
			return type;
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
			if ((ret = select(state->connection_in + 1, setp,
			    NULL, NULL, timeoutp)) >= 0)
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
			    "waiting to read", get_remote_ipaddr());
			cleanup_exit(255);
		}
		/* Read data from the socket. */
		do {
			cont = 0;
			len = roaming_read(state->connection_in, buf,
			    sizeof(buf), &cont);
		} while (len == 0 && cont);
		if (len == 0) {
			logit("Connection closed by %.200s", get_remote_ipaddr());
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
	return ssh_packet_read_seqnr(ssh, NULL);
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
ssh_packet_read_poll1(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_int len, padded_len;
	u_char *cp, type;
	u_int checksum, stored_checksum;
	int r;

	/* Check if input size is less than minimum packet size. */
	if (buffer_len(&state->input) < 4 + 8)
		return SSH_MSG_NONE;
	/* Get length of incoming packet. */
	cp = buffer_ptr(&state->input);
	len = get_u32(cp);
	if (len < 1 + 2 + 2 || len > 256 * 1024)
		ssh_packet_disconnect(ssh, "Bad packet length %u.",
		    len);
	padded_len = (len + 8) & ~7;

	/* Check if the packet has been entirely received. */
	if (buffer_len(&state->input) < 4 + padded_len)
		return SSH_MSG_NONE;

	/* The entire packet is in buffer. */

	/* Consume packet length. */
	buffer_consume(&state->input, 4);

	/*
	 * Cryptographic attack detector for ssh
	 * (C)1998 CORE-SDI, Buenos Aires Argentina
	 * Ariel Futoransky(futo@core-sdi.com)
	 */
	if (!state->receive_context.plaintext) {
		switch (detect_attack(buffer_ptr(&state->input),
		    padded_len)) {
		case DEATTACK_DETECTED:
			ssh_packet_disconnect(ssh,
			    "crc32 compensation attack: network attack detected"
			);
		case DEATTACK_DOS_DETECTED:
			ssh_packet_disconnect(ssh,
			    "deattack denial of service detected");
		}
	}

	/* Decrypt data to incoming_packet. */
	buffer_clear(&state->incoming_packet);
	cp = buffer_append_space(&state->incoming_packet, padded_len);
	if ((r = cipher_crypt(&state->receive_context, cp,
	    buffer_ptr(&state->input), padded_len)) != 0)
		fatal("%s: cipher_crypt failed: %s", __func__, ssh_err(r));

	buffer_consume(&state->input, padded_len);

#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll plain: ");
	buffer_dump(&state->incoming_packet);
#endif

	/* Compute packet checksum. */
	checksum = ssh_crc32(buffer_ptr(&state->incoming_packet),
	    buffer_len(&state->incoming_packet) - 4);

	/* Skip padding. */
	buffer_consume(&state->incoming_packet, 8 - len % 8);

	/* Test check bytes. */
	if (len != buffer_len(&state->incoming_packet))
		ssh_packet_disconnect(ssh,
		    "packet_read_poll1: len %d != buffer_len %d.",
		    len, buffer_len(&state->incoming_packet));

	cp = (u_char *)buffer_ptr(&state->incoming_packet) + len - 4;
	stored_checksum = get_u32(cp);
	if (checksum != stored_checksum)
		ssh_packet_disconnect(ssh,
		    "Corrupted check bytes on input.");
	buffer_consume_end(&state->incoming_packet, 4);

	if (state->packet_compression) {
		buffer_clear(&state->compression_buffer);
		buffer_uncompress(&state->incoming_packet,
		    &state->compression_buffer);
		buffer_clear(&state->incoming_packet);
		buffer_append(&state->incoming_packet,
		    buffer_ptr(&state->compression_buffer),
		    buffer_len(&state->compression_buffer));
	}
	state->p_read.packets++;
	state->p_read.bytes += padded_len + 4;
	type = buffer_get_char(&state->incoming_packet);
	if (type < SSH_MSG_MIN || type > SSH_MSG_MAX)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh1 packet type: %d", type);
	return type;
}

int
ssh_packet_read_poll2(struct ssh *ssh, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int padlen, need;
	u_char *macbuf, *cp, type;
	u_int maclen, block_size;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int r;

	if (state->packet_discard)
		return SSH_MSG_NONE;

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
		if (buffer_len(&state->input) < block_size)
			return SSH_MSG_NONE;
		buffer_clear(&state->incoming_packet);
		cp = buffer_append_space(&state->incoming_packet,
		    block_size);
		if ((r = cipher_crypt(&state->receive_context, cp,
		    buffer_ptr(&state->input), block_size)) != 0)
			fatal("%s: cipher_crypt failed: %s",
			    __func__, ssh_err(r));
		cp = buffer_ptr(&state->incoming_packet);
		state->packlen = get_u32(cp);
		if (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			buffer_dump(&state->incoming_packet);
#endif
			logit("Bad packet length %u.", state->packlen);
			ssh_packet_start_discard(ssh, enc, mac,
			    state->packlen, PACKET_MAX_SIZE);
			return SSH_MSG_NONE;
		}
		DBG(debug("input: packet len %u", state->packlen+4));
		buffer_consume(&state->input, block_size);
	}
	/* we have a partial packet of block_size bytes */
	need = 4 + state->packlen - block_size;
	DBG(debug("partial packet %d, need %d, maclen %d", block_size,
	    need, maclen));
	if (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		ssh_packet_start_discard(ssh, enc, mac,
		    state->packlen, PACKET_MAX_SIZE - block_size);
		return SSH_MSG_NONE;
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet
	 */
	if (buffer_len(&state->input) < need + maclen)
		return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	buffer_dump(&state->input);
#endif
	cp = buffer_append_space(&state->incoming_packet, need);
	if ((r = cipher_crypt(&state->receive_context, cp,
	    buffer_ptr(&state->input), need)) != 0)
		fatal("%s: cipher_crypt failed: %s", __func__, ssh_err(r));
	buffer_consume(&state->input, need);
	/*
	 * compute MAC over seqnr and packet,
	 * increment sequence number for incoming packet
	 */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, state->p_read.seqnr,
		    buffer_ptr(&state->incoming_packet),
		    buffer_len(&state->incoming_packet));
		if (timingsafe_bcmp(macbuf, buffer_ptr(&state->input),
		    mac->mac_len) != 0) {
			logit("Corrupted MAC on input.");
			if (need > PACKET_MAX_SIZE)
				fatal("internal error need %d", need);
			ssh_packet_start_discard(ssh, enc, mac,
			    state->packlen, PACKET_MAX_SIZE - need);
			return SSH_MSG_NONE;
		}
				
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		buffer_consume(&state->input, mac->mac_len);
	}
	/* XXX now it's safe to use fatal/packet_disconnect */
	if (seqnr_p != NULL)
		*seqnr_p = state->p_read.seqnr;
	if (++state->p_read.seqnr == 0)
		logit("incoming seqnr wraps around");
	if (++state->p_read.packets == 0)
		if (!(ssh->datafellows & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	cp = buffer_ptr(&state->incoming_packet);
	padlen = cp[4];
	DBG(debug("input: padlen %d", padlen));
	if (padlen < 4)
		ssh_packet_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen);

	/* skip packet size + padlen, discard padding */
	buffer_consume(&state->incoming_packet, 4 + 1);
	buffer_consume_end(&state->incoming_packet, padlen);

	DBG(debug("input: len before de-compress %d",
	    buffer_len(&state->incoming_packet)));
	if (comp && comp->enabled) {
		buffer_clear(&state->compression_buffer);
		buffer_uncompress(&state->incoming_packet,
		    &state->compression_buffer);
		buffer_clear(&state->incoming_packet);
		buffer_append(&state->incoming_packet,
		    buffer_ptr(&state->compression_buffer),
		    buffer_len(&state->compression_buffer));
		DBG(debug("input: len after de-compress %d",
		    buffer_len(&state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	type = buffer_get_char(&state->incoming_packet);
	if (type < SSH2_MSG_MIN || type >= SSH2_MSG_LOCAL_MIN)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", type);
	if (type == SSH2_MSG_NEWKEYS)
		ssh_set_newkeys(ssh, MODE_IN);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS &&
	    !state->server_side)
		ssh_packet_enable_delayed_compress(ssh);
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", type);
	buffer_dump(&state->incoming_packet);
#endif
	/* reset for next packet */
	state->packlen = 0;
	return type;
}

int
ssh_packet_read_poll_seqnr(struct ssh *ssh, u_int32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int reason, seqnr;
	u_char type;
	char *msg;

	for (;;) {
		if (compat20) {
			type = ssh_packet_read_poll2(ssh, seqnr_p);
			if (type) {
				state->keep_alive_timeouts = 0;
				DBG(debug("received packet type %d", type));
			}
			switch (type) {
			case SSH2_MSG_IGNORE:
				debug3("Received SSH2_MSG_IGNORE");
				break;
			case SSH2_MSG_DEBUG:
				ssh_packet_get_char(ssh);
				msg = ssh_packet_get_string(ssh, NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				msg = ssh_packet_get_string(ssh, NULL);
				xfree(msg);
				break;
			case SSH2_MSG_DISCONNECT:
				reason = ssh_packet_get_int(ssh);
				msg = ssh_packet_get_string(ssh, NULL);
				logit("Received disconnect from %s: %u: %.400s",
				    get_remote_ipaddr(), reason, msg);
				xfree(msg);
				cleanup_exit(255);
				break;
			case SSH2_MSG_UNIMPLEMENTED:
				seqnr = ssh_packet_get_int(ssh);
				debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
				    seqnr);
				break;
			default:
				return type;
			}
		} else {
			type = ssh_packet_read_poll1(ssh);
			switch (type) {
			case SSH_MSG_IGNORE:
				break;
			case SSH_MSG_DEBUG:
				msg = ssh_packet_get_string(ssh, NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				break;
			case SSH_MSG_DISCONNECT:
				msg = ssh_packet_get_string(ssh, NULL);
				logit("Received disconnect from %s: %.400s",
				    get_remote_ipaddr(), msg);
				cleanup_exit(255);
				break;
			default:
				if (type)
					DBG(debug("received packet type %d", type));
				return type;
			}
		}
	}
}

int
ssh_packet_read_poll(struct ssh *ssh)
{
	return ssh_packet_read_poll_seqnr(ssh, NULL);
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
ssh_packet_process_incoming(struct ssh *ssh, const char *buf, u_int len)
{
	struct session_state *state = ssh->state;

	if (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		if (len >= state->packet_discard)
			ssh_packet_stop_discard(ssh);
		state->packet_discard -= len;
		return;
	}
	buffer_append(&ssh->state->input, buf, len);
}

/* Returns a character from the packet. */

u_int
ssh_packet_get_char(struct ssh *ssh)
{
	char ch;

	buffer_get(&ssh->state->incoming_packet, &ch, 1);
	return (u_char) ch;
}

/* Returns an integer from the packet data. */

u_int
ssh_packet_get_int(struct ssh *ssh)
{
	return buffer_get_int(&ssh->state->incoming_packet);
}

/* Returns an 64 bit integer from the packet data. */

u_int64_t
ssh_packet_get_int64(struct ssh *ssh)
{
	return buffer_get_int64(&ssh->state->incoming_packet);
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
ssh_packet_get_bignum(struct ssh *ssh, BIGNUM * value)
{
	buffer_get_bignum(&ssh->state->incoming_packet, value);
}

void
ssh_packet_get_bignum2(struct ssh *ssh, BIGNUM * value)
{
	buffer_get_bignum2(&ssh->state->incoming_packet, value);
}

void
ssh_packet_get_ecpoint(struct ssh *ssh, const EC_GROUP *curve, EC_POINT *point)
{
	buffer_get_ecpoint(&ssh->state->incoming_packet, curve, point);
}

void *
ssh_packet_get_raw(struct ssh *ssh, u_int *length_ptr)
{
	u_int bytes = buffer_len(&ssh->state->incoming_packet);

	if (length_ptr != NULL)
		*length_ptr = bytes;
	return buffer_ptr(&ssh->state->incoming_packet);
}

int
ssh_packet_remaining(struct ssh *ssh)
{
	return buffer_len(&ssh->state->incoming_packet);
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
ssh_packet_get_string(struct ssh *ssh, u_int *length_ptr)
{
	return buffer_get_string(&ssh->state->incoming_packet, length_ptr);
}

const void *
ssh_packet_get_string_ptr(struct ssh *ssh, u_int *length_ptr)
{
	return buffer_get_string_ptr(&ssh->state->incoming_packet, length_ptr);
}

/* Ensures the returned string has no embedded \0 characters in it. */
char *
ssh_packet_get_cstring(struct ssh *ssh, u_int *length_ptr)
{
	return buffer_get_cstring(&ssh->state->incoming_packet, length_ptr);
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

	if (compat20 && (ssh->datafellows & SSH_BUG_DEBUG))
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

	/* Stop listening for connections. */
	channel_close_all();

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void
ssh_packet_write_poll(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	int len = buffer_len(&state->output);
	int cont;

	if (len > 0) {
		cont = 0;
		len = roaming_write(state->connection_out,
		    buffer_ptr(&state->output), len, &cont);
		if (len == -1) {
			if (errno == EINTR || errno == EAGAIN)
				return;
			fatal("Write failed: %.100s", strerror(errno));
		}
		if (len == 0 && !cont)
			fatal("Write connection closed");
		buffer_consume(&state->output, len);
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

	setp = (fd_set *)xcalloc(howmany(state->connection_out + 1,
	    NFDBITS), sizeof(fd_mask));
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
			    "waiting to write", get_remote_ipaddr());
			cleanup_exit(255);
		}
		ssh_packet_write_poll(ssh);
	}
	xfree(setp);
}

/* Returns true if there is buffered data to write to the connection. */

int
ssh_packet_have_data_to_write(struct ssh *ssh)
{
	return buffer_len(&ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

int
ssh_packet_not_very_much_data_to_write(struct ssh *ssh)
{
	if (ssh->state->interactive_mode)
		return buffer_len(&ssh->state->output) < 16384;
	else
		return buffer_len(&ssh->state->output) < 128 * 1024;
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

	if (ssh->datafellows & SSH_BUG_NOREKEY)
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
	return (void *)&ssh->state->input;
}

void *
ssh_packet_get_output(struct ssh *ssh)
{
	return (void *)&ssh->state->output;
}

void *
ssh_packet_get_newkeys(struct ssh *ssh, int mode)
{
	return (void *)ssh->state->newkeys[mode];
}

/* TODO Hier brauchen wir noch eine Loesung! */
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

/* TODO Hier brauchen wir noch eine Loesung! */
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

	tmp = backup_state;
	backup_state = ssh;
	ssh = tmp;
	ssh->state->connection_in = backup_state->state->connection_in;
	backup_state->state->connection_in = -1;
	ssh->state->connection_out = backup_state->state->connection_out;
	backup_state->state->connection_out = -1;
	len = buffer_len(&backup_state->state->input);
	if (len > 0) {
		buf = buffer_ptr(&backup_state->state->input);
		buffer_append(&ssh->state->input, buf, len);
		buffer_clear(&backup_state->state->input);
		add_recv_bytes(len);
	}
}

/* Reset after_authentication and reset compression in post-auth privsep */
void
ssh_packet_set_postauth(struct ssh *ssh)
{
	Comp *comp;
	int mode;

	debug("%s: called", __func__);
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	for (mode = 0; mode < MODE_MAX; mode++) {
		if (ssh->state->newkeys[mode] == NULL)
			continue;
		comp = &ssh->state->newkeys[mode]->comp;
		if (comp && comp->enabled)
			ssh_packet_init_compression(ssh);
	}
}
