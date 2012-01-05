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

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

struct session_state *
ssh_alloc_session_state(void)
{
	struct session_state *s = xcalloc(1, sizeof(*s));

	s->connection_in = -1;
	s->connection_out = -1;
	s->max_packet_size = 32768;
	s->packet_timeout_ms = -1;
	return s;
}

/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
struct session_state *
ssh_packet_set_connection(struct session_state *ssh, int fd_in, int fd_out)
{
	Cipher *none = cipher_by_name("none");

	if (none == NULL)
		fatal("packet_set_connection: cannot load cipher 'none'");
	if (ssh == NULL)
		ssh = ssh_alloc_session_state();
	ssh->connection_in = fd_in;
	ssh->connection_out = fd_out;
	cipher_init(&ssh->send_context, none, (const u_char *)"",
	    0, NULL, 0, CIPHER_ENCRYPT);
	cipher_init(&ssh->receive_context, none, (const u_char *)"",
	    0, NULL, 0, CIPHER_DECRYPT);
	ssh->newkeys[MODE_IN] = ssh->newkeys[MODE_OUT] = NULL;
	if (!ssh->initialized) {
		ssh->initialized = 1;
		buffer_init(&ssh->input);
		buffer_init(&ssh->output);
		buffer_init(&ssh->outgoing_packet);
		buffer_init(&ssh->incoming_packet);
		TAILQ_INIT(&ssh->outgoing);
		TAILQ_INIT(&ssh->private_keys);
		TAILQ_INIT(&ssh->public_keys);
		ssh->p_send.packets = ssh->p_read.packets = 0;
	}

	return ssh;
}

void
ssh_packet_set_timeout(struct session_state *ssh, int timeout, int count)
{
	if (timeout <= 0 || count <= 0) {
		ssh->packet_timeout_ms = -1;
		return;
	}
	if ((INT_MAX / 1000) / count < timeout)
		ssh->packet_timeout_ms = INT_MAX;
	else
		ssh->packet_timeout_ms = timeout * count * 1000;
}

void
ssh_packet_stop_discard(struct session_state *ssh)
{
	if (ssh->packet_discard_mac) {
		char buf[1024];
		
		memset(buf, 'a', sizeof(buf));
		while (buffer_len(&ssh->incoming_packet) <
		    PACKET_MAX_SIZE)
			buffer_append(&ssh->incoming_packet, buf,
			    sizeof(buf));
		(void) mac_compute(ssh->packet_discard_mac,
		    ssh->p_read.seqnr,
		    buffer_ptr(&ssh->incoming_packet),
		    PACKET_MAX_SIZE);
	}
	logit("Finished discarding for %.200s", get_remote_ipaddr());
	cleanup_exit(255);
}

void
ssh_packet_start_discard(struct session_state *ssh, Enc *enc, Mac *mac,
    u_int packet_length, u_int discard)
{
	if (enc == NULL || !cipher_is_cbc(enc->cipher))
		ssh_packet_disconnect(ssh, "Packet corrupt");
	if (packet_length != PACKET_MAX_SIZE && mac && mac->enabled)
		ssh->packet_discard_mac = mac;
	if (buffer_len(&ssh->input) >= discard)
		ssh_packet_stop_discard(ssh);
	ssh->packet_discard = discard -
	    buffer_len(&ssh->input);
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

int
ssh_packet_connection_is_on_socket(struct session_state *ssh)
{
	struct sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	/* filedescriptors in and out are the same, so it's a socket */
	if (ssh->connection_in == ssh->connection_out)
		return 1;
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(ssh->connection_in, (struct sockaddr *)&from,
	    &fromlen) < 0)
		return 0;
	tolen = sizeof(to);
	memset(&to, 0, sizeof(to));
	if (getpeername(ssh->connection_out, (struct sockaddr *)&to,
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
ssh_packet_get_keyiv(struct session_state *ssh, int mode, u_char *iv,
    u_int len)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->send_context;
	else
		cc = &ssh->receive_context;

	cipher_get_keyiv(cc, iv, len);
}

int
ssh_packet_get_keycontext(struct session_state *ssh, int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->send_context;
	else
		cc = &ssh->receive_context;

	return (cipher_get_keycontext(cc, dat));
}

void
ssh_packet_set_keycontext(struct session_state *ssh, int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->send_context;
	else
		cc = &ssh->receive_context;

	cipher_set_keycontext(cc, dat);
}

int
ssh_packet_get_keyiv_len(struct session_state *ssh, int mode)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->send_context;
	else
		cc = &ssh->receive_context;

	return (cipher_get_keyiv_len(cc));
}

void
ssh_packet_set_iv(struct session_state *ssh, int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &ssh->send_context;
	else
		cc = &ssh->receive_context;

	cipher_set_keyiv(cc, dat);
}

int
ssh_packet_get_ssh1_cipher(struct session_state *ssh)
{
	return (cipher_get_number(ssh->receive_context.cipher));
}

void
ssh_packet_get_state(struct session_state *ssh, int mode, u_int32_t *seqnr, u_int64_t *blocks,
    u_int32_t *packets, u_int64_t *bytes)
{
	struct packet_state *state;

	state = (mode == MODE_IN) ?
	    &ssh->p_read : &ssh->p_send;
	if (seqnr)
		*seqnr = state->seqnr;
	if (blocks)
		*blocks = state->blocks;
	if (packets)
		*packets = state->packets;
	if (bytes)
		*bytes = state->bytes;
}

void
ssh_packet_set_state(struct session_state *ssh, int mode, u_int32_t seqnr, u_int64_t blocks, u_int32_t packets,
    u_int64_t bytes)
{
	struct packet_state *state;

	state = (mode == MODE_IN) ?
	    &ssh->p_read : &ssh->p_send;
	state->seqnr = seqnr;
	state->blocks = blocks;
	state->packets = packets;
	state->bytes = bytes;
}

int
ssh_packet_connection_af(struct session_state *ssh)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	if (getsockname(ssh->connection_out, (struct sockaddr *)&to,
	    &tolen) < 0)
		return 0;
	return to.ss_family;
}

/* Sets the connection into non-blocking mode. */

void
ssh_packet_set_nonblocking(struct session_state *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->connection_in);

	if (ssh->connection_out != ssh->connection_in)
		set_nonblock(ssh->connection_out);
}

/* Returns the socket used for reading. */

int
ssh_packet_get_connection_in(struct session_state *ssh)
{
	return ssh->connection_in;
}

/* Returns the descriptor used for writing. */

int
ssh_packet_get_connection_out(struct session_state *ssh)
{
	return ssh->connection_out;
}

/* Closes the connection and clears and frees internal data structures. */

void
ssh_packet_close(struct session_state *ssh)
{
	if (!ssh->initialized)
		return;
	ssh->initialized = 0;
	if (ssh->connection_in == ssh->connection_out) {
		shutdown(ssh->connection_out, SHUT_RDWR);
		close(ssh->connection_out);
	} else {
		close(ssh->connection_in);
		close(ssh->connection_out);
	}
	buffer_free(&ssh->input);
	buffer_free(&ssh->output);
	buffer_free(&ssh->outgoing_packet);
	buffer_free(&ssh->incoming_packet);
	if (ssh->compression_buffer_ready) {
		buffer_free(&ssh->compression_buffer);
		buffer_compress_uninit();
	}
	cipher_cleanup(&ssh->send_context);
	cipher_cleanup(&ssh->receive_context);
}

/* Sets remote side protocol flags. */

void
ssh_packet_set_protocol_flags(struct session_state *ssh, u_int protocol_flags)
{
	ssh->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(struct session_state *ssh)
{
	return ssh->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

void
ssh_packet_init_compression(struct session_state *ssh)
{
	if (ssh->compression_buffer_ready == 1)
		return;
	ssh->compression_buffer_ready = 1;
	buffer_init(&ssh->compression_buffer);
}

void
ssh_packet_start_compression(struct session_state *ssh, int level)
{
	if (ssh->packet_compression && !compat20)
		fatal("Compression already enabled.");
	ssh->packet_compression = 1;
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
ssh_packet_set_encryption_key(struct session_state *ssh, const u_char *key, u_int keylen, int number)
{
	Cipher *cipher = cipher_by_number(number);

	if (cipher == NULL)
		fatal("packet_set_encryption_key: unknown cipher number %d", number);
	if (keylen < 20)
		fatal("packet_set_encryption_key: keylen too small: %d", keylen);
	if (keylen > SSH_SESSION_KEY_LENGTH)
		fatal("packet_set_encryption_key: keylen too big: %d", keylen);
	memcpy(ssh->ssh1_key, key, keylen);
	ssh->ssh1_keylen = keylen;
	cipher_init(&ssh->send_context, cipher, key, keylen, NULL,
	    0, CIPHER_ENCRYPT);
	cipher_init(&ssh->receive_context, cipher, key, keylen, NULL,
	    0, CIPHER_DECRYPT);
}

u_int
ssh_packet_get_encryption_key(struct session_state *ssh, u_char *key)
{
	if (key == NULL)
		return (ssh->ssh1_keylen);
	memcpy(key, ssh->ssh1_key, ssh->ssh1_keylen);
	return (ssh->ssh1_keylen);
}

/* Start constructing a packet to send. */
void
ssh_packet_start(struct session_state *ssh, u_char type)
{
	u_char buf[9];
	int len;

	DBG(debug("packet_start[%d]", type));
	len = compat20 ? 6 : 9;
	memset(buf, 0, len - 1);
	buf[len - 1] = type;
	buffer_clear(&ssh->outgoing_packet);
	buffer_append(&ssh->outgoing_packet, buf, len);
}

/* Append payload. */
void
ssh_packet_put_char(struct session_state *ssh, int value)
{
	char ch = value;

	buffer_append(&ssh->outgoing_packet, &ch, 1);
}

void
ssh_packet_put_int(struct session_state *ssh, u_int value)
{
	buffer_put_int(&ssh->outgoing_packet, value);
}

void
ssh_packet_put_int64(struct session_state *ssh, u_int64_t value)
{
	buffer_put_int64(&ssh->outgoing_packet, value);
}

void
ssh_packet_put_string(struct session_state *ssh, const void *buf, u_int len)
{
	buffer_put_string(&ssh->outgoing_packet, buf, len);
}

void
ssh_packet_put_cstring(struct session_state *ssh, const char *str)
{
	buffer_put_cstring(&ssh->outgoing_packet, str);
}

void
ssh_packet_put_raw(struct session_state *ssh, const void *buf, u_int len)
{
	buffer_append(&ssh->outgoing_packet, buf, len);
}

void
ssh_packet_put_bignum(struct session_state *ssh, BIGNUM * value)
{
	buffer_put_bignum(&ssh->outgoing_packet, value);
}

void
ssh_packet_put_bignum2(struct session_state *ssh, BIGNUM * value)
{
	buffer_put_bignum2(&ssh->outgoing_packet, value);
}

void
ssh_packet_put_ecpoint(struct session_state *ssh, const EC_GROUP *curve, const EC_POINT *point)
{
	buffer_put_ecpoint(&ssh->outgoing_packet, curve, point);
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

void
ssh_packet_send1(struct session_state *ssh)
{
	u_char buf[8], *cp;
	int i, padding, len;
	u_int checksum;
	u_int32_t rnd = 0;

	/*
	 * If using packet compression, compress the payload of the outgoing
	 * packet.
	 */
	if (ssh->packet_compression) {
		buffer_clear(&ssh->compression_buffer);
		/* Skip padding. */
		buffer_consume(&ssh->outgoing_packet, 8);
		/* padding */
		buffer_append(&ssh->compression_buffer,
		    "\0\0\0\0\0\0\0\0", 8);
		buffer_compress(&ssh->outgoing_packet,
		    &ssh->compression_buffer);
		buffer_clear(&ssh->outgoing_packet);
		buffer_append(&ssh->outgoing_packet,
		    buffer_ptr(&ssh->compression_buffer),
		    buffer_len(&ssh->compression_buffer));
	}
	/* Compute packet length without padding (add checksum, remove padding). */
	len = buffer_len(&ssh->outgoing_packet) + 4 - 8;

	/* Insert padding. Initialized to zero in packet_start1() */
	padding = 8 - len % 8;
	if (!ssh->send_context.plaintext) {
		cp = buffer_ptr(&ssh->outgoing_packet);
		for (i = 0; i < padding; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[7 - i] = rnd & 0xff;
			rnd >>= 8;
		}
	}
	buffer_consume(&ssh->outgoing_packet, 8 - padding);

	/* Add check bytes. */
	checksum = ssh_crc32(buffer_ptr(&ssh->outgoing_packet),
	    buffer_len(&ssh->outgoing_packet));
	put_u32(buf, checksum);
	buffer_append(&ssh->outgoing_packet, buf, 4);

#ifdef PACKET_DEBUG
	fprintf(stderr, "packet_send plain: ");
	buffer_dump(&ssh->outgoing_packet);
#endif

	/* Append to output. */
	put_u32(buf, len);
	buffer_append(&ssh->output, buf, 4);
	cp = buffer_append_space(&ssh->output,
	    buffer_len(&ssh->outgoing_packet));
	cipher_crypt(&ssh->send_context, cp,
	    buffer_ptr(&ssh->outgoing_packet),
	    buffer_len(&ssh->outgoing_packet));

#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&ssh->output);
#endif
	ssh->p_send.packets++;
	ssh->p_send.bytes += len +
	    buffer_len(&ssh->outgoing_packet);
	buffer_clear(&ssh->outgoing_packet);

	/*
	 * Note that the packet is now only buffered in output.  It won't be
	 * actually sent until packet_write_wait or packet_write_poll is
	 * called.
	 */
}

void
ssh_set_newkeys(struct session_state *ssh, int mode)
{
	Enc *enc;
	Mac *mac;
	Comp *comp;
	CipherContext *cc;
	u_int64_t *max_blocks;
	int crypt_type;

	debug2("set_newkeys: mode %d", mode);

	if (mode == MODE_OUT) {
		cc = &ssh->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ssh->p_send.packets = ssh->p_send.blocks = 0;
		max_blocks = &ssh->max_blocks_out;
	} else {
		cc = &ssh->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ssh->p_read.packets = ssh->p_read.blocks = 0;
		max_blocks = &ssh->max_blocks_in;
	}
	if (ssh->newkeys[mode] != NULL) {
		debug("set_newkeys: rekeying");
		cipher_cleanup(cc);
		enc  = &ssh->newkeys[mode]->enc;
		mac  = &ssh->newkeys[mode]->mac;
		comp = &ssh->newkeys[mode]->comp;
		mac_clear(mac);
		xfree(enc->name);
		xfree(enc->iv);
		xfree(enc->key);
		xfree(mac->name);
		xfree(mac->key);
		xfree(comp->name);
		xfree(ssh->newkeys[mode]);
	}
	ssh->newkeys[mode] = kex_get_newkeys(ssh, mode);
	if (ssh->newkeys[mode] == NULL)
		fatal("newkeys: no keys for mode %d", mode);
	enc  = &ssh->newkeys[mode]->enc;
	mac  = &ssh->newkeys[mode]->mac;
	comp = &ssh->newkeys[mode]->comp;
	if (mac_init(mac) == 0)
		mac->enabled = 1;
	DBG(debug("cipher_init_context: %d", mode));
	cipher_init(cc, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->block_size, crypt_type);
	/* Deleting the keys does not gain extra security */
	/* memset(enc->iv,  0, enc->block_size);
	   memset(enc->key, 0, enc->key_len);
	   memset(mac->key, 0, mac->key_len); */
	if ((comp->type == COMP_ZLIB ||
	    (comp->type == COMP_DELAYED &&
	     ssh->after_authentication)) && comp->enabled == 0) {
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
	if (ssh->rekey_limit)
		*max_blocks = MIN(*max_blocks,
		    ssh->rekey_limit / enc->block_size);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
void
ssh_packet_enable_delayed_compress(struct session_state *ssh)
{
	Comp *comp = NULL;
	int mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	ssh->after_authentication = 1;
	for (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		if (ssh->newkeys[mode] == NULL)
			continue;
		comp = &ssh->newkeys[mode]->comp;
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
ssh_packet_send2_wrapped(struct session_state *ssh)
{
	u_char type, *cp, *macbuf = NULL;
	u_char padlen, pad;
	u_int packet_length = 0;
	u_int i, len;
	u_int32_t rnd = 0;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int block_size;

	if (ssh->newkeys[MODE_OUT] != NULL) {
		enc  = &ssh->newkeys[MODE_OUT]->enc;
		mac  = &ssh->newkeys[MODE_OUT]->mac;
		comp = &ssh->newkeys[MODE_OUT]->comp;
	}
	block_size = enc ? enc->block_size : 8;

	cp = buffer_ptr(&ssh->outgoing_packet);
	type = cp[5];

#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	buffer_dump(&ssh->outgoing_packet);
#endif

	if (comp && comp->enabled) {
		len = buffer_len(&ssh->outgoing_packet);
		/* skip header, compress only payload */
		buffer_consume(&ssh->outgoing_packet, 5);
		buffer_clear(&ssh->compression_buffer);
		buffer_compress(&ssh->outgoing_packet,
		    &ssh->compression_buffer);
		buffer_clear(&ssh->outgoing_packet);
		buffer_append(&ssh->outgoing_packet, "\0\0\0\0\0", 5);
		buffer_append(&ssh->outgoing_packet,
		    buffer_ptr(&ssh->compression_buffer),
		    buffer_len(&ssh->compression_buffer));
		DBG(debug("compression: raw %d compressed %d", len,
		    buffer_len(&ssh->outgoing_packet)));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = buffer_len(&ssh->outgoing_packet);

	/*
	 * calc size of padding, alloc space, get random data,
	 * minimum padding is 4 bytes
	 */
	padlen = block_size - (len % block_size);
	if (padlen < 4)
		padlen += block_size;
	if (ssh->extra_pad) {
		/* will wrap if extra_pad+padlen > 255 */
		ssh->extra_pad =
		    roundup(ssh->extra_pad, block_size);
		pad = ssh->extra_pad -
		    ((len + padlen) % ssh->extra_pad);
		debug3("packet_send2: adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, ssh->extra_pad);
		padlen += pad;
		ssh->extra_pad = 0;
	}
	cp = buffer_append_space(&ssh->outgoing_packet, padlen);
	if (enc && !ssh->send_context.plaintext) {
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
	packet_length = buffer_len(&ssh->outgoing_packet) - 4;
	cp = buffer_ptr(&ssh->outgoing_packet);
	put_u32(cp, packet_length);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d)", packet_length+4, padlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, ssh->p_send.seqnr,
		    buffer_ptr(&ssh->outgoing_packet),
		    buffer_len(&ssh->outgoing_packet));
		DBG(debug("done calc MAC out #%d", ssh->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	cp = buffer_append_space(&ssh->output,
	    buffer_len(&ssh->outgoing_packet));
	cipher_crypt(&ssh->send_context, cp,
	    buffer_ptr(&ssh->outgoing_packet),
	    buffer_len(&ssh->outgoing_packet));
	/* append unencrypted MAC */
	if (mac && mac->enabled)
		buffer_append(&ssh->output, macbuf, mac->mac_len);
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&ssh->output);
#endif
	/* increment sequence number for outgoing packets */
	if (++ssh->p_send.seqnr == 0)
		logit("outgoing seqnr wraps around");
	if (++ssh->p_send.packets == 0)
		if (!(ssh->datafellows & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	ssh->p_send.blocks += (packet_length + 4) / block_size;
	ssh->p_send.bytes += packet_length + 4;
	buffer_clear(&ssh->outgoing_packet);

	if (type == SSH2_MSG_NEWKEYS)
		ssh_set_newkeys(ssh, MODE_OUT);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS && ssh->server_side)
		ssh_packet_enable_delayed_compress(ssh);
}

void
ssh_packet_send2(struct session_state *ssh)
{
	struct packet *p;
	u_char type, *cp;

	cp = buffer_ptr(&ssh->outgoing_packet);
	type = cp[5];

	/* during rekeying we can only send key exchange messages */
	if (ssh->rekeying) {
		if (!((type >= SSH2_MSG_TRANSPORT_MIN) &&
		    (type <= SSH2_MSG_TRANSPORT_MAX))) {
			debug("enqueue packet: %u", type);
			p = xmalloc(sizeof(*p));
			p->type = type;
			memcpy(&p->payload, &ssh->outgoing_packet,
			    sizeof(Buffer));
			buffer_init(&ssh->outgoing_packet);
			TAILQ_INSERT_TAIL(&ssh->outgoing, p, next);
			return;
		}
	}

	/* rekeying starts with sending KEXINIT */
	if (type == SSH2_MSG_KEXINIT)
		ssh->rekeying = 1;

	ssh_packet_send2_wrapped(ssh);

	/* after a NEWKEYS message we can send the complete queue */
	if (type == SSH2_MSG_NEWKEYS) {
		ssh->rekeying = 0;
		while ((p = TAILQ_FIRST(&ssh->outgoing))) {
			type = p->type;
			debug("dequeue packet: %u", type);
			buffer_free(&ssh->outgoing_packet);
			memcpy(&ssh->outgoing_packet, &p->payload,
			    sizeof(Buffer));
			TAILQ_REMOVE(&ssh->outgoing, p, next);
			xfree(p);
			ssh_packet_send2_wrapped(ssh);
		}
	}
}

void
ssh_packet_send(struct session_state *ssh)
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
ssh_packet_read_seqnr(struct session_state *ssh, u_int32_t *seqnr_p)
{
	int type, len, ret, ms_remain, cont;
	fd_set *setp;
	char buf[8192];
	struct timeval timeout, start, *timeoutp = NULL;

	DBG(debug("packet_read()"));

	setp = (fd_set *)xcalloc(howmany(ssh->connection_in + 1,
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
		memset(setp, 0, howmany(ssh->connection_in + 1,
		    NFDBITS) * sizeof(fd_mask));
		FD_SET(ssh->connection_in, setp);

		if (ssh->packet_timeout_ms > 0) {
			ms_remain = ssh->packet_timeout_ms;
			timeoutp = &timeout;
		}
		/* Wait for some data to arrive. */
		for (;;) {
			if (ssh->packet_timeout_ms != -1) {
				ms_to_timeval(&timeout, ms_remain);
				gettimeofday(&start, NULL);
			}
			if ((ret = select(ssh->connection_in + 1, setp,
			    NULL, NULL, timeoutp)) >= 0)
				break;
			if (errno != EAGAIN && errno != EINTR)
				break;
			if (ssh->packet_timeout_ms == -1)
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
			len = roaming_read(ssh->connection_in, buf,
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
ssh_packet_read(struct session_state *ssh)
{
	return ssh_packet_read_seqnr(ssh, NULL);
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
ssh_packet_read_expect(struct session_state *ssh, int expected_type)
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
ssh_packet_read_poll1(struct session_state *ssh)
{
	u_int len, padded_len;
	u_char *cp, type;
	u_int checksum, stored_checksum;

	/* Check if input size is less than minimum packet size. */
	if (buffer_len(&ssh->input) < 4 + 8)
		return SSH_MSG_NONE;
	/* Get length of incoming packet. */
	cp = buffer_ptr(&ssh->input);
	len = get_u32(cp);
	if (len < 1 + 2 + 2 || len > 256 * 1024)
		ssh_packet_disconnect(ssh, "Bad packet length %u.",
		    len);
	padded_len = (len + 8) & ~7;

	/* Check if the packet has been entirely received. */
	if (buffer_len(&ssh->input) < 4 + padded_len)
		return SSH_MSG_NONE;

	/* The entire packet is in buffer. */

	/* Consume packet length. */
	buffer_consume(&ssh->input, 4);

	/*
	 * Cryptographic attack detector for ssh
	 * (C)1998 CORE-SDI, Buenos Aires Argentina
	 * Ariel Futoransky(futo@core-sdi.com)
	 */
	if (!ssh->receive_context.plaintext) {
		switch (detect_attack(buffer_ptr(&ssh->input),
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
	buffer_clear(&ssh->incoming_packet);
	cp = buffer_append_space(&ssh->incoming_packet, padded_len);
	cipher_crypt(&ssh->receive_context, cp,
	    buffer_ptr(&ssh->input), padded_len);

	buffer_consume(&ssh->input, padded_len);

#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll plain: ");
	buffer_dump(&ssh->incoming_packet);
#endif

	/* Compute packet checksum. */
	checksum = ssh_crc32(buffer_ptr(&ssh->incoming_packet),
	    buffer_len(&ssh->incoming_packet) - 4);

	/* Skip padding. */
	buffer_consume(&ssh->incoming_packet, 8 - len % 8);

	/* Test check bytes. */
	if (len != buffer_len(&ssh->incoming_packet))
		ssh_packet_disconnect(ssh,
		    "packet_read_poll1: len %d != buffer_len %d.",
		    len, buffer_len(&ssh->incoming_packet));

	cp = (u_char *)buffer_ptr(&ssh->incoming_packet) + len - 4;
	stored_checksum = get_u32(cp);
	if (checksum != stored_checksum)
		ssh_packet_disconnect(ssh,
		    "Corrupted check bytes on input.");
	buffer_consume_end(&ssh->incoming_packet, 4);

	if (ssh->packet_compression) {
		buffer_clear(&ssh->compression_buffer);
		buffer_uncompress(&ssh->incoming_packet,
		    &ssh->compression_buffer);
		buffer_clear(&ssh->incoming_packet);
		buffer_append(&ssh->incoming_packet,
		    buffer_ptr(&ssh->compression_buffer),
		    buffer_len(&ssh->compression_buffer));
	}
	ssh->p_read.packets++;
	ssh->p_read.bytes += padded_len + 4;
	type = buffer_get_char(&ssh->incoming_packet);
	if (type < SSH_MSG_MIN || type > SSH_MSG_MAX)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh1 packet type: %d", type);
	return type;
}

int
ssh_packet_read_poll2(struct session_state *ssh, u_int32_t *seqnr_p)
{
	u_int padlen, need;
	u_char *macbuf, *cp, type;
	u_int maclen, block_size;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;

	if (ssh->packet_discard)
		return SSH_MSG_NONE;

	if (ssh->newkeys[MODE_IN] != NULL) {
		enc  = &ssh->newkeys[MODE_IN]->enc;
		mac  = &ssh->newkeys[MODE_IN]->mac;
		comp = &ssh->newkeys[MODE_IN]->comp;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;

	if (ssh->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		if (buffer_len(&ssh->input) < block_size)
			return SSH_MSG_NONE;
		buffer_clear(&ssh->incoming_packet);
		cp = buffer_append_space(&ssh->incoming_packet,
		    block_size);
		cipher_crypt(&ssh->receive_context, cp,
		    buffer_ptr(&ssh->input), block_size);
		cp = buffer_ptr(&ssh->incoming_packet);
		ssh->packlen = get_u32(cp);
		if (ssh->packlen < 1 + 4 ||
		    ssh->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			buffer_dump(&ssh->incoming_packet);
#endif
			logit("Bad packet length %u.", ssh->packlen);
			ssh_packet_start_discard(ssh, enc, mac,
			    ssh->packlen, PACKET_MAX_SIZE);
			return SSH_MSG_NONE;
		}
		DBG(debug("input: packet len %u", ssh->packlen+4));
		buffer_consume(&ssh->input, block_size);
	}
	/* we have a partial packet of block_size bytes */
	need = 4 + ssh->packlen - block_size;
	DBG(debug("partial packet %d, need %d, maclen %d", block_size,
	    need, maclen));
	if (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		ssh_packet_start_discard(ssh, enc, mac,
		    ssh->packlen, PACKET_MAX_SIZE - block_size);
		return SSH_MSG_NONE;
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet
	 */
	if (buffer_len(&ssh->input) < need + maclen)
		return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	buffer_dump(&ssh->input);
#endif
	cp = buffer_append_space(&ssh->incoming_packet, need);
	cipher_crypt(&ssh->receive_context, cp,
	    buffer_ptr(&ssh->input), need);
	buffer_consume(&ssh->input, need);
	/*
	 * compute MAC over seqnr and packet,
	 * increment sequence number for incoming packet
	 */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, ssh->p_read.seqnr,
		    buffer_ptr(&ssh->incoming_packet),
		    buffer_len(&ssh->incoming_packet));
		if (timingsafe_bcmp(macbuf, buffer_ptr(&ssh->input),
		    mac->mac_len) != 0) {
			logit("Corrupted MAC on input.");
			if (need > PACKET_MAX_SIZE)
				fatal("internal error need %d", need);
			ssh_packet_start_discard(ssh, enc, mac,
			    ssh->packlen, PACKET_MAX_SIZE - need);
			return SSH_MSG_NONE;
		}
				
		DBG(debug("MAC #%d ok", ssh->p_read.seqnr));
		buffer_consume(&ssh->input, mac->mac_len);
	}
	/* XXX now it's safe to use fatal/packet_disconnect */
	if (seqnr_p != NULL)
		*seqnr_p = ssh->p_read.seqnr;
	if (++ssh->p_read.seqnr == 0)
		logit("incoming seqnr wraps around");
	if (++ssh->p_read.packets == 0)
		if (!(ssh->datafellows & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	ssh->p_read.blocks += (ssh->packlen + 4) / block_size;
	ssh->p_read.bytes += ssh->packlen + 4;

	/* get padlen */
	cp = buffer_ptr(&ssh->incoming_packet);
	padlen = cp[4];
	DBG(debug("input: padlen %d", padlen));
	if (padlen < 4)
		ssh_packet_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen);

	/* skip packet size + padlen, discard padding */
	buffer_consume(&ssh->incoming_packet, 4 + 1);
	buffer_consume_end(&ssh->incoming_packet, padlen);

	DBG(debug("input: len before de-compress %d",
	    buffer_len(&ssh->incoming_packet)));
	if (comp && comp->enabled) {
		buffer_clear(&ssh->compression_buffer);
		buffer_uncompress(&ssh->incoming_packet,
		    &ssh->compression_buffer);
		buffer_clear(&ssh->incoming_packet);
		buffer_append(&ssh->incoming_packet,
		    buffer_ptr(&ssh->compression_buffer),
		    buffer_len(&ssh->compression_buffer));
		DBG(debug("input: len after de-compress %d",
		    buffer_len(&ssh->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	type = buffer_get_char(&ssh->incoming_packet);
	if (type < SSH2_MSG_MIN || type >= SSH2_MSG_LOCAL_MIN)
		ssh_packet_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", type);
	if (type == SSH2_MSG_NEWKEYS)
		ssh_set_newkeys(ssh, MODE_IN);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS &&
	    !ssh->server_side)
		ssh_packet_enable_delayed_compress(ssh);
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", type);
	buffer_dump(&ssh->incoming_packet);
#endif
	/* reset for next packet */
	ssh->packlen = 0;
	return type;
}

int
ssh_packet_read_poll_seqnr(struct session_state *ssh, u_int32_t *seqnr_p)
{
	u_int reason, seqnr;
	u_char type;
	char *msg;

	for (;;) {
		if (compat20) {
			type = ssh_packet_read_poll2(ssh, seqnr_p);
			if (type) {
				ssh->keep_alive_timeouts = 0;
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
ssh_packet_read_poll(struct session_state *ssh)
{
	return ssh_packet_read_poll_seqnr(ssh, NULL);
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
ssh_packet_process_incoming(struct session_state *ssh, const char *buf, u_int len)
{
	if (ssh->packet_discard) {
		ssh->keep_alive_timeouts = 0; /* ?? */
		if (len >= ssh->packet_discard)
			ssh_packet_stop_discard(ssh);
		ssh->packet_discard -= len;
		return;
	}
	buffer_append(&ssh->input, buf, len);
}

/* Returns a character from the packet. */

u_int
ssh_packet_get_char(struct session_state *ssh)
{
	char ch;

	buffer_get(&ssh->incoming_packet, &ch, 1);
	return (u_char) ch;
}

/* Returns an integer from the packet data. */

u_int
ssh_packet_get_int(struct session_state *ssh)
{
	return buffer_get_int(&ssh->incoming_packet);
}

/* Returns an 64 bit integer from the packet data. */

u_int64_t
ssh_packet_get_int64(struct session_state *ssh)
{
	return buffer_get_int64(&ssh->incoming_packet);
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
ssh_packet_get_bignum(struct session_state *ssh, BIGNUM * value)
{
	buffer_get_bignum(&ssh->incoming_packet, value);
}

void
ssh_packet_get_bignum2(struct session_state *ssh, BIGNUM * value)
{
	buffer_get_bignum2(&ssh->incoming_packet, value);
}

void
ssh_packet_get_ecpoint(struct session_state *ssh, const EC_GROUP *curve, EC_POINT *point)
{
	buffer_get_ecpoint(&ssh->incoming_packet, curve, point);
}

void *
ssh_packet_get_raw(struct session_state *ssh, u_int *length_ptr)
{
	u_int bytes = buffer_len(&ssh->incoming_packet);

	if (length_ptr != NULL)
		*length_ptr = bytes;
	return buffer_ptr(&ssh->incoming_packet);
}

int
ssh_packet_remaining(struct session_state *ssh)
{
	return buffer_len(&ssh->incoming_packet);
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
ssh_packet_get_string(struct session_state *ssh, u_int *length_ptr)
{
	return buffer_get_string(&ssh->incoming_packet, length_ptr);
}

void *
ssh_packet_get_string_ptr(struct session_state *ssh, u_int *length_ptr)
{
	return buffer_get_string_ptr(&ssh->incoming_packet, length_ptr);
}

/* Ensures the returned string has no embedded \0 characters in it. */
char *
ssh_packet_get_cstring(struct session_state *ssh, u_int *length_ptr)
{
	return buffer_get_cstring(&ssh->incoming_packet, length_ptr);
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
ssh_packet_send_debug(struct session_state *ssh, const char *fmt,...)
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
ssh_packet_disconnect(struct session_state *ssh, const char *fmt,...)
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
ssh_packet_write_poll(struct session_state *ssh)
{
	int len = buffer_len(&ssh->output);
	int cont;

	if (len > 0) {
		cont = 0;
		len = roaming_write(ssh->connection_out,
		    buffer_ptr(&ssh->output), len, &cont);
		if (len == -1) {
			if (errno == EINTR || errno == EAGAIN)
				return;
			fatal("Write failed: %.100s", strerror(errno));
		}
		if (len == 0 && !cont)
			fatal("Write connection closed");
		buffer_consume(&ssh->output, len);
	}
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */

void
ssh_packet_write_wait(struct session_state *ssh)
{
	fd_set *setp;
	int ret, ms_remain;
	struct timeval start, timeout, *timeoutp = NULL;

	setp = (fd_set *)xcalloc(howmany(ssh->connection_out + 1,
	    NFDBITS), sizeof(fd_mask));
	ssh_packet_write_poll(ssh);
	while (ssh_packet_have_data_to_write(ssh)) {
		memset(setp, 0, howmany(ssh->connection_out + 1,
		    NFDBITS) * sizeof(fd_mask));
		FD_SET(ssh->connection_out, setp);

		if (ssh->packet_timeout_ms > 0) {
			ms_remain = ssh->packet_timeout_ms;
			timeoutp = &timeout;
		}
		for (;;) {
			if (ssh->packet_timeout_ms != -1) {
				ms_to_timeval(&timeout, ms_remain);
				gettimeofday(&start, NULL);
			}
			if ((ret = select(ssh->connection_out + 1,
			    NULL, setp, NULL, timeoutp)) >= 0)
				break;
			if (errno != EAGAIN && errno != EINTR)
				break;
			if (ssh->packet_timeout_ms == -1)
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
ssh_packet_have_data_to_write(struct session_state *ssh)
{
	return buffer_len(&ssh->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

int
ssh_packet_not_very_much_data_to_write(struct session_state *ssh)
{
	if (ssh->interactive_mode)
		return buffer_len(&ssh->output) < 16384;
	else
		return buffer_len(&ssh->output) < 128 * 1024;
}

void
ssh_packet_set_tos(struct session_state *ssh, int tos)
{
	if (!ssh_packet_connection_is_on_socket(ssh))
		return;
	switch (ssh_packet_connection_af(ssh)) {
	case AF_INET:
		debug3("%s: set IP_TOS 0x%02x", __func__, tos);
		if (setsockopt(ssh->connection_in,
		    IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0)
			error("setsockopt IP_TOS %d: %.100s:",
			    tos, strerror(errno));
		break;
	case AF_INET6:
		debug3("%s: set IPV6_TCLASS 0x%02x", __func__, tos);
		if (setsockopt(ssh->connection_in,
		    IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0)
			error("setsockopt IPV6_TCLASS %d: %.100s:",
			    tos, strerror(errno));
		break;
	}
}

/* Informs that the current session is interactive.  Sets IP flags for that. */

void
ssh_packet_set_interactive(struct session_state *ssh, int interactive, int qos_interactive, int qos_bulk)
{
	if (ssh->set_interactive_called)
		return;
	ssh->set_interactive_called = 1;

	/* Record that we are in interactive mode. */
	ssh->interactive_mode = interactive;

	/* Only set socket options if using a socket.  */
	if (!ssh_packet_connection_is_on_socket(ssh))
		return;
	set_nodelay(ssh->connection_in);
	ssh_packet_set_tos(ssh, interactive ? qos_interactive :
	    qos_bulk);
}

/* Returns true if the current connection is interactive. */

int
ssh_packet_is_interactive(struct session_state *ssh)
{
	return ssh->interactive_mode;
}

int
ssh_packet_set_maxsize(struct session_state *ssh, u_int s)
{
	if (ssh->set_maxsize_called) {
		logit("packet_set_maxsize: called twice: old %d new %d",
		    ssh->max_packet_size, s);
		return -1;
	}
	if (s < 4 * 1024 || s > 1024 * 1024) {
		logit("packet_set_maxsize: bad size %d", s);
		return -1;
	}
	ssh->set_maxsize_called = 1;
	debug("packet_set_maxsize: setting to %d", s);
	ssh->max_packet_size = s;
	return s;
}

int
ssh_packet_inc_alive_timeouts(struct session_state *ssh)
{
	return ++ssh->keep_alive_timeouts;
}

void
ssh_packet_set_alive_timeouts(struct session_state *ssh, int ka)
{
	ssh->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(struct session_state *ssh)
{
	return ssh->max_packet_size;
}

/* roundup current message to pad bytes */
void
ssh_packet_add_padding(struct session_state *ssh, u_char pad)
{
	ssh->extra_pad = pad;
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
ssh_packet_send_ignore(struct session_state *ssh, int nbytes)
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
ssh_packet_need_rekeying(struct session_state *ssh)
{
	if (ssh->datafellows & SSH_BUG_NOREKEY)
		return 0;
	return
	    (ssh->p_send.packets > MAX_PACKETS) ||
	    (ssh->p_read.packets > MAX_PACKETS) ||
	    (ssh->max_blocks_out &&
	        (ssh->p_send.blocks > ssh->max_blocks_out)) ||
	    (ssh->max_blocks_in &&
	        (ssh->p_read.blocks > ssh->max_blocks_in));
}

void
ssh_packet_set_rekey_limit(struct session_state *ssh, u_int32_t bytes)
{
	ssh->rekey_limit = bytes;
}

void
ssh_packet_set_server(struct session_state *ssh)
{
	ssh->server_side = 1;
}

void
ssh_packet_set_authenticated(struct session_state *ssh)
{
	ssh->after_authentication = 1;
}

void *
ssh_packet_get_input(struct session_state *ssh)
{
	return (void *)&ssh->input;
}

void *
ssh_packet_get_output(struct session_state *ssh)
{
	return (void *)&ssh->output;
}

void *
ssh_packet_get_newkeys(struct session_state *ssh, int mode)
{
	return (void *)ssh->newkeys[mode];
}

/* TODO Hier brauchen wir noch eine Loesung! */
/*
 * Save the state for the real connection, and use a separate state when
 * resuming a suspended connection.
 */
void
ssh_packet_backup_state(struct session_state *ssh,
    struct session_state *backup_state)
{
	struct session_state *tmp;

	close(ssh->connection_in);
	ssh->connection_in = -1;
	close(ssh->connection_out);
	ssh->connection_out = -1;
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
ssh_packet_restore_state(struct session_state *ssh,
    struct session_state *backup_state)
{
	struct session_state *tmp;
	void *buf;
	u_int len;

	tmp = backup_state;
	backup_state = ssh;
	ssh = tmp;
	ssh->connection_in = backup_state->connection_in;
	backup_state->connection_in = -1;
	ssh->connection_out = backup_state->connection_out;
	backup_state->connection_out = -1;
	len = buffer_len(&backup_state->input);
	if (len > 0) {
		buf = buffer_ptr(&backup_state->input);
		buffer_append(&ssh->input, buf, len);
		buffer_clear(&backup_state->input);
		add_recv_bytes(len);
	}
}
