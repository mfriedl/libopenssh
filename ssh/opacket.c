/* $OpenBSD: packet.c,v 1.173 2011/05/06 21:14:05 djm Exp $ */
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
#include "packet.h"
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
#include "roaming.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

struct ssh *active_state, *backup_state;

/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
void
packet_set_connection(int fd_in, int fd_out)
{
	active_state = ssh_packet_set_connection(active_state, fd_in, fd_out);
}

void
packet_set_timeout(int timeout, int count)
{
	ssh_packet_set_timeout(active_state, timeout, count);
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

int
packet_connection_is_on_socket(void)
{
	return ssh_packet_connection_is_on_socket(active_state);
}

/*
 * Exports an IV from the CipherContext required to export the key
 * state back from the unprivileged child to the privileged parent
 * process.
 */

void
packet_get_keyiv(int mode, u_char *iv, u_int len)
{
	ssh_packet_get_keyiv(active_state, mode, iv, len);
}

int
packet_get_keycontext(int mode, u_char *dat)
{
	return ssh_packet_get_keycontext(active_state, mode, dat);
}

void
packet_set_keycontext(int mode, u_char *dat)
{
	ssh_packet_set_keycontext(active_state, mode, dat);
}

int
packet_get_keyiv_len(int mode)
{
	return ssh_packet_get_keyiv_len(active_state, mode);
}

void
packet_set_iv(int mode, u_char *dat)
{
	ssh_packet_set_iv(active_state, mode, dat);
}

int
packet_get_ssh1_cipher(void)
{
	return ssh_packet_get_ssh1_cipher(active_state);
}

void
packet_get_state(int mode, u_int32_t *seqnr, u_int64_t *blocks,
    u_int32_t *packets, u_int64_t *bytes)
{
	ssh_packet_get_state(active_state, mode, seqnr, blocks, packets, bytes);
}

void
packet_set_state(int mode, u_int32_t seqnr, u_int64_t blocks, u_int32_t packets,
    u_int64_t bytes)
{
	ssh_packet_set_state(active_state, mode, seqnr, blocks, packets, bytes);
}

/* Sets the connection into non-blocking mode. */

void
packet_set_nonblocking(void)
{
	ssh_packet_set_nonblocking(active_state);
}

/* Returns the socket used for reading. */

int
packet_get_connection_in(void)
{
	return ssh_packet_get_connection_in(active_state);
}

/* Returns the descriptor used for writing. */

int
packet_get_connection_out(void)
{
	return ssh_packet_get_connection_out(active_state);
}

/* Closes the connection and clears and frees internal data structures. */

void
packet_close(void)
{
	ssh_packet_close(active_state);
}

/* Sets remote side protocol flags. */

void
packet_set_protocol_flags(u_int protocol_flags)
{
	ssh_packet_set_protocol_flags(active_state, protocol_flags);
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
packet_get_protocol_flags(void)
{
	return ssh_packet_get_protocol_flags(active_state);
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

void
packet_start_compression(int level)
{
	ssh_packet_start_compression(active_state, level);
}

/*
 * Causes any further packets to be encrypted using the given key.  The same
 * key is used for both sending and reception.  However, both directions are
 * encrypted independently of each other.
 */

void
packet_set_encryption_key(const u_char *key, u_int keylen, int number)
{
	ssh_packet_set_encryption_key(active_state, key, keylen, number);
}

u_int
packet_get_encryption_key(u_char *key)
{
	return ssh_packet_get_encryption_key(active_state, key);
}

/* Start constructing a packet to send. */
void
packet_start(u_char type)
{
	ssh_packet_start(active_state, type);
}

/* Append payload. */
void
packet_put_char(int value)
{
	ssh_packet_put_char(active_state, value);
}

void
packet_put_int(u_int value)
{
	ssh_packet_put_int(active_state, value);
}

void
packet_put_int64(u_int64_t value)
{
	ssh_packet_put_int64(active_state, value);
}

void
packet_put_string(const void *buf, u_int len)
{
	ssh_packet_put_string(active_state, buf, len);
}

void
packet_put_cstring(const char *str)
{
	ssh_packet_put_cstring(active_state, str);
}

void
packet_put_raw(const void *buf, u_int len)
{
	ssh_packet_put_raw(active_state, buf, len);
}

void
packet_put_bignum(BIGNUM * value)
{
	ssh_packet_put_bignum(active_state, value);
}

void
packet_put_bignum2(BIGNUM * value)
{
	ssh_packet_put_bignum2(active_state, value);
}

void
packet_put_ecpoint(const EC_GROUP *curve, const EC_POINT *point)
{
	ssh_packet_put_ecpoint(active_state, curve, point);
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

void
set_newkeys(int mode)
{
	ssh_set_newkeys(active_state, mode);
}

void
packet_send(void)
{
    ssh_packet_send(active_state);
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

int
packet_read_seqnr(u_int32_t *seqnr_p)
{
	return ssh_packet_read_seqnr(active_state, seqnr_p);
}

int
packet_read(void)
{
	return ssh_packet_read(active_state);
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
packet_read_expect(int expected_type)
{
	ssh_packet_read_expect(active_state, expected_type);
}

int
packet_read_poll_seqnr(u_int32_t *seqnr_p)
{
	return ssh_packet_read_poll_seqnr(active_state, seqnr_p);
}

int
packet_read_poll(void)
{
	return ssh_packet_read_poll(active_state);
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
packet_process_incoming(const char *buf, u_int len)
{
	ssh_packet_process_incoming(active_state, buf, len);
}

/* Returns a character from the packet. */

u_int
packet_get_char(void)
{
	return ssh_packet_get_char(active_state);
}

/* Returns an integer from the packet data. */

u_int
packet_get_int(void)
{
	return ssh_packet_get_int(active_state);
}

/* Returns an 64 bit integer from the packet data. */

u_int64_t
packet_get_int64(void)
{
	return ssh_packet_get_int64(active_state);
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
packet_get_bignum(BIGNUM * value)
{
	ssh_packet_get_bignum(active_state, value);
}

void
packet_get_bignum2(BIGNUM * value)
{
	ssh_packet_get_bignum2(active_state, value);
}

void
packet_get_ecpoint(const EC_GROUP *curve, EC_POINT *point)
{
	ssh_packet_get_ecpoint(active_state, curve, point);
}

void *
packet_get_raw(u_int *length_ptr)
{
	return ssh_packet_get_raw(active_state, length_ptr);
}

int
packet_remaining(void)
{
	return ssh_packet_remaining(active_state);
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
packet_get_string(u_int *length_ptr)
{
	return ssh_packet_get_string(active_state, length_ptr);
}

void *
packet_get_string_ptr(u_int *length_ptr)
{
	return ssh_packet_get_string_ptr(active_state, length_ptr);
}

/* Ensures the returned string has no embedded \0 characters in it. */
char *
packet_get_cstring(u_int *length_ptr)
{
	return ssh_packet_get_cstring(active_state, length_ptr);
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
packet_send_debug(const char *fmt,...)
{
	/* TODO Call: ssh_packet_send_debug(active_state, fmt, ...); */
	char buf[1024];
	va_list args;

	if (compat20 && (datafellows & SSH_BUG_DEBUG))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (compat20) {
		ssh_packet_start(active_state, SSH2_MSG_DEBUG);
		ssh_packet_put_char(active_state, 0); /* bool: always display */
		ssh_packet_put_cstring(active_state, buf);
		ssh_packet_put_cstring(active_state, "");
	} else {
		ssh_packet_start(active_state, SSH_MSG_DEBUG);
		ssh_packet_put_cstring(active_state, buf);
	}
	ssh_packet_send(active_state);
	ssh_packet_write_wait(active_state);
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */

void
packet_disconnect(const char *fmt,...)
{
	/* TODO Call: ssh_packet_disconnect(active_state, fmt, ...); */
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
		ssh_packet_start(active_state, SSH2_MSG_DISCONNECT);
		ssh_packet_put_int(active_state, SSH2_DISCONNECT_PROTOCOL_ERROR);
		ssh_packet_put_cstring(active_state, buf);
		ssh_packet_put_cstring(active_state, "");
	} else {
		ssh_packet_start(active_state, SSH_MSG_DISCONNECT);
		ssh_packet_put_cstring(active_state, buf);
	}
	ssh_packet_send(active_state);
	ssh_packet_write_wait(active_state);

	/* Stop listening for connections. */
	channel_close_all();

	/* Close the connection. */
	ssh_packet_close(active_state);
	cleanup_exit(255);
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void
packet_write_poll(void)
{
	ssh_packet_write_poll(active_state);
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */

void
packet_write_wait(void)
{
	ssh_packet_write_wait(active_state);
}

/* Returns true if there is buffered data to write to the connection. */

int
packet_have_data_to_write(void)
{
	return ssh_packet_have_data_to_write(active_state);
}

/* Returns true if there is not too much data to write to the connection. */

int
packet_not_very_much_data_to_write(void)
{
	return ssh_packet_not_very_much_data_to_write(active_state);
}

/* Informs that the current session is interactive.  Sets IP flags for that. */

void
packet_set_interactive(int interactive, int qos_interactive, int qos_bulk)
{
	ssh_packet_set_interactive(active_state, interactive, qos_interactive,
	    qos_bulk);
}

/* Returns true if the current connection is interactive. */

int
packet_is_interactive(void)
{
	return ssh_packet_is_interactive(active_state);
}

int
packet_set_maxsize(u_int s)
{
	return ssh_packet_set_maxsize(active_state, s);
}

int
packet_inc_alive_timeouts(void)
{
	return ssh_packet_inc_alive_timeouts(active_state);
}

void
packet_set_alive_timeouts(int ka)
{
	ssh_packet_set_alive_timeouts(active_state, ka);
}

u_int
packet_get_maxsize(void)
{
	return ssh_packet_get_maxsize(active_state);
}

/* roundup current message to pad bytes */
void
packet_add_padding(u_char pad)
{
	ssh_packet_add_padding(active_state, pad);
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
packet_send_ignore(int nbytes)
{
	ssh_packet_send_ignore(active_state, nbytes);
}

#define MAX_PACKETS	(1U<<31)
int
packet_need_rekeying(void)
{
	return ssh_packet_need_rekeying(active_state);
}

void
packet_set_rekey_limit(u_int32_t bytes)
{
	ssh_packet_set_rekey_limit(active_state, bytes);
}

void
packet_set_server(void)
{
	ssh_packet_set_server(active_state);
}

void
packet_set_authenticated(void)
{
	ssh_packet_set_authenticated(active_state);
}

void *
packet_get_input(void)
{
	return ssh_packet_get_input(active_state);
}

void *
packet_get_output(void)
{
	return ssh_packet_get_output(active_state);
}

void *
packet_get_newkeys(int mode)
{
	return ssh_packet_get_newkeys(active_state, mode);
}

/*
 * Save the state for the real connection, and use a separate state when
 * resuming a suspended connection.
 */
void
packet_backup_state(void)
{
	ssh_packet_backup_state(active_state, backup_state);
}

/*
 * Swap in the old state when resuming a connecion.
 */
void
packet_restore_state(void)
{
	ssh_packet_restore_state(active_state, backup_state);
}
