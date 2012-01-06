/* $OpenBSD: packet.h,v 1.56 2011/05/06 21:14:05 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Interface for the packet protocol functions.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef PACKET_H
#define PACKET_H

#include <termios.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <sys/signal.h>
#include <sys/queue.h>

/* XXX fixme */
#include "buffer.h"
#include "cipher.h"
#include "dispatch.h"
#include "key.h"
#include "kex.h"
#include "ssh.h"

struct key_entry {
	TAILQ_ENTRY(key_entry) next;
	Key *key;
};

struct session_state;	/* private session data */

struct ssh {
	/* Session state */
	struct session_state *state;

	/* Key exchange */
	Kex *kex;
	Newkeys *current_keys[MODE_MAX];

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];

	/* datafellows */
	int datafellows;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;
};

struct ssh *ssh_alloc_session_state(void);
struct ssh *ssh_packet_set_connection(struct ssh *, int, int);
void     ssh_packet_set_timeout(struct ssh *, int, int);
void	 ssh_packet_stop_discard(struct ssh *);
void	 ssh_packet_start_discard(struct ssh *, Enc*, Mac*, u_int, u_int);
int	ssh_packet_connection_af(struct ssh *);
void     ssh_packet_set_nonblocking(struct ssh *);
int      ssh_packet_get_connection_in(struct ssh *);
int      ssh_packet_get_connection_out(struct ssh *);
void     ssh_packet_close(struct ssh *);
void	 ssh_packet_set_encryption_key(struct ssh *, const u_char *, u_int, int);
u_int	 ssh_packet_get_encryption_key(struct ssh *, u_char *);
void     ssh_packet_set_protocol_flags(struct ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(struct ssh *);
void ssh_packet_init_compression(struct ssh *);
void     ssh_packet_start_compression(struct ssh *, int);
void	 ssh_packet_set_tos(struct ssh *, int);
void     ssh_packet_set_interactive(struct ssh *, int, int, int);
int      ssh_packet_is_interactive(struct ssh *);
void     ssh_packet_set_server(struct ssh *);
void     ssh_packet_set_authenticated(struct ssh *);

void     ssh_packet_start(struct ssh *, u_char);
void     ssh_packet_put_char(struct ssh *, int ch);
void     ssh_packet_put_int(struct ssh *, u_int value);
void     ssh_packet_put_int64(struct ssh *, u_int64_t value);
void     ssh_packet_put_bignum(struct ssh *, BIGNUM * value);
void     ssh_packet_put_bignum2(struct ssh *, BIGNUM * value);
void     ssh_packet_put_ecpoint(struct ssh *, const EC_GROUP *, const EC_POINT *);
void     ssh_packet_put_string(struct ssh *, const void *buf, u_int len);
void     ssh_packet_put_cstring(struct ssh *, const char *str);
void     ssh_packet_put_raw(struct ssh *, const void *buf, u_int len);
void     ssh_packet_send(struct ssh *);
void     ssh_packet_send1(struct ssh *);
void	ssh_packet_send2_wrapped(struct ssh *);
void     ssh_packet_send2(struct ssh *);
void	ssh_packet_enable_delayed_compress(struct ssh *);

int      ssh_packet_read(struct ssh *);
void     ssh_packet_read_expect(struct ssh *, int type);
int      ssh_packet_read_poll(struct ssh *);
int ssh_packet_read_poll1(struct ssh *);
int ssh_packet_read_poll2(struct ssh *, u_int32_t *seqnr_p);
void     ssh_packet_process_incoming(struct ssh *, const char *buf, u_int len);
int      ssh_packet_read_seqnr(struct ssh *, u_int32_t *seqnr_p);
int      ssh_packet_read_poll_seqnr(struct ssh *, u_int32_t *seqnr_p);

u_int	 ssh_packet_get_char(struct ssh *);
u_int	 ssh_packet_get_int(struct ssh *);
u_int64_t ssh_packet_get_int64(struct ssh *);
void     ssh_packet_get_bignum(struct ssh *, BIGNUM * value);
void     ssh_packet_get_bignum2(struct ssh *, BIGNUM * value);
void	 ssh_packet_get_ecpoint(struct ssh *, const EC_GROUP *, EC_POINT *);
void	*ssh_packet_get_raw(struct ssh *, u_int *length_ptr);
void	*ssh_packet_get_string(struct ssh *, u_int *length_ptr);
char	*ssh_packet_get_cstring(struct ssh *, u_int *length_ptr);
void	*ssh_packet_get_string_ptr(struct ssh *, u_int *length_ptr);
void     ssh_packet_disconnect(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void     ssh_packet_send_debug(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

void	 ssh_set_newkeys(struct ssh *, int mode);
int	 ssh_packet_get_keyiv_len(struct ssh *, int);
void	 ssh_packet_get_keyiv(struct ssh *, int, u_char *, u_int);
int	 ssh_packet_get_keycontext(struct ssh *, int, u_char *);
void	 ssh_packet_set_keycontext(struct ssh *, int, u_char *);
void	 ssh_packet_get_state(struct ssh *, int, u_int32_t *, u_int64_t *, u_int32_t *, u_int64_t *);
void	 ssh_packet_set_state(struct ssh *, int, u_int32_t, u_int64_t, u_int32_t, u_int64_t);
int	 ssh_packet_get_ssh1_cipher(struct ssh *);
void	 ssh_packet_set_iv(struct ssh *, int, u_char *);
void	*ssh_packet_get_newkeys(struct ssh *, int);

void     ssh_packet_write_poll(struct ssh *);
void     ssh_packet_write_wait(struct ssh *);
int      ssh_packet_have_data_to_write(struct ssh *);
int      ssh_packet_not_very_much_data_to_write(struct ssh *);

int	 ssh_packet_connection_is_on_socket(struct ssh *);
int	 ssh_packet_remaining(struct ssh *);
void	 ssh_packet_send_ignore(struct ssh *, int);
void	 ssh_packet_add_padding(struct ssh *, u_char);

void	 tty_make_modes(int, struct termios *);
void	 tty_parse_modes(int, int *);

void	 ssh_packet_set_alive_timeouts(struct ssh *, int);
int	 ssh_packet_inc_alive_timeouts(struct ssh *);
int	 ssh_packet_set_maxsize(struct ssh *, u_int);
u_int	 ssh_packet_get_maxsize(struct ssh *);

/* don't allow remaining bytes after the end of the message */
#define ssh_packet_check_eom(active_state) \
do { \
	int _len = ssh_packet_remaining(active_state); \
	if (_len > 0) { \
		logit("Packet integrity error (%d bytes remaining) at %s:%d", \
		    _len ,__FILE__, __LINE__); \
		ssh_packet_disconnect(active_state, \
		    "Packet integrity error."); \
	} \
} while (0)

int	 ssh_packet_need_rekeying(struct ssh *);
void	 ssh_packet_set_rekey_limit(struct ssh *, u_int32_t);

/* TODO Hier brauchen wir noch eine Loesung! */
void	 ssh_packet_backup_state(struct ssh *, struct ssh *);
void	 ssh_packet_restore_state(struct ssh *, struct ssh *);

void	*ssh_packet_get_input(struct ssh *);
void	*ssh_packet_get_output(struct ssh *);

/* old API */
void     packet_set_connection(int, int);
void     packet_set_timeout(int, int);
void     packet_set_nonblocking(void);
int      packet_get_connection_in(void);
int      packet_get_connection_out(void);
void     packet_close(void);
void	 packet_set_encryption_key(const u_char *, u_int, int);
u_int	 packet_get_encryption_key(u_char *);
void     packet_set_protocol_flags(u_int);
u_int	 packet_get_protocol_flags(void);
void     packet_start_compression(int);
void     packet_set_interactive(int, int, int);
int      packet_is_interactive(void);
void     packet_set_server(void);
void     packet_set_authenticated(void);

void     packet_start(u_char);
void     packet_put_char(int ch);
void     packet_put_int(u_int value);
void     packet_put_int64(u_int64_t value);
void     packet_put_bignum(BIGNUM * value);
void     packet_put_bignum2(BIGNUM * value);
void     packet_put_ecpoint(const EC_GROUP *, const EC_POINT *);
void     packet_put_string(const void *buf, u_int len);
void     packet_put_cstring(const char *str);
void     packet_put_raw(const void *buf, u_int len);
void     packet_send(void);

int      packet_read(void);
void     packet_read_expect(int type);
int      packet_read_poll(void);
void     packet_process_incoming(const char *buf, u_int len);
int      packet_read_seqnr(u_int32_t *seqnr_p);
int      packet_read_poll_seqnr(u_int32_t *seqnr_p);

u_int	 packet_get_char(void);
u_int	 packet_get_int(void);
u_int64_t packet_get_int64(void);
void     packet_get_bignum(BIGNUM * value);
void     packet_get_bignum2(BIGNUM * value);
void	 packet_get_ecpoint(const EC_GROUP *, EC_POINT *);
void	*packet_get_raw(u_int *length_ptr);
void	*packet_get_string(u_int *length_ptr);
char	*packet_get_cstring(u_int *length_ptr);
void	*packet_get_string_ptr(u_int *length_ptr);
void     packet_disconnect(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void     packet_send_debug(const char *fmt,...) __attribute__((format(printf, 1, 2)));

void	 set_newkeys(int mode);
int	 packet_get_keyiv_len(int);
void	 packet_get_keyiv(int, u_char *, u_int);
int	 packet_get_keycontext(int, u_char *);
void	 packet_set_keycontext(int, u_char *);
void	 packet_get_state(int, u_int32_t *, u_int64_t *, u_int32_t *, u_int64_t *);
void	 packet_set_state(int, u_int32_t, u_int64_t, u_int32_t, u_int64_t);
int	 packet_get_ssh1_cipher(void);
void	 packet_set_iv(int, u_char *);
void	*packet_get_newkeys(int);

void     packet_write_poll(void);
void     packet_write_wait(void);
int      packet_have_data_to_write(void);
int      packet_not_very_much_data_to_write(void);

int	 packet_connection_is_on_socket(void);
int	 packet_remaining(void);
void	 packet_send_ignore(int);
void	 packet_add_padding(u_char);

void	 tty_make_modes(int, struct termios *);
void	 tty_parse_modes(int, int *);

void	 packet_set_alive_timeouts(int);
int	 packet_inc_alive_timeouts(void);
int	 packet_set_maxsize(u_int);
u_int	 packet_get_maxsize(void);

/* don't allow remaining bytes after the end of the message */
#define packet_check_eom() \
do { \
	int _len = packet_remaining(); \
	if (_len > 0) { \
		logit("Packet integrity error (%d bytes remaining) at %s:%d", \
		    _len ,__FILE__, __LINE__); \
		packet_disconnect("Packet integrity error."); \
	} \
} while (0)

int	 packet_need_rekeying(void);
void	 packet_set_rekey_limit(u_int32_t);

void	 packet_backup_state(void);
void	 packet_restore_state(void);

void	*packet_get_input(void);
void	*packet_get_output(void);

#endif				/* PACKET_H */
