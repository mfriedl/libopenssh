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
	struct sshkey *key;
};

struct session_state;	/* private session data */

struct ssh {
	/* Session state */
	struct session_state *state;

	/* Authentication context */
	void *authctxt;

	/* Key exchange */
	Kex *kex;
	Newkeys *current_keys[MODE_MAX];

	/* Host key verification */
	char *host;
	struct sockaddr *hostaddr;

	/* cached remote ip address */
	char *remote_ipaddr;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	int skip_packets;

	/* datafellows */
	int compat;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;
};

struct ssh *ssh_alloc_session_state(void);
struct ssh *ssh_packet_set_connection(struct ssh *, int, int);
void     ssh_packet_set_timeout(struct ssh *, int, int);
int	 ssh_packet_stop_discard(struct ssh *);
int	 ssh_packet_start_discard(struct ssh *, Enc*, Mac*, u_int, u_int);
int	ssh_packet_connection_af(struct ssh *);
void     ssh_packet_set_nonblocking(struct ssh *);
int      ssh_packet_get_connection_in(struct ssh *);
int      ssh_packet_get_connection_out(struct ssh *);
void     ssh_packet_close(struct ssh *);
void	 ssh_packet_set_encryption_key(struct ssh *, const u_char *, u_int, int);
void     ssh_packet_set_protocol_flags(struct ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(struct ssh *);
int      ssh_packet_start_compression(struct ssh *, int);
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
int	 ssh_packet_send1(struct ssh *);
int	 ssh_packet_send2_wrapped(struct ssh *);
int	 ssh_packet_send2(struct ssh *);

int      ssh_packet_read(struct ssh *);
void     ssh_packet_read_expect(struct ssh *, int type);
int      ssh_packet_read_poll(struct ssh *);
int ssh_packet_read_poll1(struct ssh *, u_char *);
int ssh_packet_read_poll2(struct ssh *, u_char *, u_int32_t *seqnr_p);
void     ssh_packet_process_incoming(struct ssh *, const char *buf, u_int len);
int      ssh_packet_read_seqnr(struct ssh *, u_char *, u_int32_t *seqnr_p);
int      ssh_packet_read_poll_seqnr(struct ssh *, u_char *, u_int32_t *seqnr_p);

u_int	 ssh_packet_get_char(struct ssh *);
u_int	 ssh_packet_get_int(struct ssh *);
u_int64_t ssh_packet_get_int64(struct ssh *);
void     ssh_packet_get_bignum(struct ssh *, BIGNUM * value);
void     ssh_packet_get_bignum2(struct ssh *, BIGNUM * value);
void	 ssh_packet_get_ecpoint(struct ssh *, const EC_GROUP *, EC_POINT *);
void	*ssh_packet_get_raw(struct ssh *, u_int *length_ptr);
void	*ssh_packet_get_string(struct ssh *, u_int *length_ptr);
char	*ssh_packet_get_cstring(struct ssh *, u_int *length_ptr);
const void *ssh_packet_get_string_ptr(struct ssh *, u_int *length_ptr);
void     ssh_packet_disconnect(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void     ssh_packet_send_debug(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

int	 ssh_set_newkeys(struct ssh *, int mode);
void	 ssh_packet_get_bytes(struct ssh *, u_int64_t *, u_int64_t *);

typedef void *(ssh_packet_comp_alloc_func)(void *, u_int, u_int);
typedef void (ssh_packet_comp_free_func)(void *, void *);
void	 ssh_packet_set_compress_hooks(struct ssh *, void *,
    ssh_packet_comp_alloc_func *, ssh_packet_comp_free_func *);

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

int	 ssh_packet_get_state(struct ssh *, struct sshbuf *);
int	 ssh_packet_set_state(struct ssh *, struct sshbuf *);

const char *ssh_remote_ipaddr(struct ssh *);

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

/* XXX FIXME */
void	 ssh_packet_backup_state(struct ssh *, struct ssh *);
void	 ssh_packet_restore_state(struct ssh *, struct ssh *);

void	*ssh_packet_get_input(struct ssh *);
void	*ssh_packet_get_output(struct ssh *);

/* old API */
extern struct ssh *active_state;
#ifndef PACKET_SKIP_COMPAT
u_int	 packet_get_char(void);
u_int	 packet_get_int(void);
void	 packet_backup_state(void);
void	 packet_restore_state(void);
void     packet_set_connection(int, int);
#define packet_set_timeout(timeout, count) \
	ssh_packet_set_timeout(active_state, (timeout), (count))
#define packet_connection_is_on_socket() \
	ssh_packet_connection_is_on_socket(active_state)
#define packet_set_nonblocking() \
	ssh_packet_set_nonblocking(active_state)
#define packet_get_connection_in() \
	ssh_packet_get_connection_in(active_state)
#define packet_get_connection_out() \
	ssh_packet_get_connection_out(active_state)
#define packet_close() \
	ssh_packet_close(active_state)
#define packet_set_protocol_flags(protocol_flags) \
	ssh_packet_set_protocol_flags(active_state, (protocol_flags))
#define packet_get_protocol_flags() \
	ssh_packet_get_protocol_flags(active_state)
#define packet_start_compression(level) \
	ssh_packet_start_compression(active_state, (level))
#define packet_set_encryption_key(key, keylen, number) \
	ssh_packet_set_encryption_key(active_state, (key), (keylen), (number))
#define packet_start(type) \
	ssh_packet_start(active_state, (type))
#define packet_put_char(value) \
	ssh_packet_put_char(active_state, (value))
#define packet_put_int(value) \
	ssh_packet_put_int(active_state, (value))
#define packet_put_int64(value) \
	ssh_packet_put_int64(active_state, (value))
#define packet_put_string( buf, len) \
	ssh_packet_put_string(active_state, (buf), (len))
#define packet_put_cstring(str) \
	ssh_packet_put_cstring(active_state, (str))
#define packet_put_raw(buf, len) \
	ssh_packet_put_raw(active_state, (buf), (len))
#define packet_put_bignum(value) \
	ssh_packet_put_bignum(active_state, (value))
#define packet_put_bignum2(value) \
	ssh_packet_put_bignum2(active_state, (value))
#define packet_send() \
	ssh_packet_send(active_state)
#define packet_read() \
	ssh_packet_read(active_state)
#define packet_read_expect(expected_type) \
	ssh_packet_read_expect(active_state, (expected_type))
#define packet_process_incoming(buf, len) \
	ssh_packet_process_incoming(active_state, (buf), (len))
#define packet_get_int64() \
	ssh_packet_get_int64(active_state)
#define packet_get_bignum(value) \
	ssh_packet_get_bignum(active_state, (value))
#define packet_get_bignum2(value) \
	ssh_packet_get_bignum2(active_state, (value))
#define packet_remaining() \
	ssh_packet_remaining(active_state)
#define packet_get_string(length_ptr) \
	ssh_packet_get_string(active_state, (length_ptr))
#define packet_get_string_ptr(length_ptr) \
	ssh_packet_get_string_ptr(active_state, (length_ptr))
#define packet_get_cstring(length_ptr) \
	ssh_packet_get_cstring(active_state, (length_ptr))
#define packet_send_debug(fmt, args...) \
	ssh_packet_send_debug(active_state, (fmt), ##args)
#define packet_disconnect(fmt, args...) \
	ssh_packet_disconnect(active_state, (fmt), ##args)
#define packet_write_poll() \
	ssh_packet_write_poll(active_state)
#define packet_write_wait() \
	ssh_packet_write_wait(active_state)
#define packet_have_data_to_write() \
	ssh_packet_have_data_to_write(active_state)
#define packet_not_very_much_data_to_write() \
	ssh_packet_not_very_much_data_to_write(active_state)
#define packet_set_interactive(interactive, qos_interactive, qos_bulk) \
	ssh_packet_set_interactive(active_state, (interactive), (qos_interactive), (qos_bulk))
#define packet_is_interactive() \
	ssh_packet_is_interactive(active_state)
#define packet_set_maxsize(s) \
	ssh_packet_set_maxsize(active_state, (s))
#define packet_inc_alive_timeouts() \
	ssh_packet_inc_alive_timeouts(active_state)
#define packet_set_alive_timeouts(ka) \
	ssh_packet_set_alive_timeouts(active_state, (ka))
#define packet_get_maxsize() \
	ssh_packet_get_maxsize(active_state)
#define packet_add_padding(pad) \
	ssh_packet_add_padding(active_state, (pad))
#define packet_send_ignore(nbytes) \
	ssh_packet_send_ignore(active_state, (nbytes))
#define packet_need_rekeying() \
	ssh_packet_need_rekeying(active_state)
#define packet_set_rekey_limit(bytes) \
	ssh_packet_set_rekey_limit(active_state, (bytes))
#define packet_set_server() \
	ssh_packet_set_server(active_state)
#define packet_set_authenticated() \
	ssh_packet_set_authenticated(active_state)
#define packet_get_input() \
	ssh_packet_get_input(active_state)
#define packet_get_output() \
	ssh_packet_get_output(active_state)
#define packet_set_compress_hooks(ctx, allocfunc, freefunc) \
	ssh_packet_set_compress_hooks(active_state, ctx, \
	    allocfunc, freefunc);
#define packet_check_eom() \
	ssh_packet_check_eom(active_state)
#define set_newkeys(mode) \
	ssh_set_newkeys(active_state, (mode))
#define packet_get_state(m) \
	ssh_packet_get_state(active_state, m)
#define packet_set_state(m) \
	ssh_packet_set_state(active_state, m)
#define get_remote_ipaddr() \
	ssh_remote_ipaddr(active_state)
#endif

/* new API */
int	sshpkt_start(struct ssh *ssh, u_char type);
int	sshpkt_send(struct ssh *ssh);
int     sshpkt_disconnect(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

int	sshpkt_put(struct ssh *ssh, const void *v, size_t len);
int	sshpkt_put_u8(struct ssh *ssh, u_char val);
int	sshpkt_put_u32(struct ssh *ssh, u_int32_t val);
int	sshpkt_put_u64(struct ssh *ssh, u_int64_t val);
int	sshpkt_put_string(struct ssh *ssh, const void *v, size_t len);
int	sshpkt_put_cstring(struct ssh *ssh, const void *v);
int	sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g);
int	sshpkt_put_bignum1(struct ssh *ssh, const BIGNUM *v);
int	sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v);

int	sshpkt_get_u8(struct ssh *ssh, u_char *valp);
int	sshpkt_get_u32(struct ssh *ssh, u_int32_t *valp);
int	sshpkt_get_u64(struct ssh *ssh, u_int64_t *valp);
int	sshpkt_get_string(struct ssh *ssh, u_char **valp, size_t *lenp);
int	sshpkt_get_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp);
int	sshpkt_get_cstring(struct ssh *ssh, char **valp, size_t *lenp);
int	sshpkt_get_ec(struct ssh *ssh, EC_POINT *v, const EC_GROUP *g);
int	sshpkt_get_bignum1(struct ssh *ssh, BIGNUM *v);
int	sshpkt_get_bignum2(struct ssh *ssh, BIGNUM *v);
int	sshpkt_get_end(struct ssh *ssh);

#endif				/* PACKET_H */
