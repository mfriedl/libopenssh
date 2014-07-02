/* $OpenBSD: packet.h,v 1.61 2014/05/03 17:20:34 markus Exp $ */

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

<<<<<<< packet.h
/* XXX fixme */
#include "dispatch.h"
#include "ssh.h"

struct key_entry {
	TAILQ_ENTRY(key_entry) next;
	struct sshkey *key;
};

struct kex;
struct sshkey;
struct sshbuf;
struct session_state;	/* private session data */

struct ssh {
	/* Session state */
	struct session_state *state;

	/* Authentication context */
	void *authctxt;

	/* Application specific data */
	void *app_data;

	/* Key exchange */
	struct kex *kex;

	/* Host key verification */
	char *host;
	struct sockaddr *hostaddr;

	/* cached remote ip address and port*/
	char *remote_ipaddr;
	int remote_port;

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
int	 ssh_packet_connection_af(struct ssh *);
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

const void *ssh_packet_get_string_ptr(struct ssh *, u_int *length_ptr);
void     ssh_packet_disconnect(struct ssh *, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
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

void	 tty_make_modes(struct ssh *, int, struct termios *);
void	 tty_parse_modes(struct ssh *, int, int *);

void	 ssh_packet_set_alive_timeouts(struct ssh *, int);
int	 ssh_packet_inc_alive_timeouts(struct ssh *);
int	 ssh_packet_set_maxsize(struct ssh *, u_int);
u_int	 ssh_packet_get_maxsize(struct ssh *);

int	 ssh_packet_get_state(struct ssh *, struct sshbuf *);
int	 ssh_packet_set_state(struct ssh *, struct sshbuf *);

const char *ssh_remote_ipaddr(struct ssh *);

int	 ssh_packet_need_rekeying(struct ssh *);
void	 ssh_packet_set_rekey_limits(struct ssh *, u_int32_t, time_t);
time_t	 ssh_packet_get_rekey_timeout(struct ssh *);

/* XXX FIXME */
void	 ssh_packet_backup_state(struct ssh *, struct ssh *);
void	 ssh_packet_restore_state(struct ssh *, struct ssh *);

void	*ssh_packet_get_input(struct ssh *);
void	*ssh_packet_get_output(struct ssh *);

/* old API */
extern struct ssh *active_state;

/* new API */
int	sshpkt_start(struct ssh *ssh, u_char type);
int	sshpkt_send(struct ssh *ssh);
int     sshpkt_disconnect(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int	sshpkt_add_padding(struct ssh *, u_char);

int	sshpkt_put(struct ssh *ssh, const void *v, size_t len);
int	sshpkt_putb(struct ssh *ssh, const struct sshbuf *b);
int	sshpkt_put_u8(struct ssh *ssh, u_char val);
int	sshpkt_put_u32(struct ssh *ssh, u_int32_t val);
int	sshpkt_put_u64(struct ssh *ssh, u_int64_t val);
int	sshpkt_put_string(struct ssh *ssh, const void *v, size_t len);
int	sshpkt_put_cstring(struct ssh *ssh, const void *v);
int	sshpkt_put_stringb(struct ssh *ssh, const struct sshbuf *v);
int	sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g);
int	sshpkt_put_bignum1(struct ssh *ssh, const BIGNUM *v);
int	sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v);

int	sshpkt_get(struct ssh *ssh, void *valp, size_t len);
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
const u_char	*sshpkt_ptr(struct ssh *, size_t *lenp);
=======
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
const void	*packet_get_string_ptr(u_int *length_ptr);
void     packet_disconnect(const char *fmt,...) __attribute__((noreturn)) __attribute__((format(printf, 1, 2)));
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
void	 packet_set_rekey_limits(u_int32_t, time_t);
time_t	 packet_get_rekey_timeout(void);

void	 packet_backup_state(void);
void	 packet_restore_state(void);
void	 packet_set_postauth(void);

void	*packet_get_input(void);
void	*packet_get_output(void);
>>>>>>> 1.61

#endif				/* PACKET_H */
