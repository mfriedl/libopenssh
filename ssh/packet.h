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

struct key_entry {
	TAILQ_ENTRY(key_entry) next;
	Key *key;
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
	Newkeys *current_keys[MODE_MAX];
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

	/* Session information for key exchange */
	Kex *kex;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];

	/* datafellows */
	int datafellows;

	TAILQ_HEAD(, packet) outgoing;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;
};

struct session_state* ssh_alloc_session_state(void);
struct session_state* ssh_packet_set_connection(struct session_state*, int, int);
void     ssh_packet_set_timeout(struct session_state*, int, int);
void	 ssh_packet_stop_discard(struct session_state*);
void	 ssh_packet_start_discard(struct session_state*, Enc*, Mac*, u_int, u_int);
int	ssh_packet_connection_af(struct session_state*);
void     ssh_packet_set_nonblocking(struct session_state*);
int      ssh_packet_get_connection_in(struct session_state*);
int      ssh_packet_get_connection_out(struct session_state*);
void     ssh_packet_close(struct session_state*);
void	 ssh_packet_set_encryption_key(struct session_state*, const u_char *, u_int, int);
u_int	 ssh_packet_get_encryption_key(struct session_state*, u_char *);
void     ssh_packet_set_protocol_flags(struct session_state*, u_int);
u_int	 ssh_packet_get_protocol_flags(struct session_state*);
void ssh_packet_init_compression(struct session_state*);
void     ssh_packet_start_compression(struct session_state*, int);
void	 ssh_packet_set_tos(struct session_state*, int);
void     ssh_packet_set_interactive(struct session_state*, int, int, int);
int      ssh_packet_is_interactive(struct session_state*);
void     ssh_packet_set_server(struct session_state*);
void     ssh_packet_set_authenticated(struct session_state*);

void     ssh_packet_start(struct session_state*, u_char);
void     ssh_packet_put_char(struct session_state*, int ch);
void     ssh_packet_put_int(struct session_state*, u_int value);
void     ssh_packet_put_int64(struct session_state*, u_int64_t value);
void     ssh_packet_put_bignum(struct session_state*, BIGNUM * value);
void     ssh_packet_put_bignum2(struct session_state*, BIGNUM * value);
void     ssh_packet_put_ecpoint(struct session_state*, const EC_GROUP *, const EC_POINT *);
void     ssh_packet_put_string(struct session_state*, const void *buf, u_int len);
void     ssh_packet_put_cstring(struct session_state*, const char *str);
void     ssh_packet_put_raw(struct session_state*, const void *buf, u_int len);
void     ssh_packet_send(struct session_state*);
void     ssh_packet_send1(struct session_state*);
void	ssh_packet_send2_wrapped(struct session_state*);
void     ssh_packet_send2(struct session_state*);
void	ssh_packet_enable_delayed_compress(struct session_state*);

int      ssh_packet_read(struct session_state*);
void     ssh_packet_read_expect(struct session_state*, int type);
int      ssh_packet_read_poll(struct session_state*);
int ssh_packet_read_poll1(struct session_state*);
int ssh_packet_read_poll2(struct session_state*, u_int32_t *seqnr_p);
void     ssh_packet_process_incoming(struct session_state*, const char *buf, u_int len);
int      ssh_packet_read_seqnr(struct session_state*, u_int32_t *seqnr_p);
int      ssh_packet_read_poll_seqnr(struct session_state*, u_int32_t *seqnr_p);

u_int	 ssh_packet_get_char(struct session_state*);
u_int	 ssh_packet_get_int(struct session_state*);
u_int64_t ssh_packet_get_int64(struct session_state*);
void     ssh_packet_get_bignum(struct session_state*, BIGNUM * value);
void     ssh_packet_get_bignum2(struct session_state*, BIGNUM * value);
void	 ssh_packet_get_ecpoint(struct session_state*, const EC_GROUP *, EC_POINT *);
void	*ssh_packet_get_raw(struct session_state*, u_int *length_ptr);
void	*ssh_packet_get_string(struct session_state*, u_int *length_ptr);
char	*ssh_packet_get_cstring(struct session_state*, u_int *length_ptr);
void	*ssh_packet_get_string_ptr(struct session_state*, u_int *length_ptr);
void     ssh_packet_disconnect(struct session_state*, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void     ssh_packet_send_debug(struct session_state*, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

void	 ssh_set_newkeys(struct session_state*, int mode);
int	 ssh_packet_get_keyiv_len(struct session_state*, int);
void	 ssh_packet_get_keyiv(struct session_state*, int, u_char *, u_int);
int	 ssh_packet_get_keycontext(struct session_state*, int, u_char *);
void	 ssh_packet_set_keycontext(struct session_state*, int, u_char *);
void	 ssh_packet_get_state(struct session_state*, int, u_int32_t *, u_int64_t *, u_int32_t *, u_int64_t *);
void	 ssh_packet_set_state(struct session_state*, int, u_int32_t, u_int64_t, u_int32_t, u_int64_t);
int	 ssh_packet_get_ssh1_cipher(struct session_state*);
void	 ssh_packet_set_iv(struct session_state*, int, u_char *);
void	*ssh_packet_get_newkeys(struct session_state*, int);

void     ssh_packet_write_poll(struct session_state*);
void     ssh_packet_write_wait(struct session_state*);
int      ssh_packet_have_data_to_write(struct session_state*);
int      ssh_packet_not_very_much_data_to_write(struct session_state*);

int	 ssh_packet_connection_is_on_socket(struct session_state*);
int	 ssh_packet_remaining(struct session_state*);
void	 ssh_packet_send_ignore(struct session_state*, int);
void	 ssh_packet_add_padding(struct session_state*, u_char);

void	 tty_make_modes(int, struct termios *);
void	 tty_parse_modes(int, int *);

void	 ssh_packet_set_alive_timeouts(struct session_state*, int);
int	 ssh_packet_inc_alive_timeouts(struct session_state*);
int	 ssh_packet_set_maxsize(struct session_state*, u_int);
u_int	 ssh_packet_get_maxsize(struct session_state*);

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

int	 ssh_packet_need_rekeying(struct session_state*);
void	 ssh_packet_set_rekey_limit(struct session_state*, u_int32_t);

/* TODO Hier brauchen wir noch eine Loesung! */
void	 ssh_packet_backup_state(struct session_state*, struct session_state*);
void	 ssh_packet_restore_state(struct session_state*, struct session_state*);

void	*ssh_packet_get_input(struct session_state*);
void	*ssh_packet_get_output(struct session_state*);

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
