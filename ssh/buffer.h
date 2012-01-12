/* $OpenBSD: buffer.h,v 1.21 2010/08/31 11:54:45 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for manipulating FIFO buffers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef BUFFER_H
#define BUFFER_H

#include "sshbuf.h"

typedef struct sshbuf Buffer;

#define buffer_init(b)		sshbuf_init(b)
#define buffer_clear(b)		sshbuf_reset(b)
#define buffer_free(b)		sshbuf_free(b)
#define buffer_dump(b)		sshbuf_dump(b, stderr)

/* XXX cast is safe: sshbuf never stores more than len 2^31 */
#define buffer_len(b)		((u_int) sshbuf_len(b))
#define	buffer_ptr(b)		sshbuf_ptr(b)

void	 buffer_append(Buffer *, const void *, u_int);
void	*buffer_append_space(Buffer *, u_int);
int	 buffer_check_alloc(Buffer *, u_int);
void	 buffer_get(Buffer *, void *, u_int);

void	 buffer_consume(Buffer *, u_int);
void	 buffer_consume_end(Buffer *, u_int);


int	 buffer_get_ret(Buffer *, void *, u_int);
int	 buffer_consume_ret(Buffer *, u_int);
int	 buffer_consume_end_ret(Buffer *, u_int);

#include <openssl/bn.h>

void    buffer_put_bignum(Buffer *, const BIGNUM *);
void    buffer_put_bignum2(Buffer *, const BIGNUM *);
void	buffer_get_bignum(Buffer *, BIGNUM *);
void	buffer_get_bignum2(Buffer *, BIGNUM *);

u_short	buffer_get_short(Buffer *);
void	buffer_put_short(Buffer *, u_short);

u_int	buffer_get_int(Buffer *);
void    buffer_put_int(Buffer *, u_int);

u_int64_t buffer_get_int64(Buffer *);
void	buffer_put_int64(Buffer *, u_int64_t);

int     buffer_get_char(Buffer *);
void    buffer_put_char(Buffer *, int);

void   *buffer_get_string(Buffer *, u_int *);
const void *buffer_get_string_ptr(Buffer *, u_int *);
void    buffer_put_string(Buffer *, const void *, u_int);
char   *buffer_get_cstring(Buffer *, u_int *);
void	buffer_put_cstring(Buffer *, const char *);

#define buffer_skip_string(b) (void)buffer_get_string_ptr(b, NULL);

int	buffer_put_bignum_ret(Buffer *, const BIGNUM *);
int	buffer_get_bignum_ret(Buffer *, BIGNUM *);
int	buffer_put_bignum2_ret(Buffer *, const BIGNUM *);
int	buffer_get_bignum2_ret(Buffer *, BIGNUM *);
int	buffer_get_short_ret(u_short *, Buffer *);
int	buffer_get_int_ret(u_int *, Buffer *);
int	buffer_get_int64_ret(u_int64_t *, Buffer *);
void	*buffer_get_string_ret(Buffer *, u_int *);
char	*buffer_get_cstring_ret(Buffer *, u_int *);
const void *buffer_get_string_ptr_ret(Buffer *, u_int *);
int	buffer_get_char_ret(char *, Buffer *);

#include <openssl/ec.h>

int	buffer_put_ecpoint_ret(Buffer *, const EC_GROUP *, const EC_POINT *);
void	buffer_put_ecpoint(Buffer *, const EC_GROUP *, const EC_POINT *);
int	buffer_get_ecpoint_ret(Buffer *, const EC_GROUP *, EC_POINT *);
void	buffer_get_ecpoint(Buffer *, const EC_GROUP *, EC_POINT *);

#endif				/* BUFFER_H */
