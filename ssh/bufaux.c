/* $OpenBSD: bufaux.c,v 1.50 2010/08/31 09:58:37 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Auxiliary functions for storing and retrieving various data types to/from
 * Buffers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl
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

#include <openssl/bn.h>

#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"
#include "err.h"

/*
 * Returns integers from the buffer (msb first).
 */

int
buffer_get_short_ret(u_short *v, Buffer *buffer)
{
	int ret;

	if ((ret = sshbuf_get_u16(buffer, v)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

u_short
buffer_get_short(Buffer *buffer)
{
	u_short ret;

	if (buffer_get_short_ret(&ret, buffer) == -1)
		fatal("buffer_get_short: buffer error");

	return (ret);
}

int
buffer_get_int_ret(u_int *v, Buffer *buffer)
{
	int ret;

	if ((ret = sshbuf_get_u32(buffer, v)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

u_int
buffer_get_int(Buffer *buffer)
{
	u_int ret;

	if (buffer_get_int_ret(&ret, buffer) == -1)
		fatal("buffer_get_int: buffer error");

	return (ret);
}

int
buffer_get_int64_ret(u_int64_t *v, Buffer *buffer)
{
	int ret;

	if ((ret = sshbuf_get_u64(buffer, v)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

u_int64_t
buffer_get_int64(Buffer *buffer)
{
	u_int64_t ret;

	if (buffer_get_int64_ret(&ret, buffer) == -1)
		fatal("buffer_get_int: buffer error");

	return (ret);
}

/*
 * Stores integers in the buffer, msb first.
 */
void
buffer_put_short(Buffer *buffer, u_short value)
{
	int ret;

	if ((ret = sshbuf_put_u16(buffer, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_put_int(Buffer *buffer, u_int value)
{
	int ret;

	if ((ret = sshbuf_put_u32(buffer, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_put_int64(Buffer *buffer, u_int64_t value)
{
	int ret;

	if ((ret = sshbuf_put_u64(buffer, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

/*
 * Returns an arbitrary binary string from the buffer.  The string cannot
 * be longer than 256k.  The returned value points to memory allocated
 * with xmalloc; it is the responsibility of the calling function to free
 * the data.  If length_ptr is non-NULL, the length of the returned data
 * will be stored there.  A null character will be automatically appended
 * to the returned string, and is not counted in length.
 */
void *
buffer_get_string_ret(Buffer *buffer, u_int *length_ptr)
{
	size_t len;
	int ret;
	u_char *value;

	if ((ret = sshbuf_get_string(buffer, &value, &len)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return NULL;
	}
	if (length_ptr != NULL)
		*length_ptr = len;  /* Safe: sshbuf never store len > 2^31 */
	return value;
}

void *
buffer_get_string(Buffer *buffer, u_int *length_ptr)
{
	void *ret;

	if ((ret = buffer_get_string_ret(buffer, length_ptr)) == NULL)
		fatal("buffer_get_string: buffer error");
	return (ret);
}

char *
buffer_get_cstring_ret(Buffer *buffer, u_int *length_ptr)
{
	size_t len;
	int ret;
	char *value;

	if ((ret = sshbuf_get_cstring(buffer, &value, &len)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return NULL;
	}
	if (length_ptr != NULL)
		*length_ptr = len;  /* Safe: sshbuf never store len > 2^31 */
	return value;
}

char *
buffer_get_cstring(Buffer *buffer, u_int *length_ptr)
{
	char *ret;

	if ((ret = buffer_get_cstring_ret(buffer, length_ptr)) == NULL)
		fatal("buffer_get_cstring: buffer error");
	return ret;
}

const void *
buffer_get_string_ptr_ret(Buffer *buffer, u_int *length_ptr)
{
	size_t len;
	int ret;
	const u_char *value;

	if ((ret = sshbuf_get_string_direct(buffer, &value, &len)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return NULL;
	}
	if (length_ptr != NULL)
		*length_ptr = len;  /* Safe: sshbuf never store len > 2^31 */
	return value;
}

const void *
buffer_get_string_ptr(Buffer *buffer, u_int *length_ptr)
{
	const void *ret;

	if ((ret = buffer_get_string_ptr_ret(buffer, length_ptr)) == NULL)
		fatal("buffer_get_string_ptr: buffer error");
	return (ret);
}

/*
 * Stores and arbitrary binary string in the buffer.
 */
void
buffer_put_string(Buffer *buffer, const void *buf, u_int len)
{
	int ret;

	if ((ret = sshbuf_put_string(buffer, buf, len)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_put_cstring(Buffer *buffer, const char *s)
{
	int ret;

	if ((ret = sshbuf_put_cstring(buffer, s)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

/*
 * Returns a character from the buffer (0 - 255).
 */
int
buffer_get_char_ret(char *v, Buffer *buffer)
{
	int ret;

	if ((ret = sshbuf_get_u8(buffer, (u_char *)v)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

int
buffer_get_char(Buffer *buffer)
{
	char ch;

	if (buffer_get_char_ret(&ch, buffer) == -1)
		fatal("buffer_get_char: buffer error");
	return (u_char) ch;
}

/*
 * Stores a character in the buffer.
 */
void
buffer_put_char(Buffer *buffer, int value)
{
	int ret;

	if ((ret = sshbuf_put_u8(buffer, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}
