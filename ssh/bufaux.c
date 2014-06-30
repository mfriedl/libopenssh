<<<<<<< bufaux.c
<<<<<<< bufaux.c
<<<<<<< bufaux.c
<<<<<<< bufaux.c
<<<<<<< bufaux.c
/* $OpenBSD: bufaux.c,v 1.51 2013/05/17 00:13:13 djm Exp $ */
=======
/* $OpenBSD: bufaux.c,v 1.60 2014/04/30 05:29:56 djm Exp $ */
>>>>>>> 1.60
=======
/* $OpenBSD: bufaux.c,v 1.56 2014/02/02 03:44:31 djm Exp $ */
>>>>>>> 1.56
=======
/* $OpenBSD: bufaux.c,v 1.53 2013/11/08 11:15:19 dtucker Exp $ */
>>>>>>> 1.53
=======
/* $OpenBSD: bufaux.c,v 1.53 2013/11/08 11:15:19 dtucker Exp $ */
>>>>>>> 1.53
=======
/* $OpenBSD: bufaux.c,v 1.53 2013/11/08 11:15:19 dtucker Exp $ */
>>>>>>> 1.53
/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Emulation wrappers for legacy OpenSSH buffer API atop sshbuf */

#include <sys/types.h>

<<<<<<< bufaux.c
=======
#include <openssl/bn.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "xmalloc.h"
>>>>>>> 1.56
#include "buffer.h"
#include "log.h"
#include "ssherr.h"

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
		fatal("%s: buffer error", __func__);

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
		fatal("%s: buffer error", __func__);

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
		fatal("%s: buffer error", __func__);

	return (ret);
}

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
		*length_ptr = len;  /* Safe: sshbuf never stores len > 2^31 */
	return value;
}

void *
buffer_get_string(Buffer *buffer, u_int *length_ptr)
{
	void *ret;

	if ((ret = buffer_get_string_ret(buffer, length_ptr)) == NULL)
		fatal("%s: buffer error", __func__);
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
<<<<<<< bufaux.c
=======
	if ((cp = memchr(ret, '\0', length)) != NULL) {
		/* XXX allow \0 at end-of-string for a while, remove later */
		if (cp == ret + length - 1)
			error("buffer_get_cstring_ret: string contains \\0");
		else {
			explicit_bzero(ret, length);
			free(ret);
			return NULL;
		}
>>>>>>> 1.56
	}
	if (length_ptr != NULL)
		*length_ptr = len;  /* Safe: sshbuf never stores len > 2^31 */
	return value;
}

char *
buffer_get_cstring(Buffer *buffer, u_int *length_ptr)
{
	char *ret;

	if ((ret = buffer_get_cstring_ret(buffer, length_ptr)) == NULL)
		fatal("%s: buffer error", __func__);
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
		*length_ptr = len;  /* Safe: sshbuf never stores len > 2^31 */
	return value;
}

const void *
buffer_get_string_ptr(Buffer *buffer, u_int *length_ptr)
{
	const void *ret;

	if ((ret = buffer_get_string_ptr_ret(buffer, length_ptr)) == NULL)
		fatal("%s: buffer error", __func__);
	return (ret);
}

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
		fatal("%s: buffer error", __func__);
	return (u_char) ch;
}

void
buffer_put_char(Buffer *buffer, int value)
{
	int ret;

	if ((ret = sshbuf_put_u8(buffer, value)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_put_bignum2_from_string(Buffer *buffer, const u_char *s, u_int l)
{
	int ret;

	if ((ret = sshbuf_put_bignum2_bytes(buffer, s, l)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}
<<<<<<< bufaux.c

=======

/* Pseudo bignum functions */

void *
buffer_get_bignum2_as_string_ret(Buffer *buffer, u_int *length_ptr)
{
	u_int len;
	u_char *bin, *p, *ret;

	if ((p = bin = buffer_get_string_ret(buffer, &len)) == NULL) {
		error("%s: invalid bignum", __func__);
		return NULL;
	}

	if (len > 0 && (bin[0] & 0x80)) {
		error("%s: negative numbers not supported", __func__);
		free(bin);
		return NULL;
	}
	if (len > 8 * 1024) {
		error("%s: cannot handle BN of size %d", __func__, len);
		free(bin);
		return NULL;
	}
	/* Skip zero prefix on numbers with the MSB set */
	if (len > 1 && bin[0] == 0x00 && (bin[1] & 0x80) != 0) {
		p++;
		len--;
	}
	ret = xmalloc(len);
	memcpy(ret, p, len);
	explicit_bzero(p, len);
	free(bin);
	return ret;
}

void *
buffer_get_bignum2_as_string(Buffer *buffer, u_int *l)
{
	void *ret = buffer_get_bignum2_as_string_ret(buffer, l);

	if (ret == NULL)
		fatal("%s: buffer error", __func__);
	return ret;
}

/*
 * Stores a string using the bignum encoding rules (\0 pad if MSB set).
 */
void
buffer_put_bignum2_from_string(Buffer *buffer, const u_char *s, u_int l)
{
	u_char *buf, *p;
	int pad = 0;

	if (l > 8 * 1024)
		fatal("%s: length %u too long", __func__, l);
	p = buf = xmalloc(l + 1);
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	if (l > 0 && (s[0] & 0x80) != 0) {
		*p++ = '\0';
		pad = 1;
	}
	memcpy(p, s, l);
	buffer_put_string(buffer, buf, l + pad);
	explicit_bzero(buf, l + pad);
	free(buf);
}


>>>>>>> 1.56
