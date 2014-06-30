<<<<<<< bufbn.c
<<<<<<< bufbn.c
<<<<<<< bufbn.c
<<<<<<< bufbn.c
/* $OpenBSD: bufbn.c,v 1.12 2014/04/30 05:29:56 djm Exp $ */

=======
/* $OpenBSD: bufbn.c,v 1.11 2014/02/27 08:25:09 djm Exp $*/
>>>>>>> 1.11
=======
/* $OpenBSD: bufbn.c,v 1.8 2013/11/08 11:15:19 dtucker Exp $*/
>>>>>>> 1.8
=======
/* $OpenBSD: bufbn.c,v 1.8 2013/11/08 11:15:19 dtucker Exp $*/
>>>>>>> 1.8
=======
/* $OpenBSD: bufbn.c,v 1.8 2013/11/08 11:15:19 dtucker Exp $*/
>>>>>>> 1.8
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

<<<<<<< bufbn.c
=======
#include <openssl/bn.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "xmalloc.h"
>>>>>>> 1.11
#include "buffer.h"
#include "log.h"
#include "ssherr.h"

int
buffer_put_bignum_ret(Buffer *buffer, const BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_put_bignum1(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
<<<<<<< bufbn.c
	return 0;
=======

	/* Store the number of bits in the buffer in two bytes, msb first. */
	put_u16(msg, bits);
	buffer_append(buffer, msg, 2);
	/* Store the binary data. */
	buffer_append(buffer, buf, oi);

	explicit_bzero(buf, bin_size);
	free(buf);

	return (0);
>>>>>>> 1.11
}

void
buffer_put_bignum(Buffer *buffer, const BIGNUM *value)
{
	if (buffer_put_bignum_ret(buffer, value) == -1)
		fatal("%s: buffer error", __func__);
}

int
buffer_get_bignum_ret(Buffer *buffer, BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_get_bignum1(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
<<<<<<< bufbn.c
	return 0;
=======
	bits = get_u16(buf);
	if (bits > 65535-7) {
		error("buffer_get_bignum_ret: cannot handle BN of size %d",
		    bits);
		return (-1);
	}
	/* Compute the number of binary bytes that follow. */
	bytes = (bits + 7) / 8;
	if (bytes > 8 * 1024) {
		error("buffer_get_bignum_ret: cannot handle BN of size %d", bytes);
		return (-1);
	}
	if (buffer_len(buffer) < bytes) {
		error("buffer_get_bignum_ret: input buffer too small");
		return (-1);
	}
	bin = buffer_ptr(buffer);
	if (BN_bin2bn(bin, bytes, value) == NULL) {
		error("buffer_get_bignum_ret: BN_bin2bn failed");
		return (-1);
	}
	if (buffer_consume_ret(buffer, bytes) == -1) {
		error("buffer_get_bignum_ret: buffer_consume failed");
		return (-1);
	}
	return (0);
>>>>>>> 1.11
}

void
buffer_get_bignum(Buffer *buffer, BIGNUM *value)
{
	if (buffer_get_bignum_ret(buffer, value) == -1)
		fatal("%s: buffer error", __func__);
}

int
buffer_put_bignum2_ret(Buffer *buffer, const BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_put_bignum2(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
<<<<<<< bufbn.c
	return 0;
=======
	if (value->neg) {
		error("buffer_put_bignum2_ret: negative numbers not supported");
		return (-1);
	}
	bytes = BN_num_bytes(value) + 1; /* extra padding byte */
	if (bytes < 2) {
		error("buffer_put_bignum2_ret: BN too small");
		return (-1);
	}
	buf = xmalloc(bytes);
	buf[0] = 0x00;
	/* Get the value of in binary */
	oi = BN_bn2bin(value, buf+1);
	if (oi < 0 || (u_int)oi != bytes - 1) {
		error("buffer_put_bignum2_ret: BN_bn2bin() failed: "
		    "oi %d != bin_size %d", oi, bytes);
		free(buf);
		return (-1);
	}
	hasnohigh = (buf[1] & 0x80) ? 0 : 1;
	buffer_put_string(buffer, buf+hasnohigh, bytes-hasnohigh);
	explicit_bzero(buf, bytes);
	free(buf);
	return (0);
>>>>>>> 1.11
}

void
buffer_put_bignum2(Buffer *buffer, const BIGNUM *value)
{
	if (buffer_put_bignum2_ret(buffer, value) == -1)
		fatal("%s: buffer error", __func__);
}

int
buffer_get_bignum2_ret(Buffer *buffer, BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_get_bignum2(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

void
buffer_get_bignum2(Buffer *buffer, BIGNUM *value)
{
	if (buffer_get_bignum2_ret(buffer, value) == -1)
		fatal("%s: buffer error", __func__);
}
