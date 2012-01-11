/* $OpenBSD: bufbn.c,v 1.6 2007/06/02 09:04:58 djm Exp $*/
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
 * Stores an BIGNUM in the buffer with a 2-byte msb first bit count, followed
 * by (bits+7)/8 bytes of binary data, msb first.
 */
int
buffer_put_bignum_ret(Buffer *buffer, const BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_put_bignum1(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

void
buffer_put_bignum(Buffer *buffer, const BIGNUM *value)
{
	if (buffer_put_bignum_ret(buffer, value) == -1)
		fatal("buffer_put_bignum: buffer error");
}

/*
 * Retrieves a BIGNUM from the buffer.
 */
int
buffer_get_bignum_ret(Buffer *buffer, BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_get_bignum1(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

void
buffer_get_bignum(Buffer *buffer, BIGNUM *value)
{
	if (buffer_get_bignum_ret(buffer, value) == -1)
		fatal("buffer_get_bignum: buffer error");
}

/*
 * Stores a BIGNUM in the buffer in SSH2 format.
 */
int
buffer_put_bignum2_ret(Buffer *buffer, const BIGNUM *value)
{
	int ret;

	if ((ret = sshbuf_put_bignum2(buffer, value)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

void
buffer_put_bignum2(Buffer *buffer, const BIGNUM *value)
{
	if (buffer_put_bignum2_ret(buffer, value) == -1)
		fatal("buffer_put_bignum2: buffer error");
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
		fatal("buffer_get_bignum2: buffer error");
}
