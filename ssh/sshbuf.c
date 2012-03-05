/*	$OpenBSD$	*/
/*
 * Copyright (c) 2011 Damien Miller
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

#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "err.h"
#define SSHBUF_INTERNAL
#include "sshbuf.h"

static inline int
sshbuf_check_sanity(const struct sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	if (__predict_false(buf == NULL || buf->d == NULL ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, int force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	if (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

struct sshbuf *
sshbuf_new(void)
{
	struct sshbuf *ret;

	if ((ret = calloc(sizeof(*ret), 1)) == NULL)
		return NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->freeme = 1;
	if ((ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

void
sshbuf_init(struct sshbuf *ret)
{
	bzero(ret, sizeof(*ret));
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	if ((ret->d = calloc(1, ret->alloc)) == NULL)
		ret->alloc = 0;
}

void
sshbuf_free(struct sshbuf *buf)
{
	int freeme;

	if (sshbuf_check_sanity(buf) == 0)
		bzero(buf->d, buf->alloc);
	free(buf->d);
	freeme = buf->freeme;
	bzero(buf, sizeof(buf));
	if (freeme)
		free(buf);
}

void
sshbuf_reset(struct sshbuf *buf)
{
	u_char *d;

	if (sshbuf_check_sanity(buf) == 0)
		bzero(buf->d, buf->alloc);
	buf->off = buf->size = 0;
	if (buf->alloc != SSHBUF_SIZE_INIT) {
		if ((d = realloc(buf->d, SSHBUF_SIZE_INIT)) != NULL) {
			buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
}

size_t
sshbuf_max_size(const struct sshbuf *buf)
{
	return buf->max_size;
}

int
sshbuf_set_max_size(struct sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	int r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	if ((r = sshbuf_check_sanity(buf)) < 0)
		return r;
	if (max_size > SSHBUF_SIZE_MAX)
		return SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	if (max_size < buf->alloc && max_size > buf->size) {
		rlen = roundup(buf->size, SSHBUF_SIZE_INC);
		if (rlen > max_size)
			rlen = max_size;
		rlen = buf->size;
		bzero(buf->d + buf->size, buf->alloc - buf->size);
		SSHBUF_DBG(("new alloc = %zu", rlen));
		if ((dp = realloc(buf->d, rlen)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	if (max_size < buf->alloc)
		return SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	return 0;
}

size_t
sshbuf_len(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return 0;
	return buf->size - buf->off;
}

size_t
sshbuf_avail(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return 0;
	return buf->max_size - (buf->size - buf->off);
}

u_char *
sshbuf_ptr(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return NULL;
	return buf->d + buf->off;
}

int
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	int r;

	if ((r = sshbuf_check_sanity(buf)) < 0)
		return r;
	SSHBUF_TELL("check");
	/* Slightly odd test construction is to prevent unsigned overflows */
	if (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		return SSH_ERR_NO_BUFFER_SPACE;
	return 0;
}

int
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	size_t rlen, need;
	u_char *dp;
	int r;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	if ((r = sshbuf_check_reserve(buf, len)) < 0) {	/* does sanity check */
		if (dpp != NULL)
			*dpp = NULL;
		return r;
	}
	/* If we are running against max_size, we must pack */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("reserve");
	if (len + buf->size > buf->alloc) {
		/*
		 * Prefer to alloc in SSHBUF_SIZE_INC units, but
		 * allocate less if doing so would overflow max_size.
		 */
		need = len + buf->size - buf->alloc;
		rlen = roundup(buf->alloc + need, SSHBUF_SIZE_INC);
		SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
		if (rlen > buf->max_size)
			rlen = buf->alloc + need;
		SSHBUF_DBG(("adjusted rlen %zu", rlen));
		if ((dp = realloc(buf->d, rlen)) == NULL) {
			SSHBUF_DBG(("realloc fail"));
			if (dpp != NULL)
				*dpp = NULL;
			return SSH_ERR_ALLOC_FAIL;
		}
		buf->alloc = rlen;
		buf->d = dp;
		if ((r = sshbuf_check_reserve(buf, len)) < 0) {
			/* shouldn't fail */
			if (dpp != NULL)
				*dpp = NULL;
			return r;
		}
	}
	dp = buf->d + buf->size;
	buf->size += len;
	SSHBUF_TELL("done");
	if (dpp != NULL)
		*dpp = dp;
	return 0;
}

int
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	int r;

	SSHBUF_DBG(("len = %zu", len));
	if ((r = sshbuf_check_sanity(buf)) < 0)
		return r;
	if (len == 0)
		return 0;
	if (len > sshbuf_len(buf))
		return SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	SSHBUF_TELL("done");
	return 0;
}

int
sshbuf_consume_end(struct sshbuf *buf, size_t len)
{
	int r;

	SSHBUF_DBG(("len = %zu", len));
	if ((r = sshbuf_check_sanity(buf)) < 0)
		return r;
	if (len == 0)
		return 0;
	if (len > sshbuf_len(buf))
		return SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	return 0;
}

