/* $OpenBSD: buffer.c,v 1.32 2010/02/09 03:56:28 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for manipulating fifo buffers (that can grow if needed).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "err.h"

/* Appends data to the buffer, expanding it if necessary. */

void
buffer_append(Buffer *buffer, const void *data, u_int len)
{
	int ret;

	if ((ret = sshbuf_put(buffer, data, len)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
}

void *
buffer_append_space(Buffer *buffer, u_int len)
{
	int ret;
	u_char *p;

	if ((ret = sshbuf_reserve(buffer, len, &p)) != 0)
		fatal("%s: %s", __func__, ssh_err(ret));
	return p;
}

int
buffer_check_alloc(Buffer *buffer, u_int len)
{
	int ret = sshbuf_check_reserve(buffer, len);

	if (ret == 0)
		return 1;
	if (ret == SSH_ERR_NO_BUFFER_SPACE)
		return 0;
	fatal("%s: %s", __func__, ssh_err(ret));
}

int
buffer_get_ret(Buffer *buffer, void *buf, u_int len)
{
	int ret;

	if ((ret = sshbuf_get(buffer, buf, len)) != 0) {
		error("%s: %s", __func__, ssh_err(ret));
		return -1;
	}
	return 0;
}

void
buffer_get(Buffer *buffer, void *buf, u_int len)
{
	if (buffer_get_ret(buffer, buf, len) == -1)
		fatal("buffer_get: buffer error");
}

int
buffer_consume_ret(Buffer *buffer, u_int bytes)
{
	int ret = sshbuf_consume(buffer, bytes);

	if (ret == 0)
		return 0;
	if (ret == SSH_ERR_MESSAGE_INCOMPLETE)
		return -1;
	fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_consume(Buffer *buffer, u_int bytes)
{
	if (buffer_consume_ret(buffer, bytes) == -1)
		fatal("buffer_consume: buffer error");
}

int
buffer_consume_end_ret(Buffer *buffer, u_int bytes)
{
	int ret = sshbuf_consume_end(buffer, bytes);

	if (ret == 0)
		return 0;
	if (ret == SSH_ERR_MESSAGE_INCOMPLETE)
		return -1;
	fatal("%s: %s", __func__, ssh_err(ret));
}

void
buffer_consume_end(Buffer *buffer, u_int bytes)
{
	if (buffer_consume_end_ret(buffer, bytes) == -1)
		fatal("%s: buffer error", __func__);
}

