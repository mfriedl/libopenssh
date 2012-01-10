/* $OpenBSD: dispatch.c,v 1.22 2008/10/31 15:05:34 stevesk Exp $ */
/*
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

#include <signal.h>
#include <stdarg.h>

#include "ssh1.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "packet.h"
#include "compat.h"

void
dispatch_protocol_error(int type, u_int32_t seq, struct ssh *ssh)
{
	logit("dispatch_protocol_error: type %d seq %u", type, seq);
	if (!compat20)
		fatal("protocol error");
	packet_start(SSH2_MSG_UNIMPLEMENTED);
	packet_put_int(seq);
	packet_send();
	packet_write_wait();
}

void
dispatch_protocol_ignore(int type, u_int32_t seq, struct ssh *ssh)
{
	logit("dispatch_protocol_ignore: type %d seq %u", type, seq);
}

void
ssh_dispatch_init(struct ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	for (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}
void
ssh_dispatch_range(struct ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	for (i = from; i <= to; i++) {
		if (i >= DISPATCH_MAX)
			break;
		ssh->dispatch[i] = fn;
	}
}
void
ssh_dispatch_set(struct ssh *ssh, int type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}
void
ssh_dispatch_run(struct ssh *ssh, int mode, volatile sig_atomic_t *done, void *ctxt)
{
	for (;;) {
		int type;
		u_int32_t seqnr;

		if (mode == DISPATCH_BLOCK) {
			type = ssh_packet_read_seqnr(ssh, &seqnr);
		} else {
			type = ssh_packet_read_poll_seqnr(ssh, &seqnr);
			if (type == SSH_MSG_NONE)
				return;
		}
		if (type > 0 && type < DISPATCH_MAX && ssh->dispatch[type] != NULL)
			(*ssh->dispatch[type])(type, seqnr, ctxt);
		else
			ssh_packet_disconnect(ssh, "protocol error: rcvd type %d", type);
		if (done != NULL && *done)
			return;
	}
}
