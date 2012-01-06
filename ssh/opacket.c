/* $OpenBSD: */
/*
 * Copyright (c) 2012 Markus Friedl <markus@openbsd.org>
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

#include "packet.h"

struct ssh *active_state, *backup_state;

void    
packet_backup_state(void)
{
	ssh_packet_backup_state(active_state, backup_state);
}

void    
packet_restore_state(void)
{
	ssh_packet_restore_state(active_state, backup_state);
}

u_int
packet_get_char(void)
{
	return (ssh_packet_get_char(active_state));
}

u_int
packet_get_int(void)
{
	return (ssh_packet_get_int(active_state));
}
