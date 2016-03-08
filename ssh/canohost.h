/* $OpenBSD: canohost.h,v 1.12 2016/03/07 19:02:43 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

<<<<<<< canohost.h
struct ssh;
const char	*get_canonical_hostname(int);
const char	*get_remote_name_or_ip(u_int, int);
=======
#ifndef _CANOHOST_H
#define _CANOHOST_H
>>>>>>> 1.12

char		*get_peer_ipaddr(int);
int		 get_peer_port(int);
char		*get_local_ipaddr(int);
char		*get_local_name(int);
int		get_local_port(int);

<<<<<<< canohost.h
int		 ssh_get_remote_port(struct ssh *);
int		 ssh_get_local_port(struct ssh *);
int		 get_sock_port(int, int);
=======
#endif /* _CANOHOST_H */
>>>>>>> 1.12
