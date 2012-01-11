/* $OpenBSD: authfile.h,v 1.16 2011/05/04 21:15:29 djm Exp $ */

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

#ifndef AUTHFILE_H
#define AUTHFILE_H

struct sshbuf;
struct sshkey;

int		 key_save_private(struct sshkey *, const char *,
    const char *, const char *);
int		 key_load_file(int, const char *, struct sshbuf *);
struct sshkey	*key_load_cert(const char *);
struct sshkey	*key_load_public(const char *, char **);
struct sshkey	*key_load_public_type(int, const char *, char **);
struct sshkey	*key_parse_private(struct sshbuf *, const char *, const char *,
    char **);
struct sshkey	*key_load_private(const char *, const char *, char **);
struct sshkey	*key_load_private_cert(int, const char *, const char *, int *);
struct sshkey	*key_load_private_type(int, const char *, const char *,
    char **, int *);
struct sshkey	*key_load_private_pem(int, int, const char *, char **);
int		 key_perm_ok(int, const char *);
int		 key_in_file(struct sshkey *, const char *, int);

#endif
