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

int sshkey_save_private(struct sshkey *, const char *,
    const char *, const char *);
int sshkey_load_file(int, const char *, struct sshbuf *);
int sshkey_load_cert(const char *, struct sshkey **);
int sshkey_load_public(const char *, struct sshkey **, char **);
int sshkey_load_public_type(int, const char *, struct sshkey **, char **);
int sshkey_parse_private(struct sshbuf *, const char *, const char *,
    struct sshkey **, char **);
int sshkey_load_private(const char *, const char *, struct sshkey **, char **);
int sshkey_load_private_cert(int, const char *, const char *,
    struct sshkey **, int *);
int sshkey_load_private_type(int, const char *, const char *,
    struct sshkey **, char **, int *);
int sshkey_load_private_pem(int, int, const char *, struct sshkey **, char **);
int sshkey_perm_ok(int, const char *);
int sshkey_in_file(struct sshkey *, const char *, int);

#endif
