/* $OpenBSD: kex.h,v 1.52 2010/09/22 05:01:29 djm Exp $ */

/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#ifndef KEX_H
#define KEX_H

#include <openssl/evp.h>
#include <openssl/ec.h>

#include "mac.h"

#define KEX_COOKIE_LEN	16

#define	KEX_DH1			"diffie-hellman-group1-sha1"
#define	KEX_DH14		"diffie-hellman-group14-sha1"
#define	KEX_DHGEX_SHA1		"diffie-hellman-group-exchange-sha1"
#define	KEX_DHGEX_SHA256	"diffie-hellman-group-exchange-sha256"
#define	KEX_RESUME		"resume@appgate.com"
/* The following represents the family of ECDH methods */
#define	KEX_ECDH_SHA2_STEM	"ecdh-sha2-"

#define COMP_NONE	0
#define COMP_ZLIB	1
#define COMP_DELAYED	2

enum kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

enum kex_exchange {
	KEX_DH_GRP1_SHA1,
	KEX_DH_GRP14_SHA1,
	KEX_DH_GEX_SHA1,
	KEX_DH_GEX_SHA256,
	KEX_ECDH_SHA2,
	KEX_MAX
};

#define KEX_INIT_SENT	0x0001

typedef struct Kex Kex;
typedef struct sshmac Mac;
typedef struct Comp Comp;
typedef struct Enc Enc;
typedef struct Newkeys Newkeys;

struct Enc {
	char	*name;
	Cipher	*cipher;
	int	enabled;
	u_int	key_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
struct Comp {
	int	type;
	int	enabled;
	char	*name;
};
struct Newkeys {
	Enc	enc;
	Mac	mac;
	Comp	comp;
};

struct ssh;

struct Kex {
	u_char	*session_id;
	u_int	session_id_len;
	Newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	int	server;
	char	*name;
	int	hostkey_type;
	int	kex_type;
	int	roaming;
	struct sshbuf *my;
	struct sshbuf *peer;
	sig_atomic_t done;
	int	flags;
	const EVP_MD *evp_md;
	char	*client_version_string;
	char	*server_version_string;
	int	(*verify_host_key)(struct sshkey *, struct ssh *);
	struct sshkey *(*load_host_public_key)(int, struct ssh *);
	struct sshkey *(*load_host_private_key)(int, struct ssh *);
	int	(*host_key_index)(struct sshkey *);
	int	(*kex[KEX_MAX])(struct ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	int	min, max, nbits;	/* GEX */
	EC_KEY	*ec_client_key;		/* EC�H */
	const EC_GROUP *ec_group;	/* EC�H */
};

int	 kex_names_valid(const char *);

int	kex_new(struct ssh *, char *[PROPOSAL_MAX], Kex **);
int	 kex_setup(struct ssh *, char *[PROPOSAL_MAX]);
int	 kex_finish(struct ssh *);
void	 kex_free(Kex *);

int	 kex_buf2prop(struct sshbuf *, int *, char ***);
int	 kex_prop2buf(struct sshbuf *, char *proposal[PROPOSAL_MAX]);
void	 kex_prop_free(char **);

int	 kex_send_kexinit(struct ssh *);
int	 kex_input_kexinit(int, u_int32_t, struct ssh *);
int	 kex_derive_keys(struct ssh *, u_char *, u_int, BIGNUM *);

Newkeys *kex_get_newkeys(struct ssh *, int);

int	 kexdh_client(struct ssh *);
int	 kexdh_server(struct ssh *);
int	 kexgex_client(struct ssh *);
int	 kexgex_server(struct ssh *);
int	 kexecdh_client(struct ssh *);
int	 kexecdh_server(struct ssh *);

int
kex_dh_hash(char *, char *, char *, size_t, char *, size_t, u_char *, size_t,
    BIGNUM *, BIGNUM *, BIGNUM *, u_char **, size_t *);
int
kexgex_hash(const EVP_MD *, char *, char *, char *, size_t, char *,
    size_t, u_char *, size_t, int, int, int, BIGNUM *, BIGNUM *, BIGNUM *,
    BIGNUM *, BIGNUM *, u_char **, size_t *);
int
kex_ecdh_hash(const EVP_MD *, const EC_GROUP *, char *, char *, char *, size_t,
    char *, size_t, u_char *, size_t, const EC_POINT *, const EC_POINT *,
    const BIGNUM *, u_char **, size_t *);

int	kex_ecdh_name_to_nid(const char *);
const EVP_MD *kex_ecdh_name_to_evpmd(const char *);

int
derive_ssh1_session_id(BIGNUM *, BIGNUM *, u_int8_t[8], u_int8_t[16]);

#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void	dump_digest(char *, u_char *, int);
#endif

#endif
