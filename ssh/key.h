<<<<<<< key.h
/* $OpenBSD: key.h,v 1.40 2013/12/06 13:39:49 markus Exp $ */
=======
/* $OpenBSD: key.h,v 1.42 2014/06/24 01:13:21 djm Exp $ */
>>>>>>> 1.42

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
#ifndef KEY_H
#define KEY_H

<<<<<<< key.h
#include <sys/types.h>

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#ifdef WITH_LEAKMALLOC
#include "leakmalloc.h"
#endif

#define SSH_RSA_MINIMUM_MODULUS_SIZE	768
#define SSH_KEY_MAX_SIGN_DATA_SIZE	(1 << 20)

/* XXX compat, remove when we can */
#define types sshkey_types
#define fp_type sshkey_fp_type
#define fp_rep sshkey_fp_rep

struct sshbuf;

/* Key types */
enum sshkey_types {
	KEY_RSA1,
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_DSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_RSA_CERT_V00,
	KEY_DSA_CERT_V00,
	KEY_UNSPEC
};

/* Fingerprint hash algorithms */
/* XXX add SHA256 */
enum sshkey_fp_type {
	SSH_FP_SHA1,
	SSH_FP_MD5,
	SSH_FP_SHA256
};

/* Fingerprint representation formats */
enum sshkey_fp_rep {
	SSH_FP_HEX,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opaquify? */
struct sshkey_cert {
	struct sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	u_int64_t	 serial;
	char		*key_id;
	u_int		 nprincipals;
	char		**principals;
	u_int64_t	 valid_after, valid_before;
	struct sshbuf	*critical;
	struct sshbuf	*extensions;
	struct sshkey	*signature_key;
};

/* XXX opaquify? */
struct sshkey {
	int	 type;
	int	 flags;
	RSA	*rsa;
	DSA	*dsa;
	int	 ecdsa_nid;	/* NID of curve */
	EC_KEY	*ecdsa;
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	struct sshkey_cert *cert;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

struct sshkey	*sshkey_new(int);
int		 sshkey_add_private(struct sshkey *);
struct sshkey	*sshkey_new_private(int);
void		 sshkey_free(struct sshkey *);
int		 sshkey_demote(const struct sshkey *, struct sshkey **);
int		 sshkey_equal_public(const struct sshkey *,
    const struct sshkey *);
int		 sshkey_equal(const struct sshkey *, const struct sshkey *);
char		*sshkey_fingerprint(const struct sshkey *,
    enum sshkey_fp_type, enum sshkey_fp_rep);
u_char		*sshkey_fingerprint_raw(const struct sshkey *,
    enum sshkey_fp_type, size_t *);
const char	*sshkey_type(const struct sshkey *);
const char	*sshkey_cert_type(const struct sshkey *);
int		 sshkey_write(const struct sshkey *, FILE *);
int		 sshkey_read(struct sshkey *, char **);
u_int		 sshkey_size(const struct sshkey *);

int		 sshkey_generate(int type, u_int bits, struct sshkey **keyp);
int		 sshkey_from_private(const struct sshkey *, struct sshkey **);
int	 sshkey_type_from_name(const char *);
int	 sshkey_is_cert(const struct sshkey *);
int	 sshkey_type_is_cert(int);
int	 sshkey_type_plain(int);
int	 sshkey_to_certified(struct sshkey *, int);
int	 sshkey_drop_cert(struct sshkey *);
int	 sshkey_certify(struct sshkey *, struct sshkey *);
int	 sshkey_cert_copy(const struct sshkey *, struct sshkey *);
int	 sshkey_cert_check_authority(const struct sshkey *, int, int,
    const char *, const char **);
int	 sshkey_cert_is_legacy(const struct sshkey *);

int		 sshkey_ecdsa_nid_from_name(const char *);
int		 sshkey_curve_name_to_nid(const char *);
const char *	 sshkey_curve_nid_to_name(int);
u_int		 sshkey_curve_nid_to_bits(int);
int		 sshkey_ecdsa_bits_to_nid(int);
int		 sshkey_ecdsa_key_to_nid(EC_KEY *);
int		 sshkey_ec_nid_to_hash_alg(int nid);
int		 sshkey_ec_validate_public(const EC_GROUP *, const EC_POINT *);
int		 sshkey_ec_validate_private(const EC_KEY *);
const char	*sshkey_ssh_name(const struct sshkey *);
const char	*sshkey_ssh_name_plain(const struct sshkey *);
int		 sshkey_names_valid2(const char *);
char		*key_alg_list(int, int);

int	 sshkey_from_blob(const u_char *, size_t, struct sshkey **);
int	 sshkey_to_blob_buf(const struct sshkey *, struct sshbuf *);
int	 sshkey_to_blob(const struct sshkey *, u_char **, size_t *);
int	 sshkey_plain_to_blob_buf(const struct sshkey *, struct sshbuf *);
int	 sshkey_plain_to_blob(const struct sshkey *, u_char **, size_t *);

int	 sshkey_sign(const struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, u_int);
int	 sshkey_verify(const struct sshkey *, const u_char *, size_t,
    const u_char *, size_t, u_int);

/* for debug */
void	sshkey_dump_ec_point(const EC_GROUP *, const EC_POINT *);
void	sshkey_dump_ec_key(const EC_KEY *);

#ifdef SSHKEY_INTERNAL
int ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat);
int ssh_rsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat);
int ssh_dss_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat);
int ssh_dss_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat);
int ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat);
int ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat);
int ssh_ed25519_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat);
int ssh_ed25519_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat);
#endif
=======
#include "sshkey.h"

typedef struct sshkey Key;

#define types sshkey_types
#define fp_type sshkey_fp_type
#define fp_rep sshkey_fp_rep

#ifndef SSH_KEY_NO_DEFINE
#define key_new			sshkey_new
#define key_free		sshkey_free
#define key_equal_public	sshkey_equal_public
#define key_equal		sshkey_equal
#define key_fingerprint		sshkey_fingerprint
#define key_type		sshkey_type
#define key_cert_type		sshkey_cert_type
#define key_ssh_name		sshkey_ssh_name
#define key_ssh_name_plain	sshkey_ssh_name_plain
#define key_type_from_name	sshkey_type_from_name
#define key_ecdsa_nid_from_name	sshkey_ecdsa_nid_from_name
#define key_type_is_cert	sshkey_type_is_cert
#define key_size		sshkey_size
#define key_ecdsa_bits_to_nid	sshkey_ecdsa_bits_to_nid
#define key_ecdsa_key_to_nid	sshkey_ecdsa_key_to_nid
#define key_names_valid2	sshkey_names_valid2
#define key_is_cert		sshkey_is_cert
#define key_type_plain		sshkey_type_plain
#define key_cert_is_legacy	sshkey_cert_is_legacy
#define key_curve_name_to_nid	sshkey_curve_name_to_nid
#define key_curve_nid_to_bits	sshkey_curve_nid_to_bits
#define key_curve_nid_to_name	sshkey_curve_nid_to_name
#define key_ec_nid_to_hash_alg	sshkey_ec_nid_to_hash_alg
#define key_dump_ec_point	sshkey_dump_ec_point
#define key_dump_ec_key		sshkey_dump_ec_key
#define key_fingerprint		sshkey_fingerprint
#endif

void	 key_add_private(Key *);
Key	*key_new_private(int);
void	 key_free(Key *);
Key	*key_demote(const Key *);
u_char	*key_fingerprint_raw(const Key *, enum fp_type, u_int *);
int	 key_write(const Key *, FILE *);
int	 key_read(Key *, char **);

Key	*key_generate(int, u_int);
Key	*key_from_private(const Key *);
int	 key_to_certified(Key *, int);
int	 key_drop_cert(Key *);
int	 key_certify(Key *, Key *);
void	 key_cert_copy(const Key *, Key *);
int	 key_cert_check_authority(const Key *, int, int, const char *,
	    const char **);
char	*key_alg_list(int, int);

#ifdef WITH_OPENSSL
int	 key_ec_validate_public(const EC_GROUP *, const EC_POINT *);
int	 key_ec_validate_private(const EC_KEY *);
#endif /* WITH_OPENSSL */

Key	*key_from_blob(const u_char *, u_int);
int	 key_to_blob(const Key *, u_char **, u_int *);

int	 key_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 key_verify(const Key *, const u_char *, u_int, const u_char *, u_int);

void     key_private_serialize(const Key *, struct sshbuf *);
Key	*key_private_deserialize(struct sshbuf *);
>>>>>>> 1.42

<<<<<<< key.h
int	sshkey_private_serialize(const struct sshkey *key, struct sshbuf *buf);
int	sshkey_private_deserialize(struct sshbuf *buf,  struct sshkey **keyp);
=======
/* authfile.c */
int	 key_save_private(Key *, const char *, const char *, const char *,
    int, const char *, int);
int	 key_load_file(int, const char *, struct sshbuf *);
Key	*key_load_cert(const char *);
Key	*key_load_public(const char *, char **);
Key	*key_load_private(const char *, const char *, char **);
Key	*key_load_private_cert(int, const char *, const char *, int *);
Key	*key_load_private_type(int, const char *, const char *, char **, int *);
Key	*key_load_private_pem(int, int, const char *, char **);
int	 key_perm_ok(int, const char *);
int	 key_in_file(Key *, const char *, int);
>>>>>>> 1.42

#endif
