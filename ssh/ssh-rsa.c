/* $OpenBSD: ssh-rsa.c,v 1.50 2014/01/09 23:20:00 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
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

#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "err.h"
#define SSHKEY_INTERNAL
#include "key.h"
<<<<<<< ssh-rsa.c
=======
#include "compat.h"
#include "misc.h"
#include "ssh.h"
#include "digest.h"
>>>>>>> 1.50

static int openssh_RSA_verify(int, u_char *, size_t, u_char *, size_t, RSA *);

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
<<<<<<< ssh-rsa.c
	const EVP_MD *evp_md;
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE], *sig = NULL;
	size_t slen;
	u_int dlen, len;
	int nid, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
=======
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig;
	u_int slen, dlen, len;
	int ok, nid;
	Buffer b;
>>>>>>> 1.50

<<<<<<< ssh-rsa.c
	if (key == NULL || key->rsa == NULL || (key->type != KEY_RSA &&
	    key->type != KEY_RSA_CERT && key->type != KEY_RSA_CERT_V00))
		return SSH_ERR_INVALID_ARGUMENT;
=======
	if (key == NULL || key_type_plain(key->type) != KEY_RSA ||
	    key->rsa == NULL) {
		error("%s: no RSA key", __func__);
		return -1;
	}

	/* hash the data */
	hash_alg = SSH_DIGEST_SHA1;
	nid = NID_sha1;
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		error("%s: bad hash algorithm %d", __func__, hash_alg);
		return -1;
	}
	if (ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest)) != 0) {
		error("%s: ssh_digest_memory failed", __func__);
		return -1;
	}

>>>>>>> 1.50
	slen = RSA_size(key->rsa);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

<<<<<<< ssh-rsa.c
	nid = (compat & SSH_BUG_RSASIGMD5) ? NID_md5 : NID_sha1;
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (EVP_DigestInit(&md, evp_md) != 1 ||
	    EVP_DigestUpdate(&md, data, datalen) != 1 ||
	    EVP_DigestFinal(&md, digest, &dlen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (RSA_sign(nid, digest, dlen, sig, &len, key->rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
=======
		error("%s: RSA_sign failed: %s", __func__,
		    ERR_error_string(ecode, NULL));
		free(sig);
		return -1;
>>>>>>> 1.50
	}
	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		memset(sig, 0, diff);
	} else if (len > slen) {
<<<<<<< ssh-rsa.c
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
=======
		error("%s: slen %u slen2 %u", __func__, slen, len);
		free(sig);
		return -1;
>>>>>>> 1.50
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-rsa")) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (lenp != NULL)
		*lenp = len;
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	bzero(digest, sizeof(digest));
	bzero(&md, sizeof(md));
	if (sig != NULL) {
		memset(sig, 's', slen);
		free(sig);
	}
	if (b != NULL)
		sshbuf_free(b);
	return 0;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
<<<<<<< ssh-rsa.c
	struct sshbuf *b = NULL;
	const EVP_MD *evp_md;
	EVP_MD_CTX md;
	char *ktype = NULL;
	u_char digest[EVP_MAX_MD_SIZE], *osigblob, *sigblob = NULL;
	size_t len, diff, modlen;
	u_int dlen;
	int nid, ret = SSH_ERR_INTERNAL_ERROR;
=======
	Buffer b;
	int hash_alg;
	char *ktype;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sigblob;
	u_int len, dlen, modlen;
	int rlen, ret;
>>>>>>> 1.50

<<<<<<< ssh-rsa.c
	if (key == NULL || key->rsa == NULL || (key->type != KEY_RSA &&
	    key->type != KEY_RSA_CERT && key->type != KEY_RSA_CERT_V00) ||
	    BN_num_bits(key->rsa->n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
=======
	if (key == NULL || key_type_plain(key->type) != KEY_RSA ||
	    key->rsa == NULL) {
		error("%s: no RSA key", __func__);
		return -1;
	}

	if (BN_num_bits(key->rsa->n) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error("%s: RSA modulus too small: %d < minimum %d bits",
		    __func__, BN_num_bits(key->rsa->n),
		    SSH_RSA_MINIMUM_MODULUS_SIZE);
		return -1;
	}
	buffer_init(&b);
	buffer_append(&b, signature, signaturelen);
	ktype = buffer_get_cstring(&b, NULL);
>>>>>>> 1.50
	if (strcmp("ssh-rsa", ktype) != 0) {
<<<<<<< ssh-rsa.c
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
=======
		error("%s: cannot handle type %s", __func__, ktype);
		buffer_free(&b);
		free(ktype);
		return -1;
>>>>>>> 1.50
	}
<<<<<<< ssh-rsa.c
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
=======
	free(ktype);
	sigblob = buffer_get_string(&b, &len);
	rlen = buffer_len(&b);
	buffer_free(&b);
	if (rlen != 0) {
		error("%s: remaining bytes in signature %d", __func__, rlen);
		free(sigblob);
		return -1;
>>>>>>> 1.50
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
<<<<<<< ssh-rsa.c
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
=======
		error("%s: len %u > modlen %u", __func__, len, modlen);
		free(sigblob);
		return -1;
>>>>>>> 1.50
	} else if (len < modlen) {
<<<<<<< ssh-rsa.c
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			memset(osigblob, 's', len);
			free(osigblob);
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
=======
		u_int diff = modlen - len;
		debug("%s: add padding: modlen %u > len %u", __func__,
		    modlen, len);
		sigblob = xrealloc(sigblob, 1, modlen);
>>>>>>> 1.50
		memmove(sigblob + diff, sigblob, len);
		memset(sigblob, 0, diff);
		len = modlen;
	}
<<<<<<< ssh-rsa.c
	nid = (compat & SSH_BUG_RSASIGMD5) ? NID_md5 : NID_sha1;
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_DigestInit(&md, evp_md) != 1 ||
	    EVP_DigestUpdate(&md, data, datalen) != 1 ||
	    EVP_DigestFinal(&md, digest, &dlen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
=======
	/* hash the data */
	hash_alg = SSH_DIGEST_SHA1;
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		error("%s: bad hash algorithm %d", __func__, hash_alg);
		return -1;
	}
	if (ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest)) != 0) {
		error("%s: ssh_digest_memory failed", __func__);
		return -1;
>>>>>>> 1.50
	}

<<<<<<< ssh-rsa.c
	ret = openssh_RSA_verify(nid, digest, dlen, sigblob, len, key->rsa);
 out:
	if (sigblob != NULL) {
		memset(sigblob, 's', len);
		free(sigblob);
	}
	if (ktype != NULL)
		free(ktype);
	if (b != NULL)
		sshbuf_free(b);
	bzero(digest, sizeof(digest));
	bzero(&md, sizeof(md));
=======
	ret = openssh_RSA_verify(hash_alg, digest, dlen, sigblob, len,
	    key->rsa);
	memset(digest, 'd', sizeof(digest));
	memset(sigblob, 's', len);
	free(sigblob);
	debug("%s: signature %scorrect", __func__, (ret == 0) ? "in" : "");
>>>>>>> 1.50
	return ret;
}

/*
 * See:
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
 */
/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
static const u_char id_sha1[] = {
	0x30, 0x21, /* type Sequence, length 0x21 (33) */
	0x30, 0x09, /* type Sequence, length 0x09 */
	0x06, 0x05, /* type OID, length 0x05 */
	0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
	0x05, 0x00, /* NULL */
	0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
};

static int
<<<<<<< ssh-rsa.c
openssh_RSA_verify(int type, u_char *hash, size_t hashlen,
    u_char *sigbuf, size_t siglen, RSA *rsa)
=======
openssh_RSA_verify(int hash_alg, u_char *hash, u_int hashlen,
    u_char *sigbuf, u_int siglen, RSA *rsa)
>>>>>>> 1.50
{
	size_t ret, rsasize = 0, oidlen = 0, hlen = 0;
	int len, oidmatch, hashmatch;
	const u_char *oid = NULL;
	u_char *decrypted = NULL;

<<<<<<< ssh-rsa.c
	ret = SSH_ERR_INTERNAL_ERROR;
	switch (type) {
	case NID_sha1:
=======
	ret = 0;
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
>>>>>>> 1.50
		oid = id_sha1;
		oidlen = sizeof(id_sha1);
		hlen = 20;
		break;
	default:
		goto done;
	}
	if (hashlen != hlen) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	rsasize = RSA_size(rsa);
	if (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    siglen == 0 || siglen > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	if ((decrypted = malloc(rsasize)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	if ((len = RSA_public_decrypt(siglen, sigbuf, decrypted, rsa,
	    RSA_PKCS1_PADDING)) < 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}
	if (len < 0 || (size_t)len != hlen + oidlen) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
	oidmatch = timingsafe_bcmp(decrypted, oid, oidlen) == 0;
	hashmatch = timingsafe_bcmp(decrypted + oidlen, hash, hlen) == 0;
	if (!oidmatch || !hashmatch) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	ret = 0;
done:
	if (decrypted) {
		bzero(decrypted, rsasize);
		free(decrypted);
	}
	return ret;
}
