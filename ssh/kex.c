/* $OpenBSD: kex.c,v 1.86 2010/09/22 05:01:29 djm Exp $ */
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

#include <sys/param.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "log.h"
#include "mac.h"
#include "match.h"
#include "dispatch.h"
#include "monitor.h"
#include "roaming.h"
#include "err.h"

/* prototype */
static int kex_choose_conf(struct ssh *);
static int kex_input_newkeys(int, u_int32_t, struct ssh *);

/* Validate KEX method name list */
int
kex_names_valid(const char *names)
{
	char *s, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	s = cp = xstrdup(names);
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
	    	if (strcmp(p, KEX_DHGEX_SHA256) != 0 &&
		    strcmp(p, KEX_DHGEX_SHA1) != 0 &&
		    strcmp(p, KEX_DH14) != 0 &&
		    strcmp(p, KEX_DH1) != 0 &&
		    (strncmp(p, KEX_ECDH_SHA2_STEM,
		    sizeof(KEX_ECDH_SHA2_STEM) - 1) != 0 ||
		    kex_ecdh_name_to_nid(p) == -1)) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			xfree(s);
			return 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	xfree(s);
	return 1;
}

/* put algorithm proposal into buffer */
int
kex_prop2buf(struct sshbuf *b, char *proposal[PROPOSAL_MAX])
{
	u_int i;
	int r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	for (i = 0; i < KEX_COOKIE_LEN; i++) {
		if ((r = sshbuf_put_u8(b, 0)) != 0)
			return r;
	}
	for (i = 0; i < PROPOSAL_MAX; i++) {
		if ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			return r;
	}
	if ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		return r;
	return 0;
}

/* parse buffer and return algorithm proposal */
int
kex_buf2prop(struct sshbuf *raw, int *first_kex_follows, char ***propp)
{
	struct sshbuf *b = NULL;
	u_char v;
	u_int i;
	char **proposal = NULL;
	int r;

	if ((proposal = calloc(PROPOSAL_MAX, sizeof(char *))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_putb(b, raw)) != 0 ||
	    (r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) /* skip cookie */
		goto out;
	/* extract kex init proposal strings */
	for (i = 0; i < PROPOSAL_MAX; i++) {
		if ((r = sshbuf_get_cstring(b, &(proposal[i]), NULL)) != 0)
			goto out;
		debug2("kex_parse_kexinit: %s", proposal[i]);
	}
	/* first kex follows / reserved */
	if ((r = sshbuf_get_u8(b, &v)) != 0 ||
	    (r = sshbuf_get_u32(b, &i)) != 0)
		goto out;
	if (first_kex_follows != NULL)
		*first_kex_follows = i;
	debug2("kex_parse_kexinit: first_kex_follows %d ", v);
	debug2("kex_parse_kexinit: reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	if (r != 0 && proposal != NULL)
		kex_prop_free(proposal);
	sshbuf_free(b);
	return r;
}

void
kex_prop_free(char **proposal)
{
	u_int i;

	for (i = 0; i < PROPOSAL_MAX; i++)
		xfree(proposal[i]);
	xfree(proposal);
}

/* ARGSUSED */
static int
kex_protocol_error(int type, u_int32_t seq, struct ssh *ssh)
{
	error("Hm, kex protocol error: type %d seq %u", type, seq);
	return 0;
}

static void
kex_reset_dispatch(struct ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
}

int
kex_finish(struct ssh *ssh)
{
	int r;

	kex_reset_dispatch(ssh);
	if ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	debug("SSH2_MSG_NEWKEYS sent");
	debug("expecting SSH2_MSG_NEWKEYS");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);
	return 0;
}

static int
kex_input_newkeys(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;

	debug("SSH2_MSG_NEWKEYS received");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_packet_check_eom(ssh);

	kex->done = 1;
	sshbuf_reset(kex->peer);
	/* sshbuf_reset(kex->my); */
	kex->flags &= ~KEX_INIT_SENT;
	xfree(kex->name);
	kex->name = NULL;
	return 0;
}

int
kex_send_kexinit(struct ssh *ssh)
{
	u_char *cookie;
	Kex *kex = ssh->kex;
	int r;

	if (kex == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	if (kex->flags & KEX_INIT_SENT)
		return 0;
	kex->done = 0;

	/* generate a random cookie */
	if (sshbuf_len(kex->my) < KEX_COOKIE_LEN)
		return SSH_ERR_INVALID_FORMAT;
	if ((cookie = sshbuf_ptr(kex->my)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0)
		return r;
	if ((r = sshpkt_put(ssh, sshbuf_ptr(kex->my),
	    sshbuf_len(kex->my))) != 0)
		return r;
	if ((r = sshpkt_send(ssh)) != 0)
		return r;
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	return 0;
}

/* ARGSUSED */
int
kex_input_kexinit(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	char *ptr;
	u_int i, dlen;
	int r;

	debug("SSH2_MSG_KEXINIT received");
	if (kex == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	ptr = ssh_packet_get_raw(ssh, &dlen);
	if ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		return r;

	/* discard packet */
	for (i = 0; i < KEX_COOKIE_LEN; i++)
		if ((r = sshpkt_get_u8(ssh, NULL)) != 0)
			return r;
	for (i = 0; i < PROPOSAL_MAX; i++)
		if ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0)
			return r;
	if ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
			return r;

	/* XXX check error */
	if (!(kex->flags & KEX_INIT_SENT)) {
		if ((r = kex_send_kexinit(ssh)) != 0)
			return r;
	}
	if ((r = kex_choose_conf(ssh)) != 0)
		return r;

	if (kex->kex_type >= 0 && kex->kex_type < KEX_MAX &&
	    kex->kex[kex->kex_type] != NULL)
		return (kex->kex[kex->kex_type])(ssh);

	return SSH_ERR_INTERNAL_ERROR;
}

int
kex_new(struct ssh *ssh, char *proposal[PROPOSAL_MAX], Kex **kexp)
{
	Kex *kex;
	int r;

	*kexp = NULL;
	if ((kex = calloc(1, sizeof(*kex))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((kex->peer = sshbuf_new()) == NULL ||
	    (kex->my = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kex_prop2buf(kex->my, proposal)) != 0)
		goto out;
	kex->done = 0;
	kex_reset_dispatch(ssh);
	r = 0;
	*kexp = kex;
 out:
	if (r != 0)
		kex_free(kex);
	return r;
}

void
kex_free(Kex *kex)
{
	if (kex->peer != NULL)
		sshbuf_free(kex->peer);
	if (kex->my != NULL)
		sshbuf_free(kex->my);
	if (kex->dh)
		DH_free(kex->dh);
	if (kex->ec_client_key)
		EC_KEY_free(kex->ec_client_key);
	free(kex);
}

int
kex_setup(struct ssh *ssh, char *proposal[PROPOSAL_MAX])
{
	int r;

	if ((r = kex_new(ssh, proposal, &ssh->kex)) != 0)
		return r;
	if ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = NULL;
		return r;
	}
	return 0;
}

static int
choose_enc(Enc *enc, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	if (name == NULL)
		return SSH_ERR_NO_CIPHER_ALG_MATCH;
	if ((enc->cipher = cipher_by_name(name)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	return 0;
}

static int
choose_mac(struct ssh *ssh, Mac *mac, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	if (name == NULL)
		return SSH_ERR_NO_MAC_ALG_MATCH;
	if (mac_setup(mac, name) < 0)
		return SSH_ERR_INTERNAL_ERROR;
	/* truncate the key */
	if (ssh->datafellows & SSH_BUG_HMAC)
		mac->key_len = 16;
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
	return 0;
}

static int
choose_comp(Comp *comp, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	if (name == NULL)
		return SSH_ERR_NO_COMPRESS_ALG_MATCH;
	if (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} else if (strcmp(name, "zlib") == 0) {
		comp->type = COMP_ZLIB;
	} else if (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} else {
		return SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	return 0;
}

static int
choose_kex(Kex *k, char *client, char *server)
{
	k->name = match_list(client, server, NULL);

	if (k->name == NULL)
		return SSH_ERR_NO_KEX_ALG_MATCH;
	if (strcmp(k->name, KEX_DH1) == 0) {
		k->kex_type = KEX_DH_GRP1_SHA1;
		k->evp_md = EVP_sha1();
	} else if (strcmp(k->name, KEX_DH14) == 0) {
		k->kex_type = KEX_DH_GRP14_SHA1;
		k->evp_md = EVP_sha1();
	} else if (strcmp(k->name, KEX_DHGEX_SHA1) == 0) {
		k->kex_type = KEX_DH_GEX_SHA1;
		k->evp_md = EVP_sha1();
	} else if (strcmp(k->name, KEX_DHGEX_SHA256) == 0) {
		k->kex_type = KEX_DH_GEX_SHA256;
		k->evp_md = EVP_sha256();
	} else if (strncmp(k->name, KEX_ECDH_SHA2_STEM,
	    sizeof(KEX_ECDH_SHA2_STEM) - 1) == 0) {
		k->kex_type = KEX_ECDH_SHA2;
		k->evp_md = kex_ecdh_name_to_evpmd(k->name);
	} else
		return SSH_ERR_INTERNAL_ERROR;
	return 0;
}

static int
choose_hostkeyalg(Kex *k, char *client, char *server)
{
	char *hostkeyalg = match_list(client, server, NULL);

	if (hostkeyalg == NULL)
		return SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(hostkeyalg);
	if (k->hostkey_type == KEY_UNSPEC)
		return SSH_ERR_INTERNAL_ERROR;
	free(hostkeyalg);
	return 0;
}

static int
proposals_match(char *my[PROPOSAL_MAX], char *peer[PROPOSAL_MAX])
{
	static int check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	int *idx;
	char *p;

	for (idx = &check[0]; *idx != -1; idx++) {
		if ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		if ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		if (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			return (0);
		}
	}
	debug2("proposals match");
	return (1);
}

static int
kex_choose_conf(struct ssh *ssh)
{
	Newkeys *newkeys;
	char **my = NULL, **peer = NULL;
	char **cprop, **sprop;
	int nenc, nmac, ncomp;
	u_int mode, ctos, need;
	u_char type;
	int r, first_kex_follows;
	Kex *kex = ssh->kex;

	if ((r = kex_buf2prop(kex->my, NULL, &my)) != 0 ||
	    (r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0) {
		goto out;
	}

	if (kex->server) {
		cprop=peer;
		sprop=my;
	} else {
		cprop=my;
		sprop=peer;
	}

	/* Check whether server offers roaming */
	if (!kex->server) {
		char *roaming = match_list(KEX_RESUME,
		    peer[PROPOSAL_KEX_ALGS], NULL);

		if (roaming) {
			kex->roaming = 1;
			free(roaming);
		}
	}

	/* Algorithm Negotiation */
	for (mode = 0; mode < MODE_MAX; mode++) {
		if ((newkeys = calloc(1, sizeof(*newkeys))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		if ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0 ||
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0 ||
		    (r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0)
			goto out;
		debug("kex: %s %s %s %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    newkeys->mac.name,
		    newkeys->comp.name);
	}
	if ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0 ||
	    (r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0)
		goto out;
	need = 0;
	for (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		if (need < newkeys->enc.key_len)
			need = newkeys->enc.key_len;
		if (need < newkeys->enc.block_size)
			need = newkeys->enc.block_size;
		if (need < newkeys->mac.key_len)
			need = newkeys->mac.key_len;
	}
	/* XXX need runden? */
	kex->we_need = need;

	/* ignore the next message if the proposals do not match */
	if (first_kex_follows && !proposals_match(my, peer) &&
	    !(ssh->datafellows & SSH_BUG_FIRSTKEX)) {
		if ((r = ssh_packet_read_seqnr(ssh, &type, NULL)) != 0)
			goto out;
		debug2("skipping next packet (type %u)", type);
	}
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	return r;
}

static int
derive_key(struct ssh *ssh, int id, u_int need, u_char *hash, u_int hashlen,
    BIGNUM *shared_secret, u_char **keyp)
{
	Kex *kex = ssh->kex;
	struct sshbuf *b = NULL;
	EVP_MD_CTX md;
	char c = id;
	u_int have;
	u_char *digest = NULL;
	int r, mdsz;

	if ((mdsz = EVP_MD_size(kex->evp_md)) <= 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((digest = calloc(1, roundup(need, mdsz))) == NULL ||
	    (b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(b, shared_secret)) != 0)
		goto out;

	/* K1 = HASH(K || H || "A" || session_id) */
	if (EVP_DigestInit(&md, kex->evp_md) != 1 ||
	    (!(ssh->datafellows & SSH_BUG_DERIVEKEY) &&
	    EVP_DigestUpdate(&md, sshbuf_ptr(b), sshbuf_len(b)) != 1) ||
	    EVP_DigestUpdate(&md, hash, hashlen) != 1 ||
	    EVP_DigestUpdate(&md, &c, 1) != 1 ||
	    EVP_DigestUpdate(&md, kex->session_id, kex->session_id_len) != 1 ||
	    EVP_DigestFinal(&md, digest, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	for (have = mdsz; need > have; have += mdsz) {
		if (EVP_DigestInit(&md, kex->evp_md) != 1 ||
		    (!(ssh->datafellows & SSH_BUG_DERIVEKEY) &&
		    EVP_DigestUpdate(&md, sshbuf_ptr(b), sshbuf_len(b)) != 1) ||
		    EVP_DigestUpdate(&md, hash, hashlen) != 1 ||
		    EVP_DigestUpdate(&md, digest, have) != 1 ||
		    EVP_DigestFinal(&md, digest + have, NULL) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = NULL;
	r = 0;
 out:
	if (digest)
		free (digest);
	if (b)
		sshbuf_free(b);
	return r;
}

#define NKEYS	6
int
kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
    BIGNUM *shared_secret)
{
	Kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	int r;

	for (i = 0; i < NKEYS; i++) {
		if ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			for (j = 0; j < i; j++)
				free(keys[j]);
			return r;
		}
	}
	for (mode = 0; mode < MODE_MAX; mode++) {
		ssh->current_keys[mode] = kex->newkeys[mode];
		kex->newkeys[mode] = NULL;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		ssh->current_keys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		ssh->current_keys[mode]->enc.key = keys[ctos ? 2 : 3];
		ssh->current_keys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	return 0;
}

Newkeys *
kex_get_newkeys(struct ssh *ssh, int mode)
{
	Newkeys *ret;

	ret = ssh->current_keys[mode];
	ssh->current_keys[mode] = NULL;
	return ret;
}

int
derive_ssh1_session_id(BIGNUM *host_modulus, BIGNUM *server_modulus,
    u_int8_t cookie[8], u_int8_t id[16])
{
	const EVP_MD *evp_md = EVP_md5();
	EVP_MD_CTX md;
	u_int8_t nbuf[2048], obuf[EVP_MAX_MD_SIZE];
	int len;

	if (EVP_DigestInit(&md, evp_md) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	len = BN_num_bytes(host_modulus);
	if (len < (512 / 8) || (u_int)len > sizeof(nbuf))
		return SSH_ERR_KEY_BITS_MISMATCH;
	if (BN_bn2bin(host_modulus, nbuf) <= 0 ||
	    EVP_DigestUpdate(&md, nbuf, len) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;

	len = BN_num_bytes(server_modulus);
	if (len < (512 / 8) || (u_int)len > sizeof(nbuf))
		return SSH_ERR_KEY_BITS_MISMATCH;
	if (BN_bn2bin(server_modulus, nbuf) <= 0 ||
	    EVP_DigestUpdate(&md, nbuf, len) != 1 ||
	    EVP_DigestUpdate(&md, cookie, 8) != 1 ||
	    EVP_DigestFinal(&md, obuf, NULL) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;

	memcpy(id, obuf, 16);

	memset(nbuf, 0, sizeof(nbuf));
	memset(obuf, 0, sizeof(obuf));
	memset(&md, 0, sizeof(md));
	return 0;
}

#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void
dump_digest(char *msg, u_char *digest, int len)
{
	int i;

	fprintf(stderr, "%s\n", msg);
	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", digest[i]);
		if (i%32 == 31)
			fprintf(stderr, "\n");
		else if (i%8 == 7)
			fprintf(stderr, " ");
	}
	fprintf(stderr, "\n");
}
#endif
