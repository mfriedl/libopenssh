/* $OpenBSD: kexgexc.c,v 1.12 2010/11/10 01:33:07 djm Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#include <openssl/dh.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "xmalloc.h"
#include "buffer.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "compat.h"
#include "dispatch.h"
#include "err.h"

static int input_kex_dh_gex_group(int, u_int32_t, struct ssh *);
static int input_kex_dh_gex_reply(int, u_int32_t, struct ssh *);

void
kexgex_client(struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	int min, max, nbits;

	nbits = dh_estimate(kex->we_need * 8);

	if (ssh->datafellows & SSH_OLD_DHGEX) {
		/* Old GEX request */
		ssh_packet_start(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST_OLD);
		ssh_packet_put_int(ssh, nbits);
		min = DH_GRP_MIN;
		max = DH_GRP_MAX;

		debug("SSH2_MSG_KEX_DH_GEX_REQUEST_OLD(%u) sent", nbits);
	} else {
		/* New GEX request */
		min = DH_GRP_MIN;
		max = DH_GRP_MAX;
		ssh_packet_start(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST);
		ssh_packet_put_int(ssh, min);
		ssh_packet_put_int(ssh, nbits);
		ssh_packet_put_int(ssh, max);

		debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
		    min, nbits, max);
	}
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    min, nbits, max);
#endif
	ssh_packet_send(ssh);

	kex->min   = min;
	kex->max   = max;
	kex->nbits = nbits;
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP, &input_kex_dh_gex_group);
}

static int
input_kex_dh_gex_group(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	BIGNUM *p = NULL, *g = NULL;

	debug("got SSH2_MSG_KEX_DH_GEX_GROUP");

	if ((p = BN_new()) == NULL)
		fatal("BN_new");
	ssh_packet_get_bignum2(ssh, p);
	if ((g = BN_new()) == NULL)
		fatal("BN_new");
	ssh_packet_get_bignum2(ssh, g);
	ssh_packet_check_eom(ssh);

	if (BN_num_bits(p) < kex->min || BN_num_bits(p) > kex->max)
		fatal("DH_GEX group out of range: %d !< %d !< %d",
		    kex->min, BN_num_bits(p), kex->max);

	kex->dh = dh_new_group(g, p);
	if (dh_gen_key(kex->dh, kex->we_need * 8) != 0)
		fatal("dh_gen_key failed");

#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, kex->dh->pub_key);
	fprintf(stderr, "\n");
#endif

	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
	/* generate and send 'e', client DH public key */
	ssh_packet_start(ssh, SSH2_MSG_KEX_DH_GEX_INIT);
	ssh_packet_put_bignum2(ssh, kex->dh->pub_key);
	ssh_packet_send(ssh);

	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REPLY, &input_kex_dh_gex_reply);
	return 0;
}

static int
input_kex_dh_gex_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = NULL, *shared_secret = NULL;
	struct sshkey *server_host_key;
	u_char *kbuf, *hash, *signature = NULL, *server_host_key_blob = NULL;
	u_int klen, slen, sbloblen, hashlen;
	int kout, r;

	debug("got SSH2_MSG_KEX_DH_GEX_REPLY");

	/* key, cert */
	server_host_key_blob = ssh_packet_get_string(ssh, &sbloblen);
	if ((r = sshkey_from_blob(server_host_key_blob, sbloblen,
	    &server_host_key)) != 0)
		fatal("cannot decode server_host_key_blob: %s", ssh_err(r));
	if (server_host_key->type != kex->hostkey_type)
		fatal("type mismatch for decoded server_host_key_blob");
	if (kex->verify_host_key == NULL)
		fatal("cannot verify server_host_key");
	if (kex->verify_host_key(server_host_key, ssh) == -1)
		fatal("server_host_key verification failed");

	/* DH parameter f, server public DH key */
	if ((dh_server_pub = BN_new()) == NULL)
		fatal("dh_server_pub == NULL");
	ssh_packet_get_bignum2(ssh, dh_server_pub);

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_server_pub= ");
	BN_print_fp(stderr, dh_server_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_server_pub));
#endif

	/* signed H */
	signature = ssh_packet_get_string(ssh, &slen);
	ssh_packet_check_eom(ssh);

	if (!dh_pub_is_valid(kex->dh, dh_server_pub))
	 	ssh_packet_disconnect(ssh,
		    "bad server public DH value");

	klen = DH_size(kex->dh);
	kbuf = xmalloc(klen);
	if ((kout = DH_compute_key(kbuf, dh_server_pub, kex->dh)) < 0)
		fatal("DH_compute_key: failed");
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	if ((shared_secret = BN_new()) == NULL)
		fatal("kexgex_client: BN_new failed");
	if (BN_bin2bn(kbuf, kout, shared_secret) == NULL)
		fatal("kexgex_client: BN_bin2bn failed");
	memset(kbuf, 0, klen);
	xfree(kbuf);

	if (ssh->datafellows & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	kexgex_hash(
	    kex->evp_md,
	    kex->client_version_string,
	    kex->server_version_string,
	    buffer_ptr(&kex->my), buffer_len(&kex->my),
	    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
	    server_host_key_blob, sbloblen,
	    kex->min, kex->nbits, kex->max,
	    kex->dh->p, kex->dh->g,
	    kex->dh->pub_key,
	    dh_server_pub,
	    shared_secret,
	    &hash, &hashlen
	);

	/* have keys, free DH */
	DH_free(kex->dh);
	kex->dh = NULL;
	xfree(server_host_key_blob);
	BN_clear_free(dh_server_pub);

	if (sshkey_verify(server_host_key, signature, slen, hash,
	    hashlen, datafellows) != 0)
		fatal("key_verify failed for server_host_key");
	sshkey_free(server_host_key);
	xfree(signature);

	/* save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}
	kex_derive_keys(ssh, hash, hashlen, shared_secret);
	BN_clear_free(shared_secret);

	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REPLY, NULL);
	kex_finish(ssh);
	return 0;
}
