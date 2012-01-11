/* $OpenBSD: kexgexs.c,v 1.14 2010/11/10 01:33:07 djm Exp $ */
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

#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/dh.h>

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
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "dispatch.h"
#include "err.h"

struct kexgexs_state {
    int omin, min, omax, max, onbits;
    DH *dh;
};

static void input_kex_dh_gex_init(int, u_int32_t, struct ssh *);

void
kexgex_server(struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	DH *dh;
	int omin = -1, min = -1, omax = -1, max = -1, onbits = -1, nbits = -1;
	int type;
	struct kexgexs_state *kexgexs_state;

	type = ssh_packet_read(ssh);
	switch (type) {
	case SSH2_MSG_KEX_DH_GEX_REQUEST:
		debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
		omin = min = ssh_packet_get_int(ssh);
		onbits = nbits = ssh_packet_get_int(ssh);
		omax = max = ssh_packet_get_int(ssh);
		min = MAX(DH_GRP_MIN, min);
		max = MIN(DH_GRP_MAX, max);
		nbits = MAX(DH_GRP_MIN, nbits);
		nbits = MIN(DH_GRP_MAX, nbits);
		break;
	case SSH2_MSG_KEX_DH_GEX_REQUEST_OLD:
		debug("SSH2_MSG_KEX_DH_GEX_REQUEST_OLD received");
		onbits = nbits = ssh_packet_get_int(ssh);
		/* unused for old GEX */
		omin = min = DH_GRP_MIN;
		omax = max = DH_GRP_MAX;
		break;
	default:
		fatal("protocol error during kex, no DH_GEX_REQUEST: %d", type);
	}
	ssh_packet_check_eom(ssh);

	if (omax < omin || onbits < omin || omax < onbits)
		fatal("DH_GEX_REQUEST, bad parameters: %d !< %d !< %d",
		    omin, onbits, omax);

	/* Contact privileged parent */
	dh = PRIVSEP(choose_dh(min, nbits, max));
	if (dh == NULL)
		ssh_packet_disconnect(ssh,
		    "Protocol error: no matching DH grp found");

	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	ssh_packet_start(ssh, SSH2_MSG_KEX_DH_GEX_GROUP);
	ssh_packet_put_bignum2(ssh, dh->p);
	ssh_packet_put_bignum2(ssh, dh->g);
	ssh_packet_send(ssh);

	/* flush */
	ssh_packet_write_wait(ssh);

	/* Compute our exchange value in parallel with the client */
	dh_gen_key(dh, kex->we_need * 8);

	kexgexs_state = xcalloc(1, sizeof(*kexgexs_state));
	kexgexs_state->omin = omin;
	kexgexs_state->omax = omax;
	kexgexs_state->min = min;
	kexgexs_state->max = max;
	kexgexs_state->onbits = onbits;
	kexgexs_state->dh = dh;
	kex->state = kexgexs_state;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &input_kex_dh_gex_init);
}

static void
input_kex_dh_gex_init(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	struct kexgexs_state *kexgexs_state = kex->state;
	BIGNUM *shared_secret = NULL, *dh_client_pub = NULL;
	struct sshkey *server_host_public, *server_host_private;
	DH *dh;
	u_int sbloblen, klen, slen, hashlen;
	u_char *kbuf, *hash, *signature = NULL, *server_host_key_blob = NULL;
	int omin, min, omax, max, onbits, kout, r;

	dh = kexgexs_state->dh;
	omin = kexgexs_state->omin;
	min = kexgexs_state->min;
	omax = kexgexs_state->omax;
	max = kexgexs_state->max;
	onbits = kexgexs_state->onbits;

	if (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL)
		fatal("Cannot load hostkey");
	server_host_public = kex->load_host_public_key(kex->hostkey_type, ssh);
	if (server_host_public == NULL)
		fatal("Unsupported hostkey type %d", kex->hostkey_type);
	server_host_private = kex->load_host_private_key(kex->hostkey_type, ssh);
	if (server_host_private == NULL)
		fatal("Missing private key for hostkey type %d",
		    kex->hostkey_type);

	/* key, cert */
	if ((dh_client_pub = BN_new()) == NULL)
		fatal("dh_client_pub == NULL");
	ssh_packet_get_bignum2(ssh, dh_client_pub);
	ssh_packet_check_eom(ssh);

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_client_pub= ");
	BN_print_fp(stderr, dh_client_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_client_pub));
#endif

#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, dh->pub_key);
	fprintf(stderr, "\n");
#endif
	if (!dh_pub_is_valid(dh, dh_client_pub))
		ssh_packet_disconnect(ssh,
		    "bad client public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	if ((kout = DH_compute_key(kbuf, dh_client_pub, dh)) < 0)
		fatal("DH_compute_key: failed");
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	if ((shared_secret = BN_new()) == NULL)
		fatal("kexgex_server: BN_new failed");
	if (BN_bin2bn(kbuf, kout, shared_secret) == NULL)
		fatal("kexgex_server: BN_bin2bn failed");
	memset(kbuf, 0, klen);
	xfree(kbuf);

	if ((r = sshkey_to_blob(server_host_public, &server_host_key_blob,
	    &sbloblen)) != 0)
		fatal("%s: sshkey_to_blob failed: %s", __func__, ssh_err(r));

	if (type == SSH2_MSG_KEX_DH_GEX_REQUEST_OLD)
		omin = min = omax = max = -1;

	/* calc H */
	kexgex_hash(
	    kex->evp_md,
	    kex->client_version_string,
	    kex->server_version_string,
	    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
	    buffer_ptr(&kex->my), buffer_len(&kex->my),
	    server_host_key_blob, sbloblen,
	    omin, onbits, omax,
	    dh->p, dh->g,
	    dh_client_pub,
	    dh->pub_key,
	    shared_secret,
	    &hash, &hashlen
	);
	BN_clear_free(dh_client_pub);

	/* save session id := H */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	/* sign H */
	if (PRIVSEP(sshkey_sign(server_host_private, &signature, &slen, hash,
	    hashlen, datafellows)) < 0)
		fatal("kexgex_server: sshkey_sign failed");

	/* destroy_sensitive_data(); */

	/* send server hostkey, DH pubkey 'f' and singed H */
	debug("SSH2_MSG_KEX_DH_GEX_REPLY sent");
	ssh_packet_start(ssh, SSH2_MSG_KEX_DH_GEX_REPLY);
	ssh_packet_put_string(ssh, server_host_key_blob, sbloblen);
	ssh_packet_put_bignum2(ssh, dh->pub_key);	/* f */
	ssh_packet_put_string(ssh, signature, slen);
	ssh_packet_send(ssh);

	xfree(signature);
	xfree(server_host_key_blob);
	/* have keys, free DH */
	DH_free(dh);

	kex_derive_keys(ssh, hash, hashlen, shared_secret);
	BN_clear_free(shared_secret);

	xfree(kex->state);
	kex->state = NULL;
	kex_finish(ssh);
}
