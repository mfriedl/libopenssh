/* $OpenBSD: kexecdhc.c,v 1.2 2010/09/22 05:01:29 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/ecdh.h>

#include "xmalloc.h"
#include "buffer.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "dispatch.h"
#include "compat.h"
#include "err.h"

static int input_kex_ecdh_reply(int, u_int32_t, struct ssh *);

void
kexecdh_client(struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	EC_KEY *client_key;
	const EC_GROUP *group;
	int curve_nid;

	if ((curve_nid = kex_ecdh_name_to_nid(kex->name)) == -1)
		fatal("%s: unsupported ECDH curve \"%s\"", __func__, kex->name);
	if ((client_key = EC_KEY_new_by_curve_name(curve_nid)) == NULL)
		fatal("%s: EC_KEY_new_by_curve_name failed", __func__);
	if (EC_KEY_generate_key(client_key) != 1)
		fatal("%s: EC_KEY_generate_key failed", __func__);
	group = EC_KEY_get0_group(client_key);

	ssh_packet_start(ssh, SSH2_MSG_KEX_ECDH_INIT);
	ssh_packet_put_ecpoint(ssh, group, EC_KEY_get0_public_key(client_key));
	ssh_packet_send(ssh);
	debug("sending SSH2_MSG_KEX_ECDH_INIT");

#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif

	kex->ec_client_key = client_key;
	kex->ec_group = group;

	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &input_kex_ecdh_reply);
}

static int
input_kex_ecdh_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	Kex *kex = ssh->kex;
	const EC_GROUP *group;
	EC_POINT *server_public;
	EC_KEY *client_key;
	BIGNUM *shared_secret;
	struct sshkey *server_host_key;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char *kbuf, *hash;
	u_int klen, slen, sbloblen, hashlen;
	int r;

	group = kex->ec_group;
	client_key = kex->ec_client_key;

	/* hostkey */
	server_host_key_blob = ssh_packet_get_string(ssh, &sbloblen);
	if ((r = sshkey_from_blob(server_host_key_blob, sbloblen,
	    &server_host_key)) != 0)
		fatal("%s: could not parse server host key: %s",
		    __func__, ssh_err(r));
	if (server_host_key == NULL)
		fatal("cannot decode server_host_key_blob");
	if (server_host_key->type != kex->hostkey_type)
		fatal("type mismatch for decoded server_host_key_blob");
	if (kex->verify_host_key == NULL)
		fatal("cannot verify server_host_key");
	if (kex->verify_host_key(server_host_key, ssh) == -1)
		fatal("server_host_key verification failed");

	/* Q_S, server public key */
	if ((server_public = EC_POINT_new(group)) == NULL)
		fatal("%s: EC_POINT_new failed", __func__);
	ssh_packet_get_ecpoint(ssh, group, server_public);

	if (sshkey_ec_validate_public(group, server_public) != 0)
		fatal("%s: invalid server public key", __func__);

#ifdef DEBUG_KEXECDH
	fputs("server public key:\n", stderr);
	sshkey_dump_ec_point(group, server_public);
#endif

	/* signed H */
	signature = ssh_packet_get_string(ssh, &slen);
	ssh_packet_check_eom(ssh);

	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	kbuf = xmalloc(klen);
	if (ECDH_compute_key(kbuf, klen, server_public,
	    client_key, NULL) != (int)klen)
		fatal("%s: ECDH_compute_key failed", __func__);

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((shared_secret = BN_new()) == NULL)
		fatal("%s: BN_new failed", __func__);
	if (BN_bin2bn(kbuf, klen, shared_secret) == NULL)
		fatal("%s: BN_bin2bn failed", __func__);
	memset(kbuf, 0, klen);
	xfree(kbuf);

	/* calc and verify H */
	kex_ecdh_hash(
	    kex->evp_md,
	    group,
	    kex->client_version_string,
	    kex->server_version_string,
	    buffer_ptr(&kex->my), buffer_len(&kex->my),
	    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
	    server_host_key_blob, sbloblen,
	    EC_KEY_get0_public_key(client_key),
	    server_public,
	    shared_secret,
	    &hash, &hashlen
	);
	xfree(server_host_key_blob);
	EC_POINT_clear_free(server_public);
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash,
	    hashlen, datafellows)) != 0)
		fatal("key_verify failed for server_host_key: %s", ssh_err(r));
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
	kex_finish(ssh);
	return 0;
}
