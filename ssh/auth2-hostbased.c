/* $OpenBSD: auth2-hostbased.c,v 1.14 2010/08/04 05:42:47 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include <pwd.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "pathnames.h"
#include "err.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;

static int
userauth_hostbased(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Buffer b;
	struct sshkey *key = NULL;
	char *pkalg, *cuser, *chost, *service;
	u_char *pkblob, *sig;
	u_int alen, blen, slen;
	int r, pktype, authenticated = 0;

	if (!authctxt->valid) {
		debug2("%s: disabled because of invalid user", __func__);
		return 0;
	}
	pkalg = ssh_packet_get_string(ssh, &alen);
	pkblob = ssh_packet_get_string(ssh, &blen);
	chost = ssh_packet_get_string(ssh, NULL);
	cuser = ssh_packet_get_string(ssh, NULL);
	sig = ssh_packet_get_string(ssh, &slen);

	debug("%s: cuser %s chost %s pkalg %s slen %d", __func__,
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	buffer_init(&b);
	buffer_append(&b, sig, slen);
	buffer_dump(&b);
	buffer_free(&b);
#endif
	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		logit("%s: unsupported public key algorithm: %s",
		    __func__, pkalg);
		goto done;
	}
	if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error("%s: key_from_blob: %s", __func__, ssh_err(r));
		goto done;
	}
	if (key == NULL) {
		error("%s: cannot decode key: %s", __func__, pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("%s: type mismatch for decoded key "
		    "(received %d, expected %d)", __func__, key->type, pktype);
		goto done;
	}
	service = ssh->compat & SSH_BUG_HBSERVICE ? "ssh-userauth" :
	    authctxt->service;
	buffer_init(&b);
	buffer_put_string(&b, session_id2, session_id2_len);
	/* reconstruct packet */
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->user);
	buffer_put_cstring(&b, service);
	buffer_put_cstring(&b, "hostbased");
	buffer_put_string(&b, pkalg, alen);
	buffer_put_string(&b, pkblob, blen);
	buffer_put_cstring(&b, chost);
	buffer_put_cstring(&b, cuser);
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	/* test for allowed key and correct signature */
	authenticated = 0;
	if (PRIVSEP(hostbased_key_allowed(authctxt->pw, cuser, chost, key)) &&
	    PRIVSEP(sshkey_verify(key, sig, slen,
	    buffer_ptr(&b), buffer_len(&b), ssh->compat)) == 0)
		authenticated = 1;

	buffer_free(&b);
done:
	debug2("%s: authenticated %d", __func__, authenticated);
	if (key != NULL)
		sshkey_free(key);
	xfree(pkalg);
	xfree(pkblob);
	xfree(cuser);
	xfree(chost);
	xfree(sig);
	return authenticated;
}

/* return 1 if given hostkey is allowed */
int
hostbased_key_allowed(struct passwd *pw, const char *cuser, char *chost,
    struct sshkey *key)
{
	const char *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	int len;
	char *fp;

	if (auth_key_is_revoked(key))
		return 0;

	resolvedname = get_canonical_hostname(options.use_dns);
	ipaddr = get_remote_ipaddr();

	debug2("userauth_hostbased: chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	if (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	if (options.hostbased_uses_name_from_packet_only) {
		if (auth_rhosts2(pw, cuser, chost, chost) == 0)
			return 0;
		lookup = chost;
	} else {
		if (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		if (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0)
			return 0;
		lookup = resolvedname;
	}
	debug2("userauth_hostbased: access allowed by auth_rhosts2");

	if (sshkey_is_cert(key) && 
	    sshkey_cert_check_authority(key, 1, 0, lookup, &reason)) {
		error("%s", reason);
		auth_debug_add("%s", reason);
		return 0;
	}

	host_status = check_key_in_hostfiles(pw, key, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? NULL : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	if (host_status == HOST_NEW) {
		host_status = check_key_in_hostfiles(pw, key, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? NULL :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	if (host_status == HOST_OK) {
		if (sshkey_is_cert(key)) {
			fp = sshkey_fingerprint(key->cert->signature_key,
			    SSH_FP_MD5, SSH_FP_HEX);
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", key->cert->key_id,
			    sshkey_type(key->cert->signature_key), fp,
			    cuser, lookup);
		} else {
			fp = sshkey_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(key), fp, cuser, lookup);
		}
		xfree(fp);
	}

	return (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	"hostbased",
	userauth_hostbased,
	&options.hostbased_authentication
};
