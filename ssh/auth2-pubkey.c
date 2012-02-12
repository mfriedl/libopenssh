/* $OpenBSD: auth2-pubkey.c,v 1.30 2011/09/25 05:44:47 djm Exp $ */
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
#include <sys/stat.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "pathnames.h"
#include "uidswap.h"
#include "auth-options.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "misc.h"
#include "authfile.h"
#include "match.h"
#include "err.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;

static int
userauth_pubkey(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Buffer b;
	struct sshkey *key = NULL;
	char *pkalg;
	u_char *pkblob, *sig;
	u_int alen, blen, slen;
	int r, have_sig, pktype;
	int authenticated = 0;

	if (!authctxt->valid) {
		debug2("%s: disabled because of invalid user", __func__);
		return 0;
	}
	have_sig = ssh_packet_get_char(ssh);
	if (ssh->compat & SSH_BUG_PKAUTH) {
		debug2("%s: SSH_BUG_PKAUTH", __func__);
		/* no explicit pkalg given */
		pkblob = ssh_packet_get_string(ssh, &blen);
		buffer_init(&b);
		buffer_append(&b, pkblob, blen);
		/* so we have to extract the pkalg from the pkblob */
		pkalg = buffer_get_string(&b, &alen);
		buffer_free(&b);
	} else {
		pkalg = ssh_packet_get_string(ssh, &alen);
		pkblob = ssh_packet_get_string(ssh, &blen);
	}
	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		logit("%s: unsupported public key algorithm: %s", __func__,
		    pkalg);
		goto done;
	}
	if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error("%s: could not parse key: %s", __func__, ssh_err(r));
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
	if (have_sig) {
		sig = ssh_packet_get_string(ssh, &slen);
		ssh_packet_check_eom(ssh);
		buffer_init(&b);
		if (ssh->compat & SSH_OLD_SESSIONID) {
			buffer_append(&b, session_id2, session_id2_len);
		} else {
			buffer_put_string(&b, session_id2, session_id2_len);
		}
		/* reconstruct packet */
		buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&b, authctxt->user);
		buffer_put_cstring(&b,
		    ssh->compat & SSH_BUG_PKSERVICE ?
		    "ssh-userauth" :
		    authctxt->service);
		if (ssh->compat & SSH_BUG_PKAUTH) {
			buffer_put_char(&b, have_sig);
		} else {
			buffer_put_cstring(&b, "publickey");
			buffer_put_char(&b, have_sig);
			buffer_put_cstring(&b, pkalg);
		}
		buffer_put_string(&b, pkblob, blen);
#ifdef DEBUG_PK
		buffer_dump(&b);
#endif
		/* test for correct signature */
		authenticated = 0;
		if (PRIVSEP(user_key_allowed(authctxt->pw, key)) &&
		    PRIVSEP(sshkey_verify(key, sig, slen, buffer_ptr(&b),
		    buffer_len(&b), ssh->compat)) == 0)
			authenticated = 1;
		buffer_free(&b);
		xfree(sig);
	} else {
		debug("test whether pkalg/pkblob are acceptable");
		ssh_packet_check_eom(ssh);

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		if (PRIVSEP(user_key_allowed(authctxt->pw, key))) {
			ssh_packet_start(ssh, SSH2_MSG_USERAUTH_PK_OK);
			ssh_packet_put_string(ssh, pkalg, alen);
			ssh_packet_put_string(ssh, pkblob, blen);
			ssh_packet_send(ssh);
			ssh_packet_write_wait(ssh);
			authctxt->postponed = 1;
		}
	}
	if (authenticated != 1)
		auth_clear_options();
done:
	debug2("%s: authenticated %d pkalg %s", __func__, authenticated, pkalg);
	if (key != NULL)
		sshkey_free(key);
	xfree(pkalg);
	xfree(pkblob);
	return authenticated;
}

static int
match_principals_option(const char *principal_list, struct sshkey_cert *cert)
{
	char *result;
	u_int i;

	/* XXX percent_expand() sequences for authorized_principals? */

	for (i = 0; i < cert->nprincipals; i++) {
		if ((result = match_list(cert->principals[i],
		    principal_list, NULL)) != NULL) {
			debug3("matched principal from key options \"%.100s\"",
			    result);
			xfree(result);
			return 1;
		}
	}
	return 0;
}

static int
match_principals_file(char *file, struct passwd *pw, struct sshkey_cert *cert)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES], *cp, *ep, *line_opts;
	u_long linenum = 0;
	u_int i;

	temporarily_use_uid(pw);
	debug("trying authorized principals file %s", file);
	if ((f = auth_openprincipals(file, pw, options.strict_modes)) == NULL) {
		restore_uid();
		return 0;
	}
	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		/* Skip leading whitespace. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		if ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		if (!*cp || *cp == '\n')
			continue;
		/* Trim trailing whitespace. */
		ep = cp + strlen(cp) - 1;
		while (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
			*ep-- = '\0';
		/*
		 * If the line has internal whitespace then assume it has
		 * key options.
		 */
		line_opts = NULL;
		if ((ep = strrchr(cp, ' ')) != NULL ||
		    (ep = strrchr(cp, '\t')) != NULL) {
			for (; *ep == ' ' || *ep == '\t'; ep++)
				;
			line_opts = cp;
			cp = ep;
		}
		for (i = 0; i < cert->nprincipals; i++) {
			if (strcmp(cp, cert->principals[i]) == 0) {
				debug3("matched principal \"%.100s\" "
				    "from file \"%s\" on line %lu",
			    	    cert->principals[i], file, linenum);
				if (auth_parse_options(pw, line_opts,
				    file, linenum) != 1)
					continue;
				fclose(f);
				restore_uid();
				return 1;
			}
		}
	}
	fclose(f);
	restore_uid();
	return 0;
}	

/* return 1 if user allows given key */
static int
user_key_allowed2(struct passwd *pw, struct sshkey *key, char *file)
{
	char line[SSH_MAX_PUBKEY_BYTES];
	const char *reason;
	int found_key = 0;
	FILE *f;
	u_long linenum = 0;
	struct sshkey *found = NULL;
	char *fp;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	f = auth_openkeyfile(file, pw, options.strict_modes);

	if (!f) {
		restore_uid();
		return 0;
	}

	found_key = 0;
	found = sshkey_new(sshkey_is_cert(key) ? KEY_UNSPEC : key->type);
	if (found == NULL)
		goto done;

	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		char *cp, *key_options = NULL;

		auth_clear_options();

		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		if (sshkey_read(found, &cp) != 0) {
			/* no key?  check if there are options for this key */
			int quoted = 0;
			debug2("user_key_allowed: check options: '%s'", cp);
			key_options = cp;
			for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
				if (*cp == '\\' && cp[1] == '"')
					cp++;	/* Skip both */
				else if (*cp == '"')
					quoted = !quoted;
			}
			/* Skip remaining whitespace. */
			for (; *cp == ' ' || *cp == '\t'; cp++)
				;
			if (sshkey_read(found, &cp) != 0) {
				debug2("user_key_allowed: advance: '%s'", cp);
				/* still no key?  advance to next line*/
				continue;
			}
		}
		if (sshkey_is_cert(key)) {
			if (!sshkey_equal(found, key->cert->signature_key))
				continue;
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (!key_is_cert_authority)
				continue;
			fp = sshkey_fingerprint(found, SSH_FP_MD5,
			    SSH_FP_HEX);
			debug("matching CA found: file %s, line %lu, %s %s",
			    file, linenum, sshkey_type(found), fp);
			/*
			 * If the user has specified a list of principals as
			 * a key option, then prefer that list to matching
			 * their username in the certificate principals list.
			 */
			if (authorized_principals != NULL &&
			    !match_principals_option(authorized_principals,
			    key->cert)) {
				reason = "Certificate does not contain an "
				    "authorized principal";
 fail_reason:
				xfree(fp);
				error("%s", reason);
				auth_debug_add("%s", reason);
				continue;
			}
			if (sshkey_cert_check_authority(key, 0, 0,
			    authorized_principals == NULL ? pw->pw_name : NULL,
			    &reason) != 0)
				goto fail_reason;
			if (auth_cert_options(key, pw) != 0) {
				xfree(fp);
				continue;
			}
			verbose("Accepted certificate ID \"%s\" "
			    "signed by %s CA %s via %s", key->cert->key_id,
			    sshkey_type(found), fp, file);
			xfree(fp);
			found_key = 1;
			break;
		} else if (sshkey_equal(found, key)) {
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (key_is_cert_authority)
				continue;
			found_key = 1;
			debug("matching key found: file %s, line %lu",
			    file, linenum);
			fp = sshkey_fingerprint(found, SSH_FP_MD5, SSH_FP_HEX);
			verbose("Found matching %s key: %s",
			    sshkey_type(found), fp);
			xfree(fp);
			break;
		}
	}
 done:
	restore_uid();
	fclose(f);
	if (found != NULL)
		sshkey_free(found);
	if (!found_key)
		debug2("key not found");
	return found_key;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
static int
user_cert_trusted_ca(struct passwd *pw, struct sshkey *key)
{
	char *ca_fp, *principals_file = NULL;
	const char *reason;
	int ret = 0;

	if (!sshkey_is_cert(key) || options.trusted_user_ca_keys == NULL)
		return 0;

	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    SSH_FP_MD5, SSH_FP_HEX);

	if (key_in_file(key->cert->signature_key,
	    options.trusted_user_ca_keys, 1) != 1) {
		debug2("%s: CA %s %s is not listed in %s", __func__,
		    sshkey_type(key->cert->signature_key), ca_fp,
		    options.trusted_user_ca_keys);
		goto out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	if ((principals_file = authorized_principals_file(pw)) != NULL) {
		if (!match_principals_file(principals_file, pw, key->cert)) {
			reason = "Certificate does not contain an "
			    "authorized principal";
 fail_reason:
			error("%s", reason);
			auth_debug_add("%s", reason);
			goto out;
		}
	}
	if (sshkey_cert_check_authority(key, 0, 1,
	    principals_file == NULL ? pw->pw_name : NULL, &reason) != 0)
		goto fail_reason;
	if (auth_cert_options(key, pw) != 0)
		goto out;

	verbose("Accepted certificate ID \"%s\" signed by %s CA %s via %s",
	    key->cert->key_id, sshkey_type(key->cert->signature_key), ca_fp,
	    options.trusted_user_ca_keys);
	ret = 1;

 out:
	if (principals_file != NULL)
		xfree(principals_file);
	if (ca_fp != NULL)
		xfree(ca_fp);
	return ret;
}

/* check whether given key is in .ssh/authorized_keys* */
int
user_key_allowed(struct passwd *pw, struct sshkey *key)
{
	u_int success, i;
	char *file;

	if (auth_key_is_revoked(key))
		return 0;
	if (sshkey_is_cert(key) &&
	    auth_key_is_revoked(key->cert->signature_key))
		return 0;

	success = user_cert_trusted_ca(pw, key);
	if (success)
		return success;

	for (i = 0; !success && i < options.num_authkeys_files; i++) {
		file = expand_authorized_keys(
		    options.authorized_keys_files[i], pw);
		success = user_key_allowed2(pw, key, file);
		xfree(file);
	}

	return success;
}

Authmethod method_pubkey = {
	"publickey",
	userauth_pubkey,
	&options.pubkey_authentication
};
