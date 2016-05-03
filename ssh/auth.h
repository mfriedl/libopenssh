/* $OpenBSD: auth.h,v 1.87 2016/03/07 19:02:43 djm Exp $ */

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
 *
 */

#ifndef AUTH_H
#define AUTH_H

#include <signal.h>

#include <openssl/rsa.h>

#include <bsd_auth.h>
#ifdef KRB5
#include <krb5.h>
#endif

struct ssh;
struct sshkey;

struct authctxt {
	sig_atomic_t	 success;
	int		 authenticated;	/* authenticated and alarms cancelled */
	int		 postponed;	/* authentication needs another step */
	int		 valid;		/* user exists and is allowed to login */
	int		 attempt;
	int		 failures;
	int		 server_caused_failure;
	int		 force_pwchange;
	char		*user;		/* username sent by the client */
	char		*service;
	struct passwd	*pw;		/* set if 'valid' */
	char		*style;
	void		*kbdintctxt;
	char		*info;		/* Extra info for next auth_log */
	auth_session_t	*as;
	char		**auth_methods;	/* modified from server config */
	u_int		 num_auth_methods;
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	char		*krb5_ticket_file;
#endif
	void		*methoddata;

	struct sshkey	**prev_userkeys;
	u_int		 nprev_userkeys;
};
/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

struct authmethod {
	char	*name;
	int	(*userauth)(struct ssh *);
	int	*enabled;
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
struct kbdintdevice {
	const char *name;
	void*	(*init_ctx)(struct authctxt*);
	int	(*query)(void *ctx, char **name, char **infotxt,
		    u_int *numprompts, char ***prompts, u_int **echo_on);
	int	(*respond)(void *ctx, u_int numresp, char **responses);
	void	(*free_ctx)(void *ctx);
};

int      auth_rhosts(struct passwd *, const char *);
int
auth_rhosts2(struct passwd *, const char *, const char *, const char *);

int	 auth_rhosts_rsa(struct authctxt *, char *, struct sshkey *);
int      auth_password(struct authctxt *, const char *);
int      auth_rsa(struct authctxt *, BIGNUM *);
int      auth_rsa_challenge_dialog(struct sshkey *);
BIGNUM	*auth_rsa_generate_challenge(struct sshkey *);
int	 auth_rsa_verify_response(struct sshkey *, BIGNUM *, u_char[]);
int	 auth_rsa_key_allowed(struct passwd *, BIGNUM *, struct sshkey **);

int	 auth_rhosts_rsa_key_allowed(struct passwd *, const char *,
    const char *, struct sshkey *);
int	 hostbased_key_allowed(struct passwd *, const char *, char *,
    struct sshkey *);
int	 user_key_allowed(struct passwd *, struct sshkey *, int);
void	 pubkey_auth_info(struct authctxt *, const struct sshkey *,
    const char *, ...)
	    __attribute__((__format__ (printf, 3, 4)));
void	 auth2_record_userkey(struct authctxt *, struct sshkey *);
int	 auth2_userkey_already_used(struct authctxt *, struct sshkey *);

struct stat;
int	 auth_secure_path(const char *, struct stat *, const char *, uid_t,
    char *, size_t);

#ifdef KRB5
int	auth_krb5(struct authctxt *authctxt, krb5_data *auth, char **client,
    krb5_data *);
int	auth_krb5_tgt(struct authctxt *authctxt, krb5_data *tgt);
int	auth_krb5_password(struct authctxt *authctxt, const char *password);
void	krb5_cleanup_proc(struct authctxt *authctxt);
#endif /* KRB5 */

void	do_authentication(struct ssh *);
void	do_authentication2(struct ssh *);

void	auth_info(struct authctxt *, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
void	auth_log(struct authctxt *, int, int, const char *, const char *);
void	auth_maxtries_exceeded(struct ssh *, struct authctxt *)
	    __attribute__((noreturn));
void	userauth_finish(struct ssh *, int, const char *, const char *);
int	auth_root_allowed(const char *);

char	*auth2_read_banner(void);
int	 auth2_methods_valid(const char *, int);
int	 auth2_update_methods_lists(struct authctxt *, const char *,
    const char *);
int	 auth2_setup_methods_lists(struct authctxt *);
int	 auth2_method_allowed(struct authctxt *, const char *, const char *);

void	privsep_challenge_enable(void);

int	auth2_challenge(struct ssh *, char *);
void	auth2_challenge_stop(struct ssh *);
int	bsdauth_query(void *, char **, char **, u_int *, char ***, u_int **);
int	bsdauth_respond(void *, u_int, char **);

int	allowed_user(struct passwd *);
struct passwd * getpwnamallow(const char *user);

char	*get_challenge(struct authctxt *);
int	verify_response(struct authctxt *, const char *);

char	*expand_authorized_keys(const char *, struct passwd *pw);
char	*authorized_principals_file(struct passwd *);

FILE	*auth_openkeyfile(const char *, struct passwd *, int);
FILE	*auth_openprincipals(const char *, struct passwd *, int);
int	 auth_key_is_revoked(struct sshkey *);

const char	*auth_get_canonical_hostname(struct ssh *, int);

HostStatus
check_key_in_hostfiles(struct passwd *, struct sshkey *, const char *,
    const char *, const char *);

/* hostkey handling */
struct sshkey	*get_hostkey_by_index(u_int, struct ssh *);
struct sshkey	*get_hostkey_public_by_index(int, struct ssh *);
struct sshkey	*get_hostkey_public_by_type(int, int, struct ssh *);
struct sshkey	*get_hostkey_private_by_type(int, int, struct ssh *);
int		 get_hostkey_index(struct sshkey *, int, struct ssh *);
int	 ssh1_session_key(BIGNUM *);
int	 sshd_hostkey_sign(struct sshkey *, struct sshkey *,
    u_char **, size_t *, const u_char *, size_t, const char *, u_int);

/* debug messages during authentication */
void	 auth_debug_add(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	 auth_debug_send(void);
void	 auth_debug_reset(void);

struct passwd *fakepw(void);

#endif
