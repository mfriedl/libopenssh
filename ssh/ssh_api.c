#include "ssh1.h" /* For SSH_MSG_NONE */
#include "ssh_api.h"
#include "compat.h"
#include "log.h"
#include "authfile.h"
#include "key.h"
#include "misc.h"
#include "ssh1.h"
#include "ssh2.h"
#include "version.h"
#include "xmalloc.h"

#include <string.h>

void	_ssh_exchange_banner(struct ssh *);
char	*_ssh_send_banner(struct ssh *);
char	*_ssh_read_banner(struct ssh *);
int	_ssh_verify_host_key(struct sshkey *, struct ssh *);
struct sshkey *_ssh_host_public_key(int, struct ssh *);
struct sshkey *_ssh_host_private_key(int, struct ssh *);

/*
 * stubs for the server side implementation of kex.
 * disable privsep so our stubs will never be called.
 */
int	use_privsep = 0;
int	mm_sshkey_sign(struct sshkey *, u_char **, u_int *,
    u_char *, u_int, u_int);
DH	*mm_choose_dh(int, int, int);

int
mm_sshkey_sign(struct sshkey *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen, u_int compat)
{
	return (-1);
}

DH *
mm_choose_dh(int min, int nbits, int max)
{
	return (NULL);
}

/* API */

struct ssh *
ssh_init(int is_server, struct kex_params *kex_params)
{
	struct ssh *ssh;
	static int called;

	if (!called) {
		OpenSSL_add_all_algorithms();
		called = 1;
	}

	ssh = ssh_packet_set_connection(NULL, -1, -1);
	if (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	ssh->kex = kex_new(ssh, kex_params->proposal);
	ssh->kex->server = is_server;
	if (is_server) {
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kexdh_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kexdh_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kexecdh_server;
		ssh->kex->load_host_public_key=&_ssh_host_public_key;
		ssh->kex->load_host_private_key=&_ssh_host_private_key;
	} else {
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kexecdh_client;
		ssh->kex->verify_host_key =&_ssh_verify_host_key;
	}
	return (ssh);
}

void
ssh_free(struct ssh *ssh)
{
	ssh_packet_close(ssh);
	if (ssh->kex)
		xfree(ssh->kex);
	xfree(ssh);
}

/* Returns -1 on error, 0 otherwise */
int
ssh_add_hostkey(struct ssh* ssh, char *key)
{
	struct sshkey *parsed_key, *pubkey;
	struct key_entry *k;
	Buffer key_buf;

	if (ssh->kex->server) {
		/* Parse private key */
		buffer_init(&key_buf);
		buffer_append(&key_buf, key, strlen(key));
		parsed_key = key_parse_private(&key_buf, "hostkey", "", NULL);
		buffer_free(&key_buf);

		if (parsed_key != NULL) {
			if (sshkey_from_private(parsed_key, &pubkey) != 0) {
				sshkey_free(parsed_key);
				return (-1);
			}
			k = xmalloc(sizeof(*k));
			k->key = parsed_key;
			TAILQ_INSERT_TAIL(&ssh->private_keys, k, next);

			/* add the public key, too */
			k = xmalloc(sizeof(*k));
			k->key = pubkey;
			TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);

			return (0);
		}
	} else {
		/* Parse public key */
		if ((parsed_key = sshkey_new(KEY_UNSPEC)) == NULL)
			return -1;
		if (sshkey_read(parsed_key, &key) != 0) {
			k = xmalloc(sizeof(*k));
			k->key = parsed_key;
			TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);

			return (0);
		} else {
			sshkey_free(parsed_key);
		}
	}

	return (-1);
}

void
ssh_input_append(struct ssh* ssh, const char *data, u_int len)
{
	buffer_append(ssh_packet_get_input(ssh), data, len);
}

int
ssh_packet_get(struct ssh *ssh)
{
	int type;                                                       
	u_int32_t seqnr;                                                

	if (ssh->kex->client_version_string == NULL ||
	    ssh->kex->server_version_string == NULL) {
		_ssh_exchange_banner(ssh);
		return (SSH_MSG_NONE);
	}
	/*
	 * Try to read a packet. Returns SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	type = ssh_packet_read_poll2(ssh, &seqnr);
	/*
	 * If we enough data and we have a dispatch function, call the
	 * function and return SSH_MSG_NONE. Otherwise return the packet type to
	 * the caller so it can decide how to go on.
	 *
	 * We will only call the dispatch function for:
	 *     20-29    Algorithm negotiation
	 *     30-49    Key exchange method specific (numbers can be reused for
	 *              different authentication methods)
	 */
	if (type > 0 && type < DISPATCH_MAX &&
	    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
	    ssh->dispatch[type] != NULL) {
		(*ssh->dispatch[type])(type, seqnr, ssh);
		return (SSH_MSG_NONE);
	}
	return (type);
}

void *
ssh_packet_payload(struct ssh* ssh, u_int *len)
{
	return (ssh_packet_get_raw(ssh, len));
}

void
ssh_packet_put(struct ssh* ssh, int type, const char *data, u_int len)
{
	ssh_packet_start(ssh, type);
	ssh_packet_put_raw(ssh, data, len);
	ssh_packet_send(ssh);
}

void *
ssh_output_ptr(struct ssh* ssh, u_int *len)
{
	Buffer *output = ssh_packet_get_output(ssh);

	*len = buffer_len(output);
	return (buffer_ptr(output));
}

void
ssh_output_consume(struct ssh* ssh, u_int len)
{
	buffer_consume(ssh_packet_get_output(ssh), len);
}

int
ssh_output_space(struct ssh* ssh, u_int len)
{
	return (buffer_check_alloc(ssh_packet_get_output(ssh), len));
}

int
ssh_input_space(struct ssh* ssh, u_int len)
{
	return (buffer_check_alloc(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
char *
_ssh_read_banner(struct ssh *ssh)
{
	Buffer *input;
	char c, *s, buf[256], remote_version[256];	/* must be same size! */
	int remote_major, remote_minor;
	u_int i, n, j, len;

	input = ssh_packet_get_input(ssh);
	len = buffer_len(input);
	s = buffer_ptr(input);
	for (j = n = 0;;) {
		for (i = 0; i < sizeof(buf) - 1; i++) {
			if (j >= len)
				return (NULL);
			c = s[j++];
			if (c == '\r') {
				buf[i] = '\n';
				buf[i + 1] = 0;
				continue;		/**XXX wait for \n */
			}
			if (c == '\n') {
				buf[i + 1] = 0;
				break;
			}
			buf[i] = c;
		}
		buf[sizeof(buf) - 1] = 0;
		if (strncmp(buf, "SSH-", 4) == 0)
			break;
		debug("ssh_exchange_identification: %s", buf);
		if (++n > 65536)
			fatal("ssh_exchange_identification: "
			    "No banner received");
	}
	buffer_consume(input, j);

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	if (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3)
		fatal("Bad remote protocol version identification: '%.100s'", buf);
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	ssh->datafellows = compat_datafellows(remote_version);
	if  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	if (remote_major != 2)
		fatal("Protocol major versions differ: 2 vs. %d", remote_major);
	enable_compat20();
	chop(buf);
	debug("Remote version string %.100s", buf);
	return (xstrdup(buf));
}

/* Send our own protocol version identification. */
char *
_ssh_send_banner(struct ssh *ssh)
{
	char buf[256];

	snprintf(buf, sizeof buf, "SSH-2.0-%.100s\r\n", SSH_VERSION);
	buffer_append(ssh_packet_get_output(ssh), buf, strlen(buf));
	chop(buf);
	debug("Local version string %.100s", buf);
	return (xstrdup(buf));
}

void
_ssh_exchange_banner(struct ssh *ssh)
{
	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */
	if (ssh->kex->server) {
		if (ssh->kex->server_version_string == NULL)
			ssh->kex->server_version_string = _ssh_send_banner(ssh);
		if (ssh->kex->server_version_string != NULL &&
		    ssh->kex->client_version_string == NULL)
			ssh->kex->client_version_string = _ssh_read_banner(ssh);
	} else {
		if (ssh->kex->server_version_string == NULL)
			ssh->kex->server_version_string = _ssh_read_banner(ssh);
		if (ssh->kex->server_version_string != NULL &&
		    ssh->kex->client_version_string == NULL)
			ssh->kex->client_version_string = _ssh_send_banner(ssh);
	}
	/* start initial kex as soon as we have exchanged the banners */
	if (ssh->kex->server_version_string != NULL &&
	    ssh->kex->client_version_string != NULL)
		kex_send_kexinit(ssh);
}

struct sshkey *
_ssh_host_public_key(int type, struct ssh *ssh)
{
	struct key_entry *k;

	debug3("%s: need %d", __func__, type);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3("%s: check %s", __func__, sshkey_type(k->key));
                if (k->key->type == type)
                        return (k->key);
	}
	return (NULL);
}

struct sshkey *
_ssh_host_private_key(int type, struct ssh *ssh)
{
	struct key_entry *k;

	datafellows = ssh->datafellows;	/* XXX */
	debug3("%s: need %d", __func__, type);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3("%s: check %s", __func__, sshkey_type(k->key));
                if (k->key->type == type)
                        return (k->key);
	}
	return (NULL);
}

int
_ssh_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3("%s: need %s", __func__, sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3("%s: check %s", __func__, sshkey_type(k->key));
                if (sshkey_equal_public(hostkey, k->key))
                        return (0);	/* ok */
	}
	return (-1);	/* failed */
}
