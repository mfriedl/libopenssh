/* 	$OpenBSD$ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
struct sshbuf *load_file(const char *name);

/* Load a text file into a buffer */
struct sshbuf *load_text_file(const char *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(const char *name);

