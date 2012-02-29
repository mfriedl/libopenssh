/* 	$OpenBSD$ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#include <openssl/evp.h>

#include "test_helper.h"

void sshkey_tests(void);
void sshkey_file_tests(void);

void
tests(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_CRYPTO_strings();

	sshkey_tests();
	sshkey_file_tests();
}
