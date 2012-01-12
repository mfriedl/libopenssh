/* 	$OpenBSD$ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include "test_helper.h"

#include "err.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#include "key.h"


void sshkey_tests(void);

void
sshkey_tests(void)
{
	struct sshkey *k1, *kr, *kd, *ke;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, NULL);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(KEY_UNSPEC);
	ASSERT_PTR_NE(k1, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new/free KEY_RSA1");
	k1 = sshkey_new(KEY_RSA1);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(k1->rsa, NULL);
	ASSERT_PTR_NE(k1->rsa->n, NULL);
	ASSERT_PTR_EQ(k1->rsa->p, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(KEY_RSA);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(k1->rsa, NULL);
	ASSERT_PTR_NE(k1->rsa->n, NULL);
	ASSERT_PTR_EQ(k1->rsa->p, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new/free KEY_DSA");
	k1 = sshkey_new(KEY_DSA);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(k1->dsa, NULL);
	ASSERT_PTR_NE(k1->dsa->g, NULL);
	ASSERT_PTR_EQ(k1->dsa->priv_key, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(KEY_ECDSA);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_EQ(k1->ecdsa, NULL);  /* Can't allocate without NID */
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new_private KEY_RSA");
	k1 = sshkey_new_private(KEY_RSA);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(k1->rsa, NULL);
	ASSERT_PTR_NE(k1->rsa->n, NULL);
	ASSERT_PTR_NE(k1->rsa->p, NULL);
	ASSERT_INT_EQ(sshkey_add_private(k1), 0);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("new_private KEY_DSA");
	k1 = sshkey_new_private(KEY_DSA);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(k1->dsa, NULL);
	ASSERT_PTR_NE(k1->dsa->g, NULL);
	ASSERT_PTR_NE(k1->dsa->priv_key, NULL);
	ASSERT_INT_EQ(sshkey_add_private(k1), 0);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(KEY_RSA, 128, &k1),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(k1, NULL);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(KEY_RSA, 1 << 20, &k1),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(k1, NULL);
	TEST_DONE();

	TEST_START("generate KEY_DSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(KEY_DSA, 2048, &k1),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(k1, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(KEY_ECDSA, 42, &k1),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(k1, NULL);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(KEY_RSA, 768, &kr), 0);
	ASSERT_PTR_NE(kr, NULL);
	ASSERT_PTR_NE(kr->rsa, NULL);
	ASSERT_PTR_NE(kr->rsa->n, NULL);
	ASSERT_PTR_NE(kr->rsa->p, NULL);
	ASSERT_INT_EQ(BN_num_bits(kr->rsa->n), 768);
	TEST_DONE();

	TEST_START("generate KEY_DSA");
	ASSERT_INT_EQ(sshkey_generate(KEY_DSA, 1024, &kd), 0);
	ASSERT_PTR_NE(kd, NULL);
	ASSERT_PTR_NE(kd->dsa, NULL);
	ASSERT_PTR_NE(kd->dsa->g, NULL);
	ASSERT_PTR_NE(kd->dsa->priv_key, NULL);
	TEST_DONE();

	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(KEY_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, NULL);
	ASSERT_PTR_NE(ke->ecdsa, NULL);
	ASSERT_PTR_NE(EC_KEY_get0_public_key(ke->ecdsa), NULL);
	ASSERT_PTR_NE(EC_KEY_get0_private_key(ke->ecdsa), NULL);
	TEST_DONE();

	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_demote(kr, &k1), 0);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, KEY_RSA);
	ASSERT_PTR_NE(k1->rsa, NULL);
	ASSERT_PTR_NE(k1->rsa->n, NULL);
	ASSERT_PTR_EQ(k1->rsa->p, NULL);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("demote KEY_DSA");
	ASSERT_INT_EQ(sshkey_demote(kd, &k1), 0);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(kd, k1);
	ASSERT_INT_EQ(k1->type, KEY_DSA);
	ASSERT_PTR_NE(k1->dsa, NULL);
	ASSERT_PTR_NE(k1->dsa->g, NULL);
	ASSERT_PTR_EQ(k1->dsa->priv_key, NULL);
	TEST_DONE();

	TEST_START("equal KEY_DSA/demoted KEY_DSA");
	ASSERT_INT_EQ(sshkey_equal(kd, k1), 1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_demote(ke, &k1), 0);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, KEY_ECDSA);
	ASSERT_PTR_NE(k1->ecdsa, NULL);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_KEY_get0_public_key(ke->ecdsa), NULL);
	ASSERT_PTR_EQ(EC_KEY_get0_private_key(k1->ecdsa), NULL);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	TEST_DONE();

	TEST_START("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(KEY_RSA, 768, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	ASSERT_INT_EQ(sshkey_generate(KEY_DSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, k1), 0);
	sshkey_free(k1);
	ASSERT_INT_EQ(sshkey_generate(KEY_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	TEST_DONE();

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);

}
