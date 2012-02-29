/* 	$OpenBSD$ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/objects.h>

#include "test_helper.h"

#include "err.h"
#include "authfile.h"
#include "key.h"
#include "sshbuf.h"

#include "common.h"

void sshkey_fuzz_tests(void);

static void
onerror(void *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((struct fuzz *)fuzz);
}

void
sshkey_fuzz_tests(void)
{
	struct sshkey *k1;
	struct sshbuf *buf, *fuzzed;
	struct fuzz *fuzz;
	int r;

	TEST_START("fuzz RSA1 private");
	buf = load_file("rsa1_1");
	fuzz = fuzz_begin(FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END,
	    sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), NULL);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		if (sshkey_parse_private(fuzzed, "", "key", &k1, NULL) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA1 public");
	buf = load_file("rsa1_1_pw");
	fuzz = fuzz_begin(FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END,
	    sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_public_rsa1(buf, &k1, NULL), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), NULL);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		if (sshkey_parse_public_rsa1(fuzzed, &k1, NULL) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), NULL);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		if (sshkey_parse_private(fuzzed, "", "key", &k1, NULL) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz DSA private");
	buf = load_file("dsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), NULL);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		if (sshkey_parse_private(fuzzed, "", "key", &k1, NULL) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), NULL);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		if (sshkey_parse_private(fuzzed, "", "key", &k1, NULL) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshbuf_reset(buf);
	ASSERT_INT_EQ(sshkey_to_blob_buf(k1, buf), 0);
	sshkey_free(k1);
	fuzz = fuzz_begin(FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END,
	    sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		if (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz DSA public");
	buf = load_file("dsa_1");
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshbuf_reset(buf);
	ASSERT_INT_EQ(sshkey_to_blob_buf(k1, buf), 0);
	sshkey_free(k1);
	fuzz = fuzz_begin(FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END,
	    sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		if (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA public");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private(buf, "", "key", &k1, NULL), 0);
	sshbuf_reset(buf);
	ASSERT_INT_EQ(sshkey_to_blob_buf(k1, buf), 0);
	sshkey_free(k1);
	fuzz = fuzz_begin(FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END,
	    sshbuf_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	for(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		if (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
	TEST_DONE();

}
