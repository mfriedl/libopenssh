/*	$OpenBSD	*/
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Utility functions/framework for fuzz tests */

#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "test_helper.h"

struct fuzz {
	/* Fuzz method in use */
	int strategy;

	/* Original seed data blob */
	void *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;
	size_t flen;

	/* Used by fuzz methods */
	size_t o1, o2;
};

void
fuzz_dump(struct fuzz *fuzz)
{
	u_char *p = fuzz_ptr(fuzz);
	size_t i, j, len = fuzz_len(fuzz);

	switch (fuzz->strategy) {
	case FUZZ_1_BIT_FLIP:
		fprintf(stderr, "FUZZ_1_BIT_FLIP case %zu of %zu\n",
		    fuzz->o1, fuzz->flen * 8);
		break;
	case FUZZ_2_BIT_FLIP:
		fprintf(stderr, "FUZZ_2_BIT_FLIP case %llu of %llu\n",
		    ((unsigned long long)fuzz->o1) * fuzz->o2,
		    ((unsigned long long)fuzz->flen * 8) * fuzz->flen * 8);
		break;
	case FUZZ_1_BYTE_FLIP:
		fprintf(stderr, "FUZZ_1_BYTE_FLIP case %zu of %zu\n",
		    fuzz->o1, fuzz->flen);
		break;
	case FUZZ_2_BYTE_FLIP:
		fprintf(stderr, "FUZZ_2_BYTE_FLIP case %llu of %llu\n",
		    ((unsigned long long)fuzz->o1) * fuzz->o2,
		    ((unsigned long long)fuzz->flen) * fuzz->flen);
		break;
	case FUZZ_TRUNCATE_START:
		fprintf(stderr, "FUZZ_TRUNCATE_START case %zu of %zu\n",
		    fuzz->o1, fuzz->flen);
		break;
	case FUZZ_TRUNCATE_END:
		fprintf(stderr, "FUZZ_TRUNCATE_END case %zu of %zu\n",
		    fuzz->o1, fuzz->flen);
		break;
	default:
		abort();
	}

	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, len);
	for (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		for (j = i; j < i + 16; j++) {
			if (j < len)
				fprintf(stderr, "%02x ", p[j]);
			else
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		for (j = i; j < i + 16; j++) {
			if (j < len) {
				if  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				else
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

struct fuzz *
fuzz_begin(int strategy, void *p, size_t l)
{
	struct fuzz *ret = calloc(sizeof(ret), 1);

	assert(ret != NULL);
	ret->strategy = strategy;
	ret->seed = p;
	ret->slen = l;

	switch (ret->strategy) {
	case FUZZ_1_BIT_FLIP:
	case FUZZ_2_BIT_FLIP:
		assert(ret->slen < SIZE_MAX / 8);
		/* FALLTHROUGH */
	case FUZZ_1_BYTE_FLIP:
	case FUZZ_2_BYTE_FLIP:
	case FUZZ_TRUNCATE_START:
	case FUZZ_TRUNCATE_END:
		ret->fuzzed = calloc(ret->slen, 1);
		assert(ret->fuzzed != NULL);
		break;
	default:
		abort();
	}
	fuzz_next(ret);
	return ret;
}

void
fuzz_next(struct fuzz *fuzz)
{
	switch (fuzz->strategy) {
	case FUZZ_1_BIT_FLIP:
		assert(fuzz->flen == fuzz->slen);
		assert(fuzz->fuzzed != NULL);
		assert(fuzz->o1 / 8 < fuzz->flen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->flen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		break;
	case FUZZ_2_BIT_FLIP:
		assert(fuzz->flen == fuzz->slen);
		assert(fuzz->fuzzed != NULL);
		assert(fuzz->o1 / 8 < fuzz->flen);
		assert(fuzz->o2 / 8 < fuzz->flen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->flen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		if (fuzz->o1 >= fuzz->flen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		break;
	case FUZZ_1_BYTE_FLIP:
		assert(fuzz->flen == fuzz->slen);
		assert(fuzz->fuzzed != NULL);
		assert(fuzz->o1 < fuzz->flen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->flen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		break;
	case FUZZ_2_BYTE_FLIP:
		assert(fuzz->flen == fuzz->slen);
		assert(fuzz->fuzzed != NULL);
		assert(fuzz->o1 < fuzz->flen);
		assert(fuzz->o2 < fuzz->flen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->flen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		if (fuzz->o1 >= fuzz->flen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		break;
	case FUZZ_TRUNCATE_START:
	case FUZZ_TRUNCATE_END:
		assert(fuzz->flen == fuzz->slen);
		assert(fuzz->fuzzed != NULL);
		assert(fuzz->o1 < fuzz->flen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->flen);
		fuzz->o1++;
		break;
	default:
		abort();
	}
}

int
fuzz_done(struct fuzz *fuzz)
{
	switch (fuzz->strategy) {
	case FUZZ_1_BIT_FLIP:
		return fuzz->o1 >= fuzz->flen * 8;
	case FUZZ_2_BIT_FLIP:
		return fuzz->o2 >= fuzz->flen * 8;
	case FUZZ_1_BYTE_FLIP:
		return fuzz->o1 >= fuzz->flen;
	case FUZZ_2_BYTE_FLIP:
		return fuzz->o2 >= fuzz->flen;
	case FUZZ_TRUNCATE_START:
	case FUZZ_TRUNCATE_END:
		return fuzz->o1 >= fuzz->flen;
	default:
		abort();
	}
}

size_t
fuzz_len(struct fuzz *fuzz)
{
	assert(fuzz->fuzzed != NULL);
	switch (fuzz->strategy) {
	case FUZZ_1_BIT_FLIP:
	case FUZZ_2_BIT_FLIP:
	case FUZZ_1_BYTE_FLIP:
	case FUZZ_2_BYTE_FLIP:
		return fuzz->flen;
	case FUZZ_TRUNCATE_START:
	case FUZZ_TRUNCATE_END:
		assert(fuzz->o1 < fuzz->flen);
		return fuzz->flen - fuzz->o1;
	default:
		abort();
	}
}

u_char *
fuzz_ptr(struct fuzz *fuzz)
{
	assert(fuzz->fuzzed != NULL);
	switch (fuzz->strategy) {
	case FUZZ_1_BIT_FLIP:
	case FUZZ_2_BIT_FLIP:
	case FUZZ_1_BYTE_FLIP:
	case FUZZ_2_BYTE_FLIP:
		return fuzz->fuzzed;
	case FUZZ_TRUNCATE_START:
		assert(fuzz->o1 < fuzz->flen);
		return fuzz->fuzzed + fuzz->o1;
	case FUZZ_TRUNCATE_END:
		assert(fuzz->o1 < fuzz->flen);
		return fuzz->fuzzed;
	default:
		abort();
	}
}

