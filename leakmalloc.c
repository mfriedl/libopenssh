/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
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

#include <sys/types.h>
#include <sys/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <execinfo.h>

#define LEAKMALLOC_NO_REDIRECT
#include "leakmalloc.h"

static int initialised;

struct alloc {
	RB_ENTRY(alloc) entry;
	void *addr;
	size_t len;
	void *bt[BT_MAX_DEPTH];
	int depth;
};

static int
alloc_cmp(struct alloc *a, struct alloc *b)
{
	return (a->addr == b->addr) ? 0 : (a->addr < b->addr ? -1 : 1);
}

RB_HEAD(alloc_tree, alloc);
RB_GENERATE_STATIC(alloc_tree, alloc, entry, alloc_cmp);
static struct alloc_tree alloc_tree = RB_INITIALIZER(&alloc_tree);

/* Called atexit to dump unfreed leak objects */
static void
dump_leaks(void)
{
	struct alloc *alloc;
	int i;

	RB_FOREACH(alloc, alloc_tree, &alloc_tree) {
		printf("LEAK %p %zu TRACE", alloc->addr, alloc->len);
		for (i = 0; i < alloc->depth; i++)
			printf(" %p", alloc->bt[i]);
		printf("\n");
	}
}

void __record_leak(void *addr, size_t len, void *oaddr);
void
__record_leak(void *addr, size_t len, void *oaddr)
{
	struct alloc oalloc, *alloc;

	if (!initialised) {
		atexit(dump_leaks);
		initialised = 1;
	}

	if (addr == NULL || addr == oaddr)
		return;
	if (oaddr == NULL) {
		/*
		 * malloc/calloc: allocate a leak object and fill in the
		 * trace.
		 */
		if ((alloc = calloc(1, sizeof(*alloc))) == NULL)
			errx(1, "%s: calloc failed", __func__);	
		alloc->addr = addr;
		alloc->len = len;
		if ((alloc->depth = backtrace(alloc->bt, BT_MAX_DEPTH)) == -1)
			errx(1, "%s: backtrace failed", __func__);
		if (RB_INSERT(alloc_tree, &alloc_tree, alloc) != NULL)
			errx(1, "%s: alloc for %p already exists",
			    __func__, addr);
	} else {
		oalloc.addr = oaddr;
		alloc = RB_FIND(alloc_tree, &alloc_tree, &oalloc);
		if (addr == NULL) {
			/*
			 * free: delete the tracked leak.
			 */
			if (alloc == NULL)
				return; /* Ignore untracked memory */
			RB_REMOVE(alloc_tree, &alloc_tree, alloc);
			free(alloc);
		} else {
			/*
			 * realloc: update the original address so we can 
			 * trace it when it is freed.
			 */
			if (alloc == NULL)
				errx(1, "%s: original addr missing", __func__);
			alloc->addr = addr;
			alloc->len = len;
		}
	}
}

char *
leak_strdup(const char *s)
{
	char *ret = strdup(s);

	__record_leak(ret, ret == NULL ? 0 : strlen(ret), NULL);
	return ret;
}

void *
leak_malloc(size_t len)
{
	void *ret = malloc(len);

	__record_leak(ret, len, NULL);
	return ret;
}

void *
leak_calloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);

	__record_leak(ret, nmemb * size, NULL);
	return ret;
}

void *
leak_realloc(void *s, size_t len)
{
	void *ret = realloc(s, len);
	
	__record_leak(ret, len, s);
	return ret;
}

void
leak_free(void *s)
{
	free(s);
	__record_leak(NULL, 0, s);
}

