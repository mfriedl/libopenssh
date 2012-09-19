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
#include <signal.h>
#include <err.h>

#include <execinfo.h>

#define LEAKMALLOC_NO_REDIRECT
#include "leakmalloc.h"

#define OPT_EXIT_ON_LEAKS	0x01
#define OPT_DUMP_TO_FILE	0x02
#define OPT_QUIET		0x04

#ifndef BT_MAX_DEPTH
#define BT_MAX_DEPTH 127
#endif

u_int leakmalloc_options = 0;
static int initialised;
static FILE *dumpfile;

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
	if (a->addr == b->addr)
		return 0;
	if (a->addr > b->addr)
		return 1;
	else
		return -1;
}

RB_HEAD(alloc_tree, alloc);
RB_GENERATE_STATIC(alloc_tree, alloc, entry, alloc_cmp);
static struct alloc_tree alloc_tree = RB_INITIALIZER(&alloc_tree);

static void
dump_leak(FILE *f, const char *tag, struct alloc *alloc)
{
	int i;

	fprintf(f, "%s %p %zu TRACE", tag, alloc->addr, alloc->len);
	for (i = 1; i < alloc->depth; i++)
		fprintf(f, " %p", alloc->bt[i]);
	fprintf(f, "\n");
}

/* Called atexit to dump unfreed leak objects */
static void
dump_leaks(void)
{
	struct alloc *alloc;
	int i = 0;

	if (initialised != 1)
		return;
	RB_FOREACH(alloc, alloc_tree, &alloc_tree) {
		if ((leakmalloc_options & OPT_QUIET) == 0)
			dump_leak(dumpfile ? dumpfile : stdout, "LEAK", alloc);
		i++;
	}
	if (dumpfile)
		fclose(dumpfile);
	if ((leakmalloc_options & OPT_EXIT_ON_LEAKS) != 0)
		_exit(99);
}

static void
internal_error(const char *tag, struct alloc *alloc)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "ERROR/%s", tag);
#if 0
	alloc->addr = NULL;
	alloc->len = -1;
#endif
	dump_leak(stderr, buf, alloc);
	initialised = -1;
}

static struct alloc *
new_alloc(void *addr, size_t len)
{
	struct alloc *alloc;

	if ((alloc = calloc(1, sizeof(*alloc))) == NULL)
		errx(1, "%s: calloc failed", __func__);	
	alloc->addr = addr;
	alloc->len = len;
	if ((alloc->depth = backtrace(alloc->bt, BT_MAX_DEPTH)) == -1)
		errx(1, "%s: backtrace failed", __func__);
	return alloc;
}

static void
__record_leak(void *addr, size_t len, void *oaddr)
{
	struct alloc oalloc, *alloc, *ealloc;
	char *cp;

	if (initialised == -1)
		return;
	else if (initialised == 0) {
		atexit(dump_leaks);
		if (!issetugid() &&
		    (cp = getenv("LEAKMALLOC_OPTIONS")) != NULL) {
			if (strchr(cp, 'X') != NULL)
				leakmalloc_options |= OPT_EXIT_ON_LEAKS;
			if (strchr(cp, 'D') != NULL)
				leakmalloc_options |= OPT_DUMP_TO_FILE;
			if (strchr(cp, 'Q') != NULL)
				leakmalloc_options |= OPT_QUIET;
		}
		if ((leakmalloc_options & OPT_DUMP_TO_FILE) != 0 &&
		    (dumpfile = fopen("leakmalloc.out", "w+")) == NULL)
			err(1, "fopen(\"leakmalloc.out\")");
		initialised = 1;
	}

	if (oaddr == NULL) {
		/*
		 * malloc/calloc/realloc(NULL,...): allocate a leak object
		 * and fill in the trace.
		 */
		if (addr == NULL)
			return;		/* alloc failed or free(NULL) */
		alloc = new_alloc(addr, len);
		ealloc = RB_INSERT(alloc_tree, &alloc_tree, alloc);
		if (ealloc != NULL) {
			internal_error("original", ealloc);
			internal_error("new", alloc);
			warnx("%s: alloc for fresh alloc %p already exists",
			    __func__, addr);
			raise(SIGABRT);
		}
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
			if (alloc == NULL) {
				alloc = new_alloc(NULL, -1);
				internal_error("new", alloc);
				warnx("%s: realloc original addr %p missing",
				    __func__, oaddr);
				raise(SIGABRT);
			}
			RB_REMOVE(alloc_tree, &alloc_tree, alloc);
			alloc->addr = addr;
			alloc->len = len;
			ealloc = RB_INSERT(alloc_tree, &alloc_tree, alloc);
			if (ealloc != NULL) {
				internal_error("original", ealloc);
				internal_error("new", alloc);
				warnx("%s: alloc for realloc %p already exists",
				    __func__, addr);
				raise(SIGABRT);
			}
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

