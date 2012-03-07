#include <stdlib.h>
#include <string.h>

#include "leakmalloc.h"

static void *a, *b, *c, *d, *e, *f;

static void
f6(void)
{
	d = strdup("hello");
	e = malloc(789);
}

static void
f5(void)
{
	c = calloc(1, 678);
	f6();
}

static void
f4(void)
{
	b = malloc(456);
	f5();
	free(e);
}

static void
f3(void)
{
	a = malloc(123);
	f = realloc(NULL, 321);
}

static void
f2(void)
{
	f4();
	b = realloc(b, 567);
}

static void
f1(void)
{
	int i;

	f2();
	for (i = 0; i < 10; i++)
		f3();
}

int
main(void)
{
	f1();
	free(f);
	return 0;
}
