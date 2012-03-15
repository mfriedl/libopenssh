#	$OpenBSD:$

.if defined(LEAKMALLOC)
SUBDIR=	leakmalloc ssh unittests
.else
SUBDIR=	ssh unittests regress
.endif

.include <bsd.subdir.mk>
