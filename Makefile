#	$OpenBSD:$

.if defined(LEAKMALLOC)
SUBDIR=	leakmalloc ssh unittests
.else
SUBDIR=	ssh regress unittests
.endif

.include <bsd.subdir.mk>
