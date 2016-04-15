#	$OpenBSD:$

.if defined(LEAKMALLOC)
SUBDIR=	leakmalloc sshunittests
.else
SUBDIR=	ssh regress
.endif

.include <bsd.subdir.mk>
