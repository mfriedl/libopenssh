#	$OpenBSD$

PROG=test_sshkey
SRCS=tests.c test_sshkey.c test_file.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	./${PROG} -d ${.CURDIR}/testdata

.include <bsd.regress.mk>

