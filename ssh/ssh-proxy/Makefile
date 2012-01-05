#	$OpenBSD: Makefile,v 1.24 2010/02/09 08:55:31 markus Exp $

.PATH:		${.CURDIR}/..

PROG=	ssh-proxy

BINDIR=	/usr/sbin
NOMAN=	yes

SRCS=	ssh-proxy.c \
	kexdhs.c kexgexs.c kexecdhs.c \
	roaming_dummy.c

.include <bsd.prog.mk>

DPADD+=	${LIBCRYPTO} ${LIBZ}
LDADD+=	-lcrypto -lz
