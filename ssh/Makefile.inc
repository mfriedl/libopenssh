#	$OpenBSD: Makefile.inc,v 1.39 2010/10/01 23:10:48 djm Exp $

CFLAGS+=	-I${.CURDIR}/..

# enable warnings
WARNINGS=Yes

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wbounded
CDIAGFLAGS+=	-Wshadow

#DEBUG=-g

#CFLAGS+=	-DJPAKE

CFLAGS+=	-DENABLE_PKCS11
.include <bsd.own.mk>
.ifndef NOPIC
CFLAGS+=	-DHAVE_DLOPEN
.endif

.include <bsd.obj.mk>

.if !defined(LIB)
.if exists(${.CURDIR}/../lib/${__objdir})
LDADD+=         -L${.CURDIR}/../lib/${__objdir} -lssh -lgssapi -lkrb5
DPADD+=         ${.CURDIR}/../lib/${__objdir}/libssh.a
.else
LDADD+=         -L${.CURDIR}/../lib -lssh -lgssapi -lkrb5
DPADD+=         ${.CURDIR}/../lib/libssh.a
.endif
DPADD+=         ${.CURDIR}/../lib/shlib_version
LDADD+=         -lcrypto -lz
DPADD+=         ${LIBCRYPTO} ${LIBZ}
.endif
