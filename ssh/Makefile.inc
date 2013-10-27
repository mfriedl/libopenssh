#	$OpenBSD: Makefile.inc,v 1.39 2010/10/01 23:10:48 djm Exp $

CFLAGS+=	-I${.CURDIR}/..

# enable warnings
WARNINGS=Yes

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Wchar-subscripts
CDIAGFLAGS+=	-Wcomment
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Wformat
CDIAGFLAGS+=	-Wformat-security
CDIAGFLAGS+=	-Wimplicit
CDIAGFLAGS+=	-Winline
CDIAGFLAGS+=	-Wmissing-declarations
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wparentheses
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wreturn-type
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wstrict-aliasing
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wswitch
CDIAGFLAGS+=	-Wtrigraphs
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wno-unused-parameter # Not clean for this yet
#-Wno-error=address
#CDIAGFLAGS+=	-Wcast-qual # XXX not clean
#CDIAGFLAGS+=	-Wcast-align # XXX can't be clean with sockaddr casts?


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
LDADD+=         -L${.CURDIR}/../lib/${__objdir} -lssh
DPADD+=         ${.CURDIR}/../lib/${__objdir}/libssh.a
.else
LDADD+=         -L${.CURDIR}/../lib -lssh
DPADD+=         ${.CURDIR}/../lib/libssh.a
.endif
DPADD+=         ${.CURDIR}/../lib/shlib_version
LDADD+=         -lcrypto -lz
DPADD+=         ${LIBCRYPTO} ${LIBZ}
.endif

.if defined(LEAKMALLOC)
DEBUG=		-g
COPTS=		-O0
LEAKMALLOC_DIR=	${.CURDIR}/../../leakmalloc/leakmalloc
CFLAGS+=	-I${LEAKMALLOC_DIR} -DWITH_LEAKMALLOC 
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lleakmalloc -lexecinfo
CFLAGS+=	-Dmalloc=leak_malloc -Dstrdup=leak_strdup
CFLAGS+=	-Dcalloc=leak_calloc -Drealloc=leak_realloc
CFLAGS+=	-Dfree=leak_free
. if exists(${LEAKMALLOC_DIR}/${__objdir})
LDADD+=         -L${LEAKMALLOC_DIR}/${__objdir}
DPADD+=         ${LEAKMALLOC_DIR}/${__objdir}/libleakmalloc.a
. else
LDADD+=         -L${LEAKMALLOC_DIR}
DPADD+=         ${LEAKMALLOC_DIR}/libleakmalloc.a
. endif
.else
CDIAGFLAGS+=	-Wuninitialized
.endif

