#	$OpenBSD: Makefile.inc,v 1.6 2015/07/01 23:11:18 djm Exp $

.include <bsd.own.mk>
.include <bsd.obj.mk>

REGRESS_FAIL_EARLY= yes

# XXX detect from ssh binary?
SSH1?=		yes
OPENSSL?=	yes

.if (${OPENSSL:L} == "yes")
CFLAGS+=	-DWITH_OPENSSL
.else
# SSH v.1 requires OpenSSL.
SSH1=		no
.endif

.if (${SSH1:L} == "yes")
CFLAGS+=	-DWITH_SSH1
.endif

# enable warnings
WARNINGS=Yes

DEBUG=-g
CFLAGS+=	-fstack-protector-all
CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wchar-subscripts
CDIAGFLAGS+=	-Wcomment
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
.if ${COMPILER_VERSION} == "gcc4"
CDIAGFLAGS+=	-Wpointer-sign
CDIAGFLAGS+=	-Wold-style-definition
.endif

CFLAGS+=-I${.CURDIR}/../test_helper -I${.CURDIR}/../../ssh

.if exists(${.CURDIR}/../test_helper/${__objdir})
LDADD+=-L${.CURDIR}/../test_helper/${__objdir} -ltest_helper
DPADD+=${.CURDIR}/../test_helper/${__objdir}/libtest_helper.a
.else
LDADD+=-L${.CURDIR}/../test_helper -ltest_helper
DPADD+=${.CURDIR}/../test_helper/libtest_helper.a
.endif

.if exists(${.CURDIR}/../../ssh/lib/${__objdir})
LDADD+=-L${.CURDIR}/../../ssh/lib/${__objdir} -lssh
DPADD+=${.CURDIR}/../../ssh/lib/${__objdir}/libssh.a
.else
LDADD+=-L${.CURDIR}/../../ssh/lib -lssh
DPADD+=${.CURDIR}/../../ssh/lib/libssh.a
.endif

.if defined(LEAKMALLOC)
DEBUG=		-g
COPTS=		-O0
LEAKMALLOC_DIR=	${.CURDIR}/../../leakmalloc/leakmalloc
CFLAGS+=	-I${LEAKMALLOC_DIR} -DWITH_LEAKMALLOC 
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lleakmalloc -lexecinfo
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

LDADD+= -lutil
DPADD+= ${LIBUTIL}

.if (${OPENSSL:L} == "yes")
LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}
.endif
