#	$OpenBSD$

.include <bsd.own.mk>
.include <bsd.obj.mk>

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wformat
.if (${CC:L} == "gcc" || ${CC:L} == "cc")
CDIAGFLAGS+=	-Wbounded
.endif

DEBUG=-g

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

LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}
