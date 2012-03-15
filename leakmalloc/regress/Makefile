#	$OpenBSD$

.include <bsd.own.mk>
.include <bsd.obj.mk>

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wformat
.if (${CC:L} == "gcc" || ${CC:L} == "cc")
CDIAGFLAGS+=	-Wbounded
.endif
DEBUG=-g
COPTS=-O0

CPPFLAGS+=-I${.CURDIR}/../leakmalloc

.if exists(${.CURDIR}/../leakmalloc/${__objdir})
LDADD+=-L${.CURDIR}/../leakmalloc/${__objdir} -lleakmalloc
DPADD+=${.CURDIR}/../leakmalloc/${__objdir}/libleakmalloc.a
.else
LDADD+=-L${.CURDIR}/../leakmalloc -lleakmalloc
DPADD+=${.CURDIR}/../leakmalloc/libleakmalloc.a
.endif

LDFLAGS+=-L/usr/local/lib
LDADD+=-lexecinfo

PROG=leaky
SRCS=leaky.c
REGRESS_TARGETS=does-leak outfile exit-leak summary 

does-leak: ${PROG}
	./${PROG} | grep -q "^LEAK "

outfile: ${PROG}
	rm -f leakmalloc.out
	env LEAKMALLOC_OPTIONS=D ./${PROG}
	grep -q "^LEAK " leakmalloc.out

exit-leak: ${PROG}
	sh -c 'export LEAKMALLOC_OPTIONS=XQ ; ./${PROG} ; test $$? -eq 99'

summary: ${PROG}
	test `./${PROG} | ${.CURDIR}/../leakresolve.py -p ${PROG} | \
	      grep "^Total:" | cut -d' ' -f 2` -eq 22

clean:
	rm -f ${PROG} *.o *.core leakmalloc.out

.include <bsd.regress.mk>

