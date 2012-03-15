#	$OpenBSD$

LIB=	leakmalloc
SRCS=	leakmalloc.c
HDRS=	leakmalloc.h
#MAN=	leakmalloc.3
NOMAN=1
NOPIC=1
NOPROFILE=1

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wmissing-declarations
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wcast-qual
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wcast-align
CDIAGFLAGS+=	-Wbad-function-cast

CPPFLAGS+= -I/usr/local/include
DEBUG=-ggdb3
COPTS=-O0
INSTALL_STRIP=

.include <bsd.lib.mk>
