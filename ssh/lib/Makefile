#	$OpenBSD: Makefile,v 1.64 2012/08/02 13:38:39 okan Exp $

.PATH:		${.CURDIR}/..

LIB=	ssh
SRCS=	authfd.c authfile.c canohost.c \
	channels.c cipher.c cipher-3des1.c cipher-bf1.c cipher-ctr.c \
	cleanup.c compat.c crc32.c deattack.c fatal.c \
	hostfile.c log.c match.c nchan.c packet.c readpass.c \
	rsa.c ttymodes.c xmalloc.c atomicio.c \
	key.c dispatch.c kex.c mac.c uidswap.c uuencode.c misc.c \
	ssh-dss.c ssh-rsa.c ssh-ecdsa.c dh.c kexdh.c kexgex.c kexecdh.c \
	kexdhc.c kexgexc.c kexecdhc.c msg.c progressmeter.c dns.c \
	monitor_fdpass.c umac.c addrmatch.c schnorr.c jpake.c ssh-pkcs11.c \
	\
	sshbuf-getput-basic.c \
	sshbuf-getput-crypto.c \
	sshbuf-misc.c \
	sshbuf.c \
	err.c

SRCS+=	kexdhs.c kexgexs.c kexecdhs.c
SRCS+=	opacket.c ssh_api.c
SRCS+=	roaming_dummy.c

DEBUGLIBS= no
NOPROFILE= yes

install:
	@echo -n

.include "${.CURDIR}/../Makefile.inc"
.include <bsd.own.mk>

.if (${KERBEROS5:L} == "yes")
CFLAGS+= -DKRB5 -I${DESTDIR}/usr/include/kerberosV

SRCS+= gss-genr.c
CFLAGS+= -DGSSAPI
.endif # KERBEROS5

NOPIC= yes
.include <bsd.lib.mk>
