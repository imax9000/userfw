SRCS=	dummynet.c
KMOD=	userfw_dummynet
KMODDIR?=	/boot/modules
CFLAGS+=	-I${S}/../../include -I${MAKEOBJDIRPREFIX}${S}

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ${S}/dummynet.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
