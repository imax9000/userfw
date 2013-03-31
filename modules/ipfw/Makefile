SRCS=	ipfw.c
KMOD=	userfw_ipfw
KMODDIR?=	/boot/modules
CFLAGS+=	-I${S}/../../include
# CMake will put generated ip_fw_private.h in our obj dir
CFLAGS+=	-I${MAKEOBJDIRPREFIX}${S}

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ${S}/ipfw.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
