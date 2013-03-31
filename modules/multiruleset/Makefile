SRCS=	multiruleset.c
KMOD=	userfw_multiruleset
KMODDIR?=	/boot/modules
CFLAGS+=	-I${S}/../../include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ${S}/multiruleset.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
