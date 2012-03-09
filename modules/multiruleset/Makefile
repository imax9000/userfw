SRCS=	multiruleset.c
KMOD=	userfw_multiruleset
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} multiruleset.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
