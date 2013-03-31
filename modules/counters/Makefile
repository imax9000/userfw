SRCS=	counters.c
KMOD=	userfw_counters
KMODDIR?=	/boot/modules
CFLAGS+=	-I${S}/../../include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ${S}/counters.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
