SRCS=	bpf.c
KMOD=	userfw_bpf
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} bpf.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
