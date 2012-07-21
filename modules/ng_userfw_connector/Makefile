SRCS=	ng_userfw_connector.c opt_netgraph.h
KMOD=	ng_userfw_connector
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ng_userfw_connector.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
