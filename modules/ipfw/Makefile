SRCS=	ipfw.c
KMOD=	userfw_ipfw
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ipfw.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
