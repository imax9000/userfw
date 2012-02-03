SRCS=	dummy.c
KMOD=	userfw_dummy
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} dummy.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
