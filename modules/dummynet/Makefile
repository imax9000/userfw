SRCS=	dummynet.c
KMOD=	userfw_dummynet
KMODDIR?=	/boot/modules
CFLAGS+=	-I../../include

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} dummynet.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
