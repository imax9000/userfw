SRCS=	userfw_mod.c \
	userfw.c \
	userfw_dev.c \
	userfw_module.c \
	userfw_cache.c \
	userfw_pfil.c \
	userfw_domain.c \
	userfw_cmd.c \
	userfw_util.c \
	userfw_ruleset.c \
	userfw_msgbuilder.c \
	base.c
KMOD=	userfw
CFLAGS+=	-I../include
KMODDIR?=	/boot/modules
PREFIX?=	/usr/local

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} base.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
