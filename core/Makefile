SRCS=	userfw_mod.c \
	userfw.c \
	userfw_module.c \
	userfw_cache.c \
	userfw_pfil.c \
	userfw_domain.c \
	userfw_cmd.c \
	userfw_util.c \
	userfw_ruleset.c \
	userfw_msgbuilder.c \
	base.c \
	ip.c \
	ipv4.c
KMOD=	userfw
CFLAGS+=	-I../include
KMODDIR?=	/boot/modules
PREFIX?=	/usr/local

.if defined(SKIP_DOMAIN_STUB)
CFLAGS+=	-DSKIP_DOMAIN_STUB
.endif
.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} base.h "${PREFIX}/include/userfw/modules"
	${INSTALL} ip.h "${PREFIX}/include/userfw/modules"
	${INSTALL} ipv4.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
