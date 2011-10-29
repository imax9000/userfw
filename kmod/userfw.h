#ifndef USERFW_H
#define USERFW_H

#include "userfw_rules_priv.h"
#include <userfw/rules.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>

typedef struct __userfw_chk_args
{
	int	af;
	struct ifnet	*ifp;
	int	dir;
	struct inpcb	*inpcb;
} userfw_chk_args;

int userfw_init(void);
int userfw_uninit(void);

userfw_action userfw_chk(struct mbuf **, userfw_chk_args *);

#endif /* USERFW_H */
