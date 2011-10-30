#ifndef USERFW_H
#define USERFW_H

#include "userfw_rules_priv.h"
#include <userfw/rules.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

MALLOC_DECLARE(M_USERFW);

typedef struct __userfw_chk_args
{
	int	af;
	struct ifnet	*ifp;
	int	dir;
	struct inpcb	*inpcb;
} userfw_chk_args;

typedef struct __userfw_ruleset
{
	userfw_rule	*rule;
	struct rwlock	mtx;
} userfw_ruleset;

extern userfw_ruleset global_rules;

#define USERFW_RLOCK(p)	rw_rlock(&((p)->mtx))
#define USERFW_WLOCK(p)	rw_wlock(&((p)->mtx))
#define USERFW_RUNLOCK(p)	rw_runlock(&((p)->mtx))
#define USERFW_WUNLOCK(p)	rw_wunlock(&((p)->mtx))
#define USERFW_INIT_LOCK(p, s)	rw_init(&((p)->mtx), (s))
#define USERFW_UNINIT_LOCK(p)	rw_destroy(&((p)->mtx))

int userfw_init(void);
int userfw_uninit(void);

userfw_action userfw_chk(struct mbuf **, userfw_chk_args *);

#endif /* USERFW_H */
