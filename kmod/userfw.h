#ifndef USERFW_H
#define USERFW_H

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <userfw/types.h>
#include <userfw/module.h>

MALLOC_DECLARE(M_USERFW);

typedef struct __userfw_rule
{
	struct __userfw_rule *next;

	uint16_t	number;
	userfw_action	action;
	userfw_match	match;
} userfw_rule;

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

int userfw_chk(struct mbuf **, userfw_chk_args *);

#endif /* USERFW_H */
