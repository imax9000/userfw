#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include "base.h"
#include <userfw/module.h>

static int
action_allow(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache)
{
	return 0;
}

static int
action_deny(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache)
{
	return EACCES;
}

static int
match_direction(struct mbuf **mb, userfw_chk_args *args, userfw_match *m, userfw_cache *cache)
{
	return args->dir == m->op;
}

enum __base_actions
{
	A_ALLOW
	,A_DENY
};

static userfw_action_descr base_actions[] = {
	{A_ALLOW,	0,	0,	{},	"allow",	action_allow}
	,{A_DENY,	0,	0,	{},	"deny",	action_deny}
};

enum __base_matches
{
	M_IN = USERFW_IN
	,M_OUT = USERFW_OUT
};

static userfw_match_descr base_matches[] = {
	{M_IN,	0,	0,	{},	"in",	match_direction}
	,{M_OUT,	0,	0,	{},	"out",	match_direction}
};

static userfw_modinfo base_modinfo =
{
	USERFW_BASE_MOD,
	2,	/* nactions */
	2,	/* nmatches */
	base_actions,
	base_matches,
	"base"
};

static int
userfw_base_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&base_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_BASE_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t	userfw_base_mod = {
	"userfw_base",
	userfw_base_modevent,
	0
};

MODULE_VERSION(userfw_base, 1);
MODULE_DEPEND(userfw_base, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_base, userfw_base_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
