#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "dummynet.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_var.h>
#include <netinet/ip_dummynet.h>
#include <netinet/ipfw/ip_fw_private.h>

static int
action_dummynet(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_)
{
	struct ip_fw_args ipfw_args;
	int ret = EACCES;
	int dir;

	*continue_ = 1;
	VERIFY_OPCODE2(action, USERFW_DUMMYNET_MOD, A_PIPE, A_QUEUE, 0);

	ipfw_args.m = *mb;
	ipfw_args.oif = (args->dir == USERFW_OUT) ? args->ifp : NULL;
	ipfw_args.inp = args->inpcb;
	ipfw_args.rule.info = action->args[0].uint16.value;
	if (action->op == A_PIPE)
		ipfw_args.rule.info |= IPFW_IS_PIPE;
	dir = (args->dir == USERFW_OUT) ? DIR_OUT : DIR_IN;

	if (ip_dn_io_ptr != NULL)
	{
		SET_NET_IPLEN(mtod(*mb, struct ip *));
		if (mtod(*mb, struct ip *)->ip_v == 4)
			ret = ip_dn_io_ptr(mb, dir, &ipfw_args);
		else if (mtod(*mb, struct ip *)->ip_v == 6)
			ret = ip_dn_io_ptr(mb, dir | PROTO_IPV6, &ipfw_args);
		if ((*mb) != NULL)
		{
			SET_HOST_IPLEN(mtod(*mb, struct ip *));
		}
	}

	return ret;
};

static userfw_action_descr dummynet_actions[] =
{
	{A_PIPE,	1,	{T_UINT16},	"pipe",	action_dummynet}
	,{A_QUEUE,	1,	{T_UINT16},	"queue",	action_dummynet}
};

static userfw_modinfo dummynet_modinfo =
{
	.id = USERFW_DUMMYNET_MOD,
	.name = "dummynet",
	.nactions = sizeof(dummynet_actions)/sizeof(dummynet_actions[0]),
	.nmatches = 0,
	.ncmds = 0,
	.actions = dummynet_actions,
	.matches = NULL,
	.cmds = NULL
};

static int
dummynet_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&dummynet_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_DUMMYNET_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t dummynet_mod =
{
	"userfw_dummy",
	dummynet_modevent,
	0
};

MODULE_VERSION(userfw_dummynet, 1);
MODULE_DEPEND(userfw_dummynet, userfw_core, 1, 1, 1);
MODULE_DEPEND(userfw_dummynet, dummynet, 3, 3, 3);

DECLARE_MODULE(userfw_dummynet, dummynet_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
