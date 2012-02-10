/*-
 * Copyright (C) 2012 by Maxim Ignatenko <gelraen.ua@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


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
send_to_dummynet(struct mbuf **mb, userfw_chk_args *args, uint16_t num, int is_pipe)
{
	struct ip_fw_args ipfw_args;
	int ret = 0;
	int dir;

	ipfw_args.m = *mb;
	ipfw_args.oif = (args->dir == USERFW_OUT) ? args->ifp : NULL;
	ipfw_args.inp = args->inpcb;
	ipfw_args.rule.info = num;
	if (is_pipe)
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
}

static int
action_dummynet(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	int ret = 0;

	*continue_ = 1;
	VERIFY_OPCODE2(action, USERFW_DUMMYNET_MOD, A_PIPE, A_QUEUE, 0);

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		ret = send_to_dummynet(mb, args, action->args[0].uint16.value, action->op == A_PIPE);
	}

	return ret;
}

static int
action_dummynet_match(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	int ret = 0, match_ret = 0;
	uint16_t num;
	userfw_arg matcharg;

	*continue_ = 1;
	VERIFY_OPCODE2(action, USERFW_DUMMYNET_MOD, A_MPIPE, A_MQUEUE, 0);

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		matcharg.type = T_INVAL;
		match_ret = action->args[0].match.p->do_match(mb, args, action->args[0].match.p, cache, &matcharg);
		if (match_ret != 0)
		{
			switch(matcharg.type)
			{
			case T_UINT16:
				num = matcharg.uint16.value;
				ret = send_to_dummynet(mb, args, num, action->op == A_MPIPE);
				break;
			case T_UINT32:
				num = matcharg.uint32.value;
				ret = send_to_dummynet(mb, args, num, action->op == A_MPIPE);
				break;
			}
		}
	}
	return ret;
}

static userfw_action_descr dummynet_actions[] =
{
	{A_PIPE,	1,	{T_UINT16},	"pipe",	action_dummynet}
	,{A_QUEUE,	1,	{T_UINT16},	"queue",	action_dummynet}
	,{A_MPIPE,	1,	{T_MATCH},	"match-pipe",	action_dummynet_match}
	,{A_MQUEUE,	1,	{T_MATCH},	"match-queue",	action_dummynet_match}
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
	"userfw_dummynet",
	dummynet_modevent,
	0
};

MODULE_VERSION(userfw_dummynet, 1);
MODULE_DEPEND(userfw_dummynet, userfw_core, 1, 1, 1);
MODULE_DEPEND(userfw_dummynet, dummynet, 3, 3, 3);

DECLARE_MODULE(userfw_dummynet, dummynet_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
