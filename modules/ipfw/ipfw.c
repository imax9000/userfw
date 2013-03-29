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
#include "ipfw.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_var.h>
#include "ip_fw_private.h"

static int
match_ipfw_table_ctor(userfw_match *match)
{
	if (match->args[0].uint16.value >= IPFW_TABLES_MAX)
		return EINVAL;
	return 0;
}

static int
match_ipfw_table(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	int ret = 0, lookup_from_cache = 0;
	struct ip_fw_chain *chain = &V_layer3_chain;
	uint32_t tablearg = 0;
	uint32_t key;
	uint16_t table = match->args[0].uint16.value;
#define cache_id (match->op == M_LOOKUP_SRC ? table : table + IPFW_TABLES_MAX)

	VERIFY_OPCODE2(match, USERFW_IPFW_MOD, M_LOOKUP_SRC, M_LOOKUP_DST, 0);

	if (cache != NULL && 
			(lookup_from_cache = (uint32_t)(long)userfw_cache_read(cache, USERFW_IPFW_MOD,
						IPFW_TABLES_MAX*4 + cache_id)) != 0)
	{
		ret = (uint32_t)(long)userfw_cache_read(cache, USERFW_IPFW_MOD, cache_id);
		tablearg = (uint32_t)(long)userfw_cache_read(cache, USERFW_IPFW_MOD,
				IPFW_TABLES_MAX*2 + cache_id);
	}
	else
	{
		if (mtod(*mb, struct ip *)->ip_v != 4)
			return 0;

		if (match->op == M_LOOKUP_SRC)
			key = mtod(*mb, struct ip *)->ip_src.s_addr;
		else /* if (match->op == M_LOOKUP_DST) */
			key = mtod(*mb, struct ip *)->ip_dst.s_addr;

		IPFW_RLOCK(chain);

		ret = ipfw_lookup_table(chain, table, key, &tablearg);

		IPFW_RUNLOCK(chain);

		if (cache != NULL)
		{
			userfw_cache_write(cache, USERFW_IPFW_MOD, cache_id, (void*)(long)ret, NULL);
			userfw_cache_write(cache, USERFW_IPFW_MOD, IPFW_TABLES_MAX*2 + cache_id,
					(void*)(long)tablearg, NULL);
			userfw_cache_write(cache, USERFW_IPFW_MOD, IPFW_TABLES_MAX*4 + cache_id,
					(void*)1, NULL);
		}
	}

	if (marg != NULL)
	{
		switch (marg->type)
		{
		case T_UINT16:
			marg->uint16.value = tablearg;
			break;
		case T_UINT32:
			marg->uint32.value = tablearg;
			break;
		default:
			marg->type = T_UINT32;
			marg->uint32.value = tablearg;
			break;
		}
	}

	return ret;
};

static int
match_ipfw_tag(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	VERIFY_OPCODE(match, USERFW_IPFW_MOD, M_TAGGED, 0);
	if (m_tag_locate(*mb, MTAG_IPFW, match->args[0].uint32.value, NULL) != NULL)
		return 1;
	return 0;
}

static userfw_match_descr ipfw_matches[] =
{
	{M_LOOKUP_SRC,	1,	{T_UINT16},	"lookup-src-ip",	match_ipfw_table,	match_ipfw_table_ctor}
	,{M_LOOKUP_DST,	1,	{T_UINT16},	"lookup-dst-ip",	match_ipfw_table,	match_ipfw_table_ctor}
	,{M_TAGGED,	1,	{T_UINT32},	"tagged",	match_ipfw_tag}
};

static int
action_ipfw_tag(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	struct m_tag *mtag = NULL;

	*continue_ = 1;
	VERIFY_OPCODE2(action, USERFW_IPFW_MOD, A_TAG, A_UNTAG, 0);

	switch(action->op)
	{
	case A_TAG:
		mtag = m_tag_alloc(MTAG_IPFW, action->args[0].uint32.value, 0, M_NOWAIT);
		if (mtag != NULL)
			m_tag_prepend(*mb, mtag);
		break;
	case A_UNTAG:
		mtag = m_tag_locate(*mb, MTAG_IPFW, action->args[0].uint32.value, NULL);
		if (mtag != NULL)
			m_tag_delete(*mb, mtag);
		break;
	}

	return 0;
}

static userfw_action_descr ipfw_actions[] =
{
	{A_TAG,	1,	{T_UINT32},	"tag",	action_ipfw_tag}
	,{A_UNTAG,	1,	{T_UINT32},	"untag",	action_ipfw_tag}
};

static userfw_modinfo ipfw_modinfo =
{
	.id = USERFW_IPFW_MOD,
	.name = "ipfw",
	.nactions = sizeof(ipfw_actions)/sizeof(ipfw_actions[0]),
	.nmatches = sizeof(ipfw_matches)/sizeof(ipfw_matches[0]),
	.ncmds = 0,
	.actions = ipfw_actions,
	.matches = ipfw_matches,
	.cmds = NULL
};

static int
ipfw_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ipfw_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_IPFW_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ipfw_mod =
{
	"userfw_ipfw",
	ipfw_modevent,
	0
};

MODULE_VERSION(userfw_ipfw, 1);
MODULE_DEPEND(userfw_ipfw, userfw_core, 1, 1, 1);
MODULE_DEPEND(userfw_ipfw, ipfw, 2, 2, 2);

DECLARE_MODULE(userfw_ipfw, ipfw_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
