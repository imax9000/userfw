/*-
 * Copyright (C) 2011-2012 by Maxim Ignatenko <gelraen.ua@gmail.com>
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
#include "ipv4.h"
#include <userfw/module.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/mbuf.h>
#include "userfw_module.h"
#include <userfw/io.h>
#include <userfw/ruleset.h>

static int
match_ipv4(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *margs)
{
	struct mbuf	*m = *mb;
	uint32_t	val = 0;
	struct ip	*ip = mtod(m, struct ip *);

	VERIFY_OPCODE2(match, USERFW_IPV4_MOD, M_SRCIPV4, M_DSTIPV4, 0);

	if (ip->ip_v != 4)
		return 0;

	switch (match->op)
	{
	case M_SRCIPV4:
		val = ip->ip_src.s_addr;
		break;
	case M_DSTIPV4:
		val = ip->ip_dst.s_addr;
		break;
	}

	if ((val & match->args[0].ipv4.mask) ==
		(match->args[0].ipv4.addr & match->args[0].ipv4.mask))
		return 1;

	return 0;
}

static userfw_match_descr ipv4_matches[] = {
	{M_SRCIPV4,	1,	{T_IPv4},	"src-addr",	match_ipv4}
	,{M_DSTIPV4,	1,	{T_IPv4},	"dst-addr",	match_ipv4}
};

static userfw_modinfo ipv4_modinfo =
{
	.id = USERFW_IPV4_MOD,
	.nactions = 0,
	.nmatches = sizeof(ipv4_matches)/sizeof(ipv4_matches[0]),
	.ncmds = 0,
	.actions = NULL,
	.matches = ipv4_matches,
	.cmds = NULL,
	.name = "ipv4"
};

static int
userfw_ipv4_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ipv4_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_IPV4_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t	userfw_ipv4_mod = {
	"userfw_ipv4",
	userfw_ipv4_modevent,
	0
};

MODULE_VERSION(userfw_ipv4, 1);
MODULE_DEPEND(userfw_ipv4, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_ipv4, userfw_ipv4_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
