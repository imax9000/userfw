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
#include "base.h"
#include <userfw/module.h>
#include <sys/mbuf.h>
#include "userfw_module.h"
#include <userfw/io.h>
#include <userfw/ruleset.h>
#include "userfw_util.h"

static int
action_allow(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache, int *continue_, uint32_t flags)
{
	*continue_ = 0;
	return 0;
}

static int
action_deny(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache, int *continue_, uint32_t flags)
{
	*continue_ = 0;
	return EACCES;
}

static int
action_continue(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache, int *continue_, uint32_t flags)
{
	int ret = a->args[0].action.p->do_action(mb, args, a->args[0].action.p, cache, continue_, flags);
	*continue_ = (a->op == A_CONTINUE) ? 1 : 0;
	return ret;
}

static userfw_action_descr base_actions[] = {
	{A_ALLOW,	0,	{},	"allow",	action_allow}
	,{A_DENY,	0,	{},	"deny",	action_deny}
	,{A_CONTINUE,	1,	{T_ACTION},	"continue-after", action_continue}
	,{A_STOP,	1,	{T_ACTION},	"stop-after", action_continue}
};

static int
match_direction(struct mbuf **mb, userfw_chk_args *args, userfw_match *m, userfw_cache *cache, userfw_arg *marg)
{
	VERIFY_OPCODE2(m, USERFW_BASE_MOD, M_IN, M_OUT, 0);

	if (args->dir == m->op)
		return 1;
	else
		return 0;
}

static int
match_logic(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	userfw_match	*match1, *match2;
	int	ret1;

	VERIFY_OPCODE2(match, USERFW_BASE_MOD, M_OR, M_AND, 0);

	match1 = match->args[0].match.p;
	match2 = match->args[1].match.p;

	ret1 = match1->do_match(mb, args, match1, cache, marg);

	if ((*mb) == NULL)
		return 0;

	if (ret1 == 0 && match->op == M_AND)
		return 0;

	if (ret1 != 0 && match->op == M_OR)
		return ret1;

	return match2->do_match(mb, args, match2, cache, marg);
}

static int
match_invert(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	userfw_match	*match1;

	VERIFY_OPCODE(match, USERFW_BASE_MOD, M_NOT, 0);

	match1 = match->args[0].match.p;
	if (match1->do_match(mb, args, match1, cache, marg))
		return 0;
	else
		return 1;
}

static int
match_any(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	VERIFY_OPCODE(match, USERFW_BASE_MOD, M_ANY, 0);
	return 1;
}

static int
match_frame_len(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	VERIFY_OPCODE(match, USERFW_BASE_MOD, M_FRAME_LEN, 0);
	if ((*mb)->m_pkthdr.len == match->args[0].uint32.value)
		return 1;
	else
		return 0;
}

static userfw_match_descr base_matches[] = {
	{M_IN,	0,	{},	"in",	match_direction}
	,{M_OUT,	0,	{},	"out",	match_direction}
	,{M_OR,	2,	{T_MATCH, T_MATCH},	"or",	match_logic}
	,{M_AND,	2,	{T_MATCH, T_MATCH}, "and",	match_logic}
	,{M_NOT,	1,	{T_MATCH},	"not",	match_invert}
	,{M_ANY,	0,	{},	"any",	match_any}
	,{M_FRAME_LEN,	1,	{T_UINT32},	"frame-len",	match_frame_len}
};

static struct userfw_io_block *
serialize_modinfo(const userfw_modinfo *modinfo, struct malloc_type *mtype)
{
	struct userfw_io_block *msg;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MOD_DESCR, 2, mtype);
	userfw_msg_insert_string(msg, ST_NAME, modinfo->name, strnlen(modinfo->name, USERFW_NAME_LEN), 0, mtype);
	userfw_msg_insert_uint32(msg, ST_MOD_ID, modinfo->id, 1, mtype);

	return msg;
}

static int
cmd_modlist(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	struct modinfo_entry *modinfo;
	int count = 0, i = 0;
	struct userfw_io_block *msg;
	unsigned char *buf;
	size_t len;

	rw_rlock(&userfw_modules_list_mtx);

	SLIST_FOREACH(modinfo, &userfw_modules_list, entries)
	{
		count++;
	}

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, count+2, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_ERRNO, 0, 0, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 1, M_USERFW);
	i = 2;

	SLIST_FOREACH(modinfo, &userfw_modules_list, entries)
	{
		userfw_msg_set_arg(msg, serialize_modinfo(modinfo->data, M_USERFW), i);
		i++;
	}
	rw_runlock(&userfw_modules_list_mtx);

	len = userfw_msg_calc_size(msg);
	buf = malloc(len, M_USERFW, M_WAITOK);
	if (userfw_msg_serialize(msg, buf, len) > 0)
	{
		userfw_domain_send_to_socket(so, buf, len);
	}
	free(buf, M_USERFW);
	userfw_msg_free(msg, M_USERFW);

	return 0;
}

static struct userfw_io_block *
serialize_op_info(uint32_t subtype, opcode_t opcode, const char *name, size_t namelen, int nargs, const uint8_t *argtypes, struct malloc_type *mtype)
{
	struct userfw_io_block *msg;
	int i;

	msg = userfw_msg_alloc_container(T_CONTAINER, subtype, nargs+2, mtype);
	userfw_msg_insert_string(msg, ST_NAME, name, namelen, 0, mtype);
	userfw_msg_insert_uint32(msg, ST_OPCODE, opcode, 1, mtype);

	for(i = 0; i < nargs; i++)
	{
		userfw_msg_insert_uint32(msg, ST_ARGTYPE, argtypes[i], i+2, mtype);
	}

	return msg;
}

static struct userfw_io_block *
serialize_modinfo_full(const userfw_modinfo *modinfo, struct malloc_type *mtype)
{
	struct userfw_io_block *msg;
	int i, cur;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MOD_DESCR,
		2 + modinfo->nactions + modinfo->nmatches + modinfo->ncmds, mtype);
	userfw_msg_insert_string(msg, ST_NAME, modinfo->name, strnlen(modinfo->name, USERFW_NAME_LEN), 0, mtype);
	userfw_msg_insert_uint32(msg, ST_MOD_ID, modinfo->id, 1, mtype);
	cur = 2;
	for(i = 0; i < modinfo->nactions; i++)
	{
		userfw_msg_set_arg(msg,
			serialize_op_info(ST_ACTION_DESCR,
				modinfo->actions[i].opcode,
				modinfo->actions[i].name,
				strnlen(modinfo->actions[i].name, USERFW_NAME_LEN),
				modinfo->actions[i].nargs,
				modinfo->actions[i].arg_types,
				M_USERFW),
			cur);
		cur++;
	}
	for(i = 0; i < modinfo->nmatches; i++)
	{
		userfw_msg_set_arg(msg,
			serialize_op_info(ST_MATCH_DESCR,
				modinfo->matches[i].opcode,
				modinfo->matches[i].name,
				strnlen(modinfo->matches[i].name, USERFW_NAME_LEN),
				modinfo->matches[i].nargs,
				modinfo->matches[i].arg_types,
				M_USERFW),
			cur);
		cur++;
	}
	for(i = 0; i < modinfo->ncmds; i++)
	{
		userfw_msg_set_arg(msg,
			serialize_op_info(ST_CMD_DESCR,
				modinfo->cmds[i].opcode,
				modinfo->cmds[i].name,
				strnlen(modinfo->cmds[i].name, USERFW_NAME_LEN),
				modinfo->cmds[i].nargs,
				modinfo->cmds[i].arg_types,
				M_USERFW),
			cur);
		cur++;
	}

	return msg;
}

static int
cmd_modinfo(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	struct userfw_io_block *msg;
	unsigned char *buf;
	size_t len;
	const userfw_modinfo *modinfo;
	
	modinfo = userfw_mod_find(args[0].uint32.value);

	if (modinfo == NULL)
	{
		return ENOENT;
	}
	else
	{
		msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 3, M_USERFW);
		userfw_msg_insert_uint32(msg, ST_ERRNO, 0, 0, M_USERFW);
		userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 1, M_USERFW);

		userfw_msg_set_arg(msg, serialize_modinfo_full(modinfo, M_USERFW), 2);
	}

	len = userfw_msg_calc_size(msg);
	buf = malloc(len, M_USERFW, M_WAITOK);
	if (userfw_msg_serialize(msg, buf, len) > 0)
	{
		userfw_domain_send_to_socket(so, buf, len);
	}
	free(buf, M_USERFW);
	userfw_msg_free(msg, M_USERFW);

	return 0;	
}

static int
cmd_list_ruleset(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	struct userfw_io_block *msg;
	unsigned char *buf;
	int len;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW);
	userfw_msg_set_arg(msg, userfw_ruleset_serialize(&global_rules, M_USERFW), 1);

	len = userfw_msg_calc_size(msg);
	buf = malloc(len, M_USERFW, M_WAITOK);
	if (userfw_msg_serialize(msg, buf, len) > 0)
		userfw_domain_send_to_socket(so, buf, len);
	free(buf, M_USERFW);
	userfw_msg_free(msg, M_USERFW);
	return 0;
}

static int
cmd_delete_rule(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int num, ret;

	num = args[0].uint32.value;
	ret = userfw_ruleset_delete_rule(&global_rules, num, M_USERFW);
	userfw_msg_reply_error(so, cookie, ret);

	return ret;
}

static int
cmd_insert_rule(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret;
	userfw_rule *rule;

	rule = malloc(sizeof(*rule), M_USERFW, M_WAITOK | M_ZERO);
	rule->number = args[0].uint32.value;
	/* XXX: this should not be so ugly */
	rule->action = *(args[1].action.p);
	rule->match = *(args[2].match.p);
	free(args[1].action.p, M_USERFW);
	args[1].action.p = NULL;
	args[1].type = T_INVAL;
	free(args[2].match.p, M_USERFW);
	args[2].match.p = NULL;
	args[2].type = T_INVAL;

	ret = userfw_ruleset_insert_rule(&global_rules, rule);
	userfw_msg_reply_error(so, cookie, ret);
	if (ret != 0)
	{
		free_rule(rule, M_USERFW);
	}
	return ret;
}

static int
cmd_flush_ruleset(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret;

	ret = userfw_ruleset_replace(&global_rules, NULL, M_USERFW);
	userfw_msg_reply_error(so, cookie, ret);

	return ret;
}

static userfw_cmd_descr base_cmds[] = {
	{CMD_MODLIST,	0,	{},	"modlist", cmd_modlist,	userfw_cmd_access_anybody}
	,{CMD_MODINFO,	1,	{T_UINT32}, "modinfo", cmd_modinfo,	userfw_cmd_access_anybody}
	,{CMD_LIST_RULESET,	0,	{},	"list",	cmd_list_ruleset}
	,{CMD_DELETE_RULE,	1,	{T_UINT32}, "delete", cmd_delete_rule}
	,{CMD_INSERT_RULE,	3,	{T_UINT32,T_ACTION,T_MATCH},	"add",	cmd_insert_rule}
	,{CMD_FLUSH_RULESET,	0,	{},	"flush",	cmd_flush_ruleset}
};

static userfw_modinfo base_modinfo =
{
	.id = USERFW_BASE_MOD,
	.nactions = sizeof(base_actions)/sizeof(base_actions[0]),
	.nmatches = sizeof(base_matches)/sizeof(base_matches[0]),
	.ncmds = sizeof(base_cmds)/sizeof(base_cmds[0]),
	.actions = base_actions,
	.matches = base_matches,
	.cmds = base_cmds,
	.name = "base"
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
