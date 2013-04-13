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
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <sys/tree.h>
#include <vm/uma.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include <userfw/ruleset.h>
#include "multiruleset.h"

struct ruleset_tree_entry
{
	RB_ENTRY(ruleset_tree_entry)	tree;
	uint32_t	id;
	userfw_ruleset	ruleset;
};

struct
{
	RB_HEAD(multiruleset_tree, ruleset_tree_entry) root;
	struct rmlock	mtx;
	struct rm_priotracker	rm_internal;
} root;

#define	RLOCK	rm_rlock(&(root.mtx), &(root.rm_internal))
#define RUNLOCK	rm_runlock(&(root.mtx), &(root.rm_internal))
#define WLOCK	rm_wlock(&(root.mtx))
#define WUNLOCK	rm_wunlock(&(root.mtx))

static uma_zone_t	multiruleset_zone;

RB_PROTOTYPE_STATIC(multiruleset_tree, ruleset_tree_entry, tree, tree_compare);

static int
tree_compare(struct ruleset_tree_entry *e1, struct ruleset_tree_entry *e2)
{
	if (e1->id > e2->id)
		return 1;
	if (e1->id < e2->id)
		return -1;
	return 0;
}

static int
tree_init(void)
{
	multiruleset_zone = uma_zcreate("userfw multiruleset entries",
		sizeof(struct ruleset_tree_entry),
		NULL, NULL,
		0, 0, 0, 0);
	rm_init(&(root.mtx), "multiruleset tree mtx");
	RB_INIT(&(root.root));
	return 0;
}

static void
free_ruleset_entry_locked(struct ruleset_tree_entry *entry)
{
	if (entry != NULL)
	{
		RB_REMOVE(multiruleset_tree, &(root.root), entry);
		/* wait for all threads to finish with this ruleset */
		USERFW_WLOCK(&(entry->ruleset));
		USERFW_WUNLOCK(&(entry->ruleset));
		userfw_ruleset_uninit(&(entry->ruleset), M_USERFW);
		uma_zfree(multiruleset_zone, entry);
	}
};

static int
tree_uninit(void)
{
	struct ruleset_tree_entry *entry, *next;

	WLOCK;
	RB_FOREACH_SAFE(entry, multiruleset_tree, &(root.root), next)
	{
		free_ruleset_entry_locked(entry);
	}
	WUNLOCK;
	rm_destroy(&(root.mtx));
	return 0;
}

static userfw_ruleset *
find_ruleset_locked(uint32_t id)
{
	struct ruleset_tree_entry find, *entry = NULL;

	find.id = id;
	entry = RB_FIND(multiruleset_tree, &(root.root), &find);
	if (entry != NULL)
		return &(entry->ruleset);

	return NULL;
}

static int
remove_ruleset_locked(uint32_t id)
{
	struct ruleset_tree_entry find, *entry = NULL;

	find.id = id;
	entry = RB_FIND(multiruleset_tree, &(root.root), &find);
	if (entry != NULL)
	{
		free_ruleset_entry_locked(entry);
		return 0;
	}

	return ENOENT;
}

static int
create_ruleset_locked(uint32_t id)
{
	struct ruleset_tree_entry *entry = NULL;

	if (find_ruleset_locked(id) != NULL)
		return EEXIST;

	entry = uma_zalloc(multiruleset_zone, M_WAITOK);
	if (entry != NULL)
	{
		entry->id = id;
		userfw_ruleset_init(&(entry->ruleset), "multiruleset: ruleset mtx");
		RB_INSERT(multiruleset_tree, &(root.root), entry);
		return 0;
	}
	return ENOMEM;
}

static int
invoke_ruleset(uint32_t id, struct mbuf **mb, userfw_chk_args *args)
{
	int ret = 0; /* TODO: make sysctl for default value */
	userfw_ruleset *ruleset = NULL;

	RLOCK;
	ruleset = find_ruleset_locked(id);
	if (ruleset != NULL)
	{
		ret = check_packet(mb, args, ruleset);
	}
	RUNLOCK;

	return ret;
}

static int
action_ruleset(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	*continue_ = 0;
	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		return invoke_ruleset(action->args[0].uint32.value, mb, args);
	}
	else
	{
		/* should be unreachable */
		printf("userfw_multiruleset: action \"ruleset\" called with USERFW_ACTION_FLAG_SECOND_PASS\n");
		return 0;
	}
}

static int
action_match_ruleset(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	userfw_arg marg;
	int match_ret = 0;

	*continue_ = 0;
	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		marg.type = T_UINT32;
		marg.uint32.value = 0; /* default ruleset */
		match_ret = action->args[0].match.p->do_match(mb, args, action->args[0].match.p, cache, &marg);
		if (match_ret != 0)
		{
			switch(marg.type)
			{
			case T_UINT16:
				return invoke_ruleset(marg.uint16.value, mb, args);
			case T_UINT32:
				return invoke_ruleset(marg.uint32.value, mb, args);
			case T_UINT64:
				return invoke_ruleset(marg.uint64.value, mb, args);
			}
			return 0;
		}
		else
		{
			*continue_ = 1;
			return 0;
		}
	}
	else
	{
		/* should be unreachable */
		printf("userfw_multiruleset: action \"match-ruleset\" called with USERFW_ACTION_FLAG_SECOND_PASS\n");
		return 0;
	}
}

static userfw_action_descr multiruleset_actions[] =
{
	{A_RULESET,	1,	{T_UINT32},	"ruleset",	action_ruleset}
	,{A_MRULESET,	1,	{T_MATCH},	"match-ruleset",	action_match_ruleset}
};

static int
cmd_list(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	userfw_ruleset *ruleset = NULL;
	struct userfw_io_block *msg;
	unsigned char *buf;
	int len;

	RLOCK;
	ruleset = find_ruleset_locked(args[0].uint32.value);
	if (ruleset != NULL)
	{
		msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2, M_USERFW);
		userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW);
		userfw_msg_set_arg(msg, userfw_ruleset_serialize(ruleset, M_USERFW), 1);

		len = userfw_msg_calc_size(msg);
		buf = malloc(len, M_USERFW, M_WAITOK);
		if (userfw_msg_serialize(msg, buf, len) > 0)
			userfw_domain_send_to_socket(so, buf, len);
		free(buf, M_USERFW);
		userfw_msg_free(msg, M_USERFW);
	}
	else
	{
		userfw_msg_reply_error(so, cookie, ENOENT);
	}
	RUNLOCK;

	return 0;
}

static int
cmd_add(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	userfw_ruleset *ruleset = NULL;
	userfw_rule *rule = NULL;
	int ret;

	RLOCK;
	ruleset = find_ruleset_locked(args[0].uint32.value);
	if (ruleset == NULL)
	{
		RUNLOCK;
		WLOCK;
		create_ruleset_locked(args[0].uint32.value);
		WUNLOCK;
		RLOCK;
		ruleset = find_ruleset_locked(args[0].uint32.value);
	}
	if (ruleset != NULL)
	{
		rule = malloc(sizeof(*rule), M_USERFW, M_WAITOK | M_ZERO);
		rule->number = args[1].uint32.value;
		/* XXX: this should not be so ugly */
		rule->action = *(args[2].action.p);
		rule->match = *(args[3].match.p);
		free(args[2].action.p, M_USERFW);
		args[2].action.p = NULL;
		args[2].type = T_INVAL;
		free(args[3].match.p, M_USERFW);
		args[3].match.p = NULL;
		args[3].type = T_INVAL;

		ret = userfw_ruleset_insert_rule(ruleset, rule);
		userfw_msg_reply_error(so, cookie, ret);
		if (ret != 0)
		{
			free_rule(rule, M_USERFW);
		}
	}
	else
	{
		userfw_msg_reply_error(so, cookie, ENOENT);
	}
	RUNLOCK;

	return 0;
}

static int
cmd_delete(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	userfw_ruleset *ruleset = NULL;
	int ret;

	RLOCK;
	ruleset = find_ruleset_locked(args[0].uint32.value);
	if (ruleset != NULL)
	{
		ret = userfw_ruleset_delete_rule(ruleset, args[1].uint32.value, M_USERFW);
		userfw_msg_reply_error(so, cookie, ret);
	}
	else
	{
		userfw_msg_reply_error(so, cookie, ENOENT);
	}
	RUNLOCK;

	return 0;
}

static int
cmd_flush(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	userfw_ruleset *ruleset = NULL;
	int ret;

	RLOCK;
	ruleset = find_ruleset_locked(args[0].uint32.value);
	if (ruleset != NULL)
	{
		ret = userfw_ruleset_replace(ruleset, NULL, M_USERFW);
		userfw_msg_reply_error(so, cookie, ret);
	}
	else
	{
		userfw_msg_reply_error(so, cookie, ENOENT);
	}
	RUNLOCK;

	return 0;
}

static int
cmd_drop_ruleset(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret = 0;

	WLOCK;
	ret = remove_ruleset_locked(args[0].uint32.value);
	WUNLOCK;
	userfw_msg_reply_error(so, cookie, ret);

	return 0;
}

static userfw_cmd_descr multiruleset_cmds[] =
{
	{CMD_LIST,	1,	{T_UINT32},	"mlist",	cmd_list}
	,{CMD_ADD,	4,	{T_UINT32, T_UINT32, T_ACTION, T_MATCH},	"madd",	cmd_add}
	,{CMD_DELETE,	2,	{T_UINT32, T_UINT32},	"mdelete",	cmd_delete}
	,{CMD_FLUSH,	1,	{T_UINT32},	"mflush",	cmd_flush}
	,{CMD_DROP,	1,	{T_UINT32},	"drop-ruleset",	cmd_drop_ruleset}
};

static userfw_modinfo multiruleset_modinfo =
{
	.id = USERFW_MULTIRULESET_MOD,
	.name = "multiruleset",
	.nactions = sizeof(multiruleset_actions)/sizeof(multiruleset_actions[0]),
	.nmatches = 0,
	.ncmds = sizeof(multiruleset_cmds)/sizeof(multiruleset_cmds[0]),
	.actions = multiruleset_actions,
	.matches = NULL,
	.cmds = multiruleset_cmds
};

RB_GENERATE_STATIC(multiruleset_tree, ruleset_tree_entry, tree, tree_compare);

static int
multiruleset_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&multiruleset_modinfo);
		tree_init();
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_MULTIRULESET_MOD);
		tree_uninit();
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t multiruleset_mod =
{
	"userfw_multiruleset",
	multiruleset_modevent,
	0
};

MODULE_VERSION(userfw_multiruleset, 1);
DEPEND_ON_USERFW_CORE(userfw_multiruleset);

DECLARE_MODULE(userfw_multiruleset, multiruleset_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
