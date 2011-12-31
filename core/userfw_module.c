/*-
 * Copyright (C) 2011 by Maxim Ignatenko <gelraen.ua@gmail.com>
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


#include <userfw/module.h>
#include "userfw.h"
#include "userfw_module.h"

userfw_modules_head_t userfw_modules_list = SLIST_HEAD_INITIALIZER(userfw_modules_list);
struct rwlock userfw_modules_list_mtx;

int module_used(userfw_module_id_t);
int module_used_in_match(userfw_match *, userfw_module_id_t);
int module_used_in_action(userfw_action *, userfw_module_id_t);

int
userfw_mod_register(userfw_modinfo * mod)
{
	int ret = 0;
	struct modinfo_entry *m;

	rw_wlock(&userfw_modules_list_mtx);

	SLIST_FOREACH(m, &userfw_modules_list, entries)
	{
		if (m->data->id == mod->id)
		{
			ret = EEXIST;
			break;
		}
	}

	if (ret == 0)
	{
		m = malloc(sizeof(struct modinfo_entry), M_USERFW, M_WAITOK);
		m->data = mod;
		SLIST_INSERT_HEAD(&userfw_modules_list, m, entries);
	}

	rw_wunlock(&userfw_modules_list_mtx);

	return ret;
}

int
userfw_mod_unregister(userfw_module_id_t id)
{
	int ret = 0;
	struct modinfo_entry *m, *prev = NULL;

	USERFW_RLOCK(&global_rules);

	if (module_used(id))
	{
		ret = EBUSY;
	}

	if (ret == 0)
	{
		rw_wlock(&userfw_modules_list_mtx);

		m = SLIST_FIRST(&userfw_modules_list);
		if (m != NULL && m->data->id == id)
		{
			SLIST_REMOVE_HEAD(&userfw_modules_list, entries);
			free(m, M_USERFW);
		}
		else
		{
			SLIST_FOREACH(m, &userfw_modules_list, entries)
			{
				if (SLIST_NEXT(m, entries) != NULL && SLIST_NEXT(m, entries)->data->id)
				{
					prev = m;
					break;
				}
			}

			if (prev != NULL)
			{
				m = SLIST_NEXT(prev, entries);
				SLIST_REMOVE_AFTER(prev, entries);
				free(m, M_USERFW);
			}
			else
			{
				ret = ENOENT;
			}
		}

		rw_wunlock(&userfw_modules_list_mtx);
	}

	USERFW_RUNLOCK(&global_rules);

	return ret;
}

int
module_used_in_match(userfw_match *match, userfw_module_id_t id)
{
	int i;

	if (match->mod == id)
		return 1;

	for(i = 0; i < match->nargs; i++)
	{
		switch (match->args[i].type)
		{
		case T_MATCH:
			if (module_used_in_match(match->args[i].match.p, id))
				return 1;
			break;
		case T_ACTION:
			if (module_used_in_action(match->args[i].action.p, id))
				return 1;
			break;
		}
	}

	return 0;
}

int
module_used_in_action(userfw_action *action, userfw_module_id_t id)
{
	int i;

	if (action->mod == id)
		return 1;

	for(i = 0; i < action->nargs; i++)
	{
		switch (action->args[i].type)
		{
		case T_MATCH:
			if (module_used_in_match(action->args[i].match.p, id))
				return 1;
			break;
		case T_ACTION:
			if (module_used_in_action(action->args[i].action.p, id))
				return 1;
			break;
		}
	}

	return 0;
}

int
module_used(userfw_module_id_t id)
{
	userfw_rule *rule = global_rules.rule;

	while(rule != NULL)
	{
		if (module_used_in_match(&(rule->match), id) ||
				module_used_in_action(&(rule->action), id))
			return 1;

		rule = rule->next;
	}

	return 0;
}

const userfw_modinfo *
userfw_mod_find(userfw_module_id_t id)
{
	struct modinfo_entry *m;
	const userfw_modinfo *ret = NULL;

	rw_rlock(&userfw_modules_list_mtx);

	SLIST_FOREACH(m, &userfw_modules_list, entries)
	{
		if (m->data->id == id)
		{
			ret = m->data;
			break;
		}
	}
	
	rw_runlock(&userfw_modules_list_mtx);

	return ret;
}

const userfw_match_descr *
userfw_mod_find_match(userfw_module_id_t mod, opcode_t id)
{
	const userfw_modinfo *modinfo = NULL;
	int i;

	modinfo = userfw_mod_find(mod);

	if (modinfo == NULL)
		return NULL;

	for(i = 0; i < modinfo->nmatches; i++)
	{
		if (modinfo->matches[i].opcode == id)
			return &(modinfo->matches[i]);
	}

	return NULL;
}

const userfw_action_descr *
userfw_mod_find_action(userfw_module_id_t mod, opcode_t id)
{
	const userfw_modinfo *modinfo = NULL;
	int i;

	modinfo = userfw_mod_find(mod);

	if (modinfo == NULL)
		return NULL;

	for(i = 0; i < modinfo->nactions; i++)
	{
		if (modinfo->actions[i].opcode == id)
			return &(modinfo->actions[i]);
	}

	return NULL;
}

const userfw_cmd_descr *
userfw_mod_find_cmd(userfw_module_id_t mod, opcode_t id)
{
	const userfw_modinfo *modinfo = NULL;
	int i;

	modinfo = userfw_mod_find(mod);

	if (modinfo == NULL)
		return NULL;

	for(i = 0; i < modinfo->ncmds; i++)
	{
		if (modinfo->cmds[i].opcode == id)
			return &(modinfo->cmds[i]);
	}

	return NULL;
}