#include <userfw/module.h>
#include "userfw.h"
#include "userfw_module.h"

userfw_modules_head_t userfw_modules_list = SLIST_HEAD_INITIALIZER(userfw_modules_list);
struct rwlock userfw_modules_list_mtx;

int module_used(userfw_module_id_t);
int module_used_in_match(userfw_match *, userfw_module_id_t);

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
module_used_in_match(userfw_match * match, userfw_module_id_t id)
{
	int i;

	if (match->mod == id)
		return 1;

	for(i = 0; i < match->nargs; i++)
	{
		if (match->args[i].type == T_MATCH && 
				module_used_in_match(match->args[i].match.p, id))
			return 1;
	}

	return 0;
}

int
module_used(userfw_module_id_t id)
{
	userfw_rule *rule = global_rules.rule;
	int i;

	while(rule != NULL)
	{
		if (module_used_in_match(&(rule->match), id))
			return 1;

		for(i = 0; i < rule->action.nargs; i++)
		{
			if (rule->action.args[i].type == T_MATCH &&
					module_used_in_match(rule->action.args[i].match.p, id))
				return 1;
		}

		rule = rule->next;
	}

	return 0;
}
