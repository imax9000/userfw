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


#include <userfw/module.h>
#include "userfw.h"
#include "userfw_module.h"
#include <userfw/ruleset.h>

userfw_modules_head_t userfw_modules_list = SLIST_HEAD_INITIALIZER(userfw_modules_list);
struct rwlock userfw_modules_list_mtx;

static struct modinfo_entry *
userfw_mod_find_locked(userfw_module_id_t id)
{
	struct modinfo_entry *m;

	SLIST_FOREACH(m, &userfw_modules_list, entries)
	{
		if (m->data->id == id)
		{
			return m;
		}
	}
	return NULL;
}

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
		m = malloc(sizeof(struct modinfo_entry), M_USERFW, M_WAITOK | M_ZERO);
		m->data = mod;
		m->refcount = 0;
		mtx_init(&(m->refcount_mtx), "userfw: modinfo_entry.refcount_mtx", NULL, MTX_DEF);
		SLIST_INSERT_HEAD(&userfw_modules_list, m, entries);
	}

	rw_wunlock(&userfw_modules_list_mtx);

	return ret;
}

int
userfw_mod_unregister(userfw_module_id_t id)
{
	int ret = 0;
	struct modinfo_entry *m;

	if (ret == 0)
	{
		rw_wlock(&userfw_modules_list_mtx);

		m = userfw_mod_find_locked(id);
#if 0
		mtx_lock(&(m->refcount_mtx));
#endif
		if (m->refcount != 0)
			ret = EBUSY;
#if 0
		mtx_unlock(&(m->refcount_mtx));
#endif

		if (ret == 0)
		{
			SLIST_REMOVE(&userfw_modules_list, m, modinfo_entry, entries);
			mtx_destroy(&(m->refcount_mtx));
			free(m, M_USERFW);
		}

		rw_wunlock(&userfw_modules_list_mtx);
	}

	return ret;
}

const userfw_modinfo *
userfw_mod_find(userfw_module_id_t id)
{
	const userfw_modinfo *ret = NULL;
	struct modinfo_entry *m;

	rw_rlock(&userfw_modules_list_mtx);
	m = userfw_mod_find_locked(id);
	rw_runlock(&userfw_modules_list_mtx);

	if (m != NULL)
		ret = m->data;

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

int
userfw_mod_inc_refcount(userfw_module_id_t id)
{
	struct modinfo_entry *mod;
	int err = 0;

	rw_rlock(&userfw_modules_list_mtx);
	mod = userfw_mod_find_locked(id);
	if (mod == NULL)
		err = ENOENT;
	else
	{
		mtx_lock(&(mod->refcount_mtx));
		mod->refcount++;
		mtx_unlock(&(mod->refcount_mtx));
	}
	rw_runlock(&userfw_modules_list_mtx);

	return err;
}

int
userfw_mod_dec_refcount(userfw_module_id_t id)
{
	struct modinfo_entry *mod;
	int err = 0;

	rw_rlock(&userfw_modules_list_mtx);
	mod = userfw_mod_find_locked(id);
	if (mod == NULL)
		err = ENOENT;
	else
	{
		mtx_lock(&(mod->refcount_mtx));
		mod->refcount--;
		mtx_unlock(&(mod->refcount_mtx));
	}
	rw_runlock(&userfw_modules_list_mtx);

	return err;
}
