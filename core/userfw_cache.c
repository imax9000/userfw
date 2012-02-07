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


#include "userfw.h"
#include <userfw/cache.h>
#include <sys/tree.h>

struct userfw_cache_entry
{
	RB_ENTRY(userfw_cache_entry)	tree;
	userfw_module_id_t	mod;
	uint32_t	id;
	void	*data;
	void	(*dtor)(void*);
};

struct __userfw_cache
{
	RB_HEAD(userfw_cache_tree, userfw_cache_entry)	root;
};

RB_PROTOTYPE_STATIC(userfw_cache_tree, userfw_cache_entry, tree, tree_compare);

static uma_zone_t cache_zone, entry_zone;

int
userfw_cache_init(void)
{
	cache_zone = uma_zcreate("userfw cache instances",
			sizeof(userfw_cache),
			NULL, NULL,
			0, 0, 0, 0);
	entry_zone = uma_zcreate("userfw cache entries",
			sizeof(struct userfw_cache_entry),
			NULL, NULL,
			0, 0, 0, 0);
	return 0;
}

int
userfw_cache_uninit(void)
{
	uma_zdestroy(cache_zone);
	uma_zdestroy(entry_zone);
	return 0;
}

userfw_cache *
userfw_cache_alloc(int flags)
{
	userfw_cache *ret = NULL;

	ret = uma_zalloc(cache_zone, flags);
	if (ret != NULL)
	{
		RB_INIT(&(ret->root));
	}

	return ret;
}

int
userfw_cache_destroy(userfw_cache * p)
{
	struct userfw_cache_entry *entry, *next;

	if (p == NULL)
		return 0;

	RB_FOREACH_SAFE(entry, userfw_cache_tree, &(p->root), next)
	{
		RB_REMOVE(userfw_cache_tree, &(p->root), entry);
		if (entry->dtor != NULL)
			entry->dtor(entry->data);
		uma_zfree(entry_zone, entry);
	}
	uma_zfree(cache_zone, p);
	return 0;
}

int
userfw_cache_write(userfw_cache * p, userfw_module_id_t mod, uint32_t id, void* data, void (*dtor)(void*))
{
	struct userfw_cache_entry find, *entry = NULL;

	if (p == NULL)
		return ENOENT;

	find.mod = mod;
	find.id = id;
	entry = RB_FIND(userfw_cache_tree, &(p->root), &find);

	if (entry != NULL)
	{
		if (entry->dtor != NULL)
			entry->dtor(entry->data);
		entry->data = data;
		entry->dtor = dtor;
	}
	else
	{
		entry = uma_zalloc(entry_zone, M_NOWAIT);
		if (entry != NULL)
		{
			entry->mod = mod;
			entry->id = id;
			entry->data = data;
			entry->dtor = dtor;
			RB_INSERT(userfw_cache_tree, &(p->root), entry);
		}
		else
			return ENOMEM;
	}

	return 0;
}

void *
userfw_cache_read(userfw_cache * p, userfw_module_id_t mod, uint32_t id)
{
	struct userfw_cache_entry find, *entry = NULL;

	if (p == NULL)
		return NULL;

	find.mod = mod;
	find.id = id;
	entry = RB_FIND(userfw_cache_tree, &(p->root), &find);
	if (entry != NULL)
		return entry->data;

	return NULL;
}

int
userfw_cache_delete(userfw_cache * p, userfw_module_id_t mod, uint32_t id)
{
	struct userfw_cache_entry find, *entry = NULL;

	if (p == NULL)
		return ENOENT;

	find.mod = mod;
	find.id = id;
	entry = RB_FIND(userfw_cache_tree, &(p->root), &find);
	if (entry != NULL)
	{
		RB_REMOVE(userfw_cache_tree, &(p->root), entry);
		if (entry->dtor != NULL)
			entry->dtor(entry->data);
		uma_zfree(entry_zone, entry);
	}
	else
		return ENOENT;

	return 0;
}

static int
tree_compare(struct userfw_cache_entry *e1, struct userfw_cache_entry *e2)
{
	if (e1->mod > e2->mod)
		return 1;
	if (e1->mod < e2->mod)
		return -1;
	if (e1->id > e2->id)
		return 1;
	if (e1->id < e2->id)
		return -1;
	return 0;
}

RB_GENERATE_STATIC(userfw_cache_tree, userfw_cache_entry, tree, tree_compare);
