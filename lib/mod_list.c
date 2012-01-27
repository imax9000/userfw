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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <stdio.h>
#include <sys/param.h>
#include "mod_list.h"
#ifdef LIB_SEPARATE_BUILD
#include <userfw/modules/base.h>
#else
#include "../core/base.h"
#endif
#include "message.h"

static unsigned int
get_int_val(const struct userfw_io_block *msg)
{
	switch(msg->type)
	{
	case T_UINT16:
		return msg->data.uint16.value;
	case T_UINT32:
		return msg->data.uint32.value;
	}

	return 0;
}

#define FILL_DESCR(x) static void fill_ ## x ## _descr(struct userfw_io_block *src, struct userfw_ ## x ## _descr *dst) \
{\
	int arg_count = 0, i;\
\
	for(i = 0; i < src->nargs; i++)\
	{\
		switch(src->args[i]->subtype)\
		{\
		case ST_OPCODE:\
			dst->opcode = get_int_val(src->args[i]);\
			break;\
		case ST_NAME:\
			if (src->args[i]->type == T_STRING)\
			{\
				bcopy(src->args[i]->data.string.data, dst->name,\
					MIN(USERFW_NAME_LEN, src->args[i]->data.string.length));\
				if (src->args[i]->data.string.length < USERFW_NAME_LEN)\
					dst->name[src->args[i]->data.string.length] = '\0';\
			}\
			else\
				fprintf(stderr, "userfw_modlist_get: incorrect type for ST_NAME: %d\n", src->args[i]->type);\
			break;\
		case ST_ARGTYPE:\
			dst->arg_types[arg_count] = get_int_val(src->args[i]);\
			arg_count++;\
			break;\
		}\
	}\
	dst->nargs = arg_count;\
}

FILL_DESCR(action);
FILL_DESCR(match);
FILL_DESCR(cmd);

static int
fill_modinfo(struct userfw_connection *c, struct userfw_modinfo *dst, userfw_module_id_t id)
{
	struct userfw_io_block *msg = NULL, *cur;
	int ret = 0, i, j;

	if ((ret = userfw_send_modinfo_cmd(c, id)) < 0)
		return ret;

	msg = userfw_recv_msg(c);
	if (msg == NULL)
		return -1;

	dst->id = id;
	dst->nactions = 0;
	dst->nmatches = 0;
	dst->ncmds = 0;

	for(i = 0; i < msg->nargs; i++)
	{
		if (msg->args[i]->subtype == ST_MOD_DESCR)
		{
			cur = msg->args[i];
			for(j = 0; j < cur->nargs; j++)
			{
				switch (cur->args[j]->subtype)
				{
				case ST_ACTION_DESCR:
					dst->nactions++;
					break;
				case ST_MATCH_DESCR:
					dst->nmatches++;
					break;
				case ST_CMD_DESCR:
					dst->ncmds++;
					break;
				case ST_NAME:
					if (cur->args[j]->type == T_STRING)
					{
						bcopy(cur->args[j]->data.string.data,
							dst->name,
							MIN(USERFW_NAME_LEN, cur->args[j]->data.string.length));
						if (cur->args[j]->data.string.length < USERFW_NAME_LEN)
							dst->name[cur->args[j]->data.string.length] = '\0';
					}
					else
						fprintf(stderr, "fill_modinfo: incorrect type for ST_NAME: %d\n", cur->type);
					break;
				case ST_OPCODE:
					dst->id = get_int_val(cur->args[j]);
					break;
				}
			}

			dst->actions = malloc(sizeof(struct userfw_action_descr) * dst->nactions);
			dst->matches = malloc(sizeof(struct userfw_match_descr) * dst->nmatches);
			dst->cmds = malloc(sizeof(struct userfw_cmd_descr) * dst->ncmds);

			if (dst->actions != NULL &&
				dst->matches != NULL &&
				dst->cmds != NULL)
			{
				int cur_action = 0, cur_match = 0, cur_cmd = 0;

				for(j = 0; j < cur->nargs; j++)
				{
					switch (cur->args[j]->subtype)
					{
					case ST_ACTION_DESCR:
						fill_action_descr(cur->args[j], &(dst->actions[cur_action]));
						dst->actions[cur_action].module = dst->id;
						cur_action++;
						break;
					case ST_MATCH_DESCR:
						fill_match_descr(cur->args[j], &(dst->matches[cur_match]));
						dst->matches[cur_match].module = dst->id;
						cur_match++;
						break;
					case ST_CMD_DESCR:
						fill_cmd_descr(cur->args[j], &(dst->cmds[cur_cmd]));
						dst->cmds[cur_cmd].module = dst->id;
						cur_cmd++;
						break;
					}
				}
			}
			else
			{
				ret = -1;
				errno = ENOMEM;
				break;
			}
		}
	}

	userfw_msg_free(msg);
	msg = NULL;

	return ret;
}

struct userfw_modlist *
userfw_modlist_get(struct userfw_connection *c)
{
	struct userfw_modlist *ret = NULL;
	unsigned char *buf = NULL;
	size_t len;
	struct userfw_io_block *msg = NULL, *cur;
	int i, j, k, count;

	if (userfw_send_modlist_cmd(c) >= 0 &&
		(msg = userfw_recv_msg(c)) != NULL)
	{
		ret = malloc(sizeof(*ret));
		if (ret != NULL)
		{
			for(count = 0, i = 0; i < msg->nargs; i++)
			{
				if (msg->args[i]->subtype == ST_MOD_DESCR)
					count++;
			}
			ret->nmodules = count;
			ret->modules = malloc(sizeof(struct userfw_modinfo) * count);
			if (ret->modules != NULL)
			{
				for(count = 0, i = 0; i < msg->nargs; i++)
				{
					if (msg->args[i]->subtype == ST_MOD_DESCR)
					{
						for(j = 0; j < msg->args[i]->nargs; j++)
						{
							cur = msg->args[i]->args[j];
							if (cur->subtype == ST_MOD_ID)
								ret->modules[count].id = get_int_val(cur);
						}
						count++;
					}
				}

				userfw_msg_free(msg);
				msg = NULL;

				for(i = 0; i < count && ret != NULL; i++)
				{
					if (fill_modinfo(c, &(ret->modules[i]), ret->modules[i].id) != 0)
					{
						userfw_modlist_destroy(ret);
						ret = NULL;
						break;
					}
				}
			}
			else
			{
				userfw_modlist_destroy(ret);
				ret = NULL;
				errno = ENOMEM;
			}
		}
		if (msg != NULL)
			userfw_msg_free(msg);
	}
	
	return ret;
}

void
userfw_modlist_destroy(struct userfw_modlist *m)
{
	int i, j, k;
	if (m == NULL)
		return;

	if (m->nmodules > 0 && m->modules != NULL)
	{
		for(i = 0; i < m->nmodules; i++)
		{
			if (m->modules[i].nactions > 0 && m->modules[i].actions != NULL)
				free(m->modules[i].actions);
			if (m->modules[i].nmatches > 0 && m->modules[i].matches != NULL)
				free(m->modules[i].matches);
			if (m->modules[i].ncmds > 0 && m->modules[i].cmds != NULL)
				free(m->modules[i].cmds);
		}
		free(m->modules);
	}

	free(m);
}

int
userfw_find_module_by_name(const struct userfw_modlist *m, const char *name, size_t len, struct userfw_modinfo **dst)
{
	int i, ret = 0;
	for(i = 0; i < m->nmodules; i++)
	{
		if (memcmp(name, m->modules[i].name, MIN(len, USERFW_NAME_LEN)) == 0
			&& (len >= USERFW_NAME_LEN || m->modules[i].name[len] == '\0'))
		{
			*dst = &(m->modules[i]);
			ret++;
		}
	}
	return ret;
}

int
userfw_find_module_by_id(const struct userfw_modlist *m, userfw_module_id_t id, struct userfw_modinfo **dst)
{
	int i, ret = 0;
	for(i = 0; i < m->nmodules; i++)
	{
		if (m->modules[i].id == id)
		{
			*dst = &(m->modules[i]);
			ret++;
		}
	}
	return ret;
}

#define SEARCH_FUNCTIONS(x, y) \
int \
userfw_find_ ## x (const struct userfw_modlist *m, const char *name, size_t len, struct userfw_ ## x ##_descr **dst) \
{ \
	int i, ret = 0; \
	for(i = 0; i < m->nmodules; i++) \
		ret += userfw_find_ ## x ## _in_module(&(m->modules[i]), name, len, dst); \
	return ret; \
} \
 \
int \
userfw_find_ ## x ## _in_module(const struct userfw_modinfo *m, const char *name, size_t len, struct userfw_ ## x ## _descr **dst) \
{ \
	int i, ret = 0; \
	for(i = 0; i < m->n ## y; i++) \
	{ \
		if (memcmp(name, m->y[i].name, MIN(len, USERFW_NAME_LEN)) == 0 \
			&& (len >= USERFW_NAME_LEN || m->y[i].name[len] == '\0')) \
		{ \
			*dst = &(m->y[i]); \
			ret++; \
		} \
	} \
	return ret; \
} \
 \
int \
userfw_find_ ## x ## _by_opcode(const struct userfw_modinfo *m, opcode_t op, struct userfw_ ## x ## _descr **dst) \
{ \
	int i, ret = 0; \
	for(i = 0; i < m->n ## y; i++) \
	{ \
		if (m->y[i].opcode == op) \
		{ \
			*dst = &(m->y[i]); \
			ret++; \
		} \
	} \
	return ret; \
}

SEARCH_FUNCTIONS(action, actions);
SEARCH_FUNCTIONS(match, matches);
SEARCH_FUNCTIONS(cmd, cmds);
