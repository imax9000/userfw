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
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/mbuf.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "counters.h"

struct counter
{
	uint64_t	packets;
	uint64_t	bytes;
};

#define	NCOUNTERS	(0x10000)

struct counter counters[NCOUNTERS];
struct mtx mutexes[NCOUNTERS];
struct rmlock global_mutex;
struct rm_priotracker rm_internal;

static void
counter_inc(uint16_t id, uint64_t size)
{
	rm_rlock(&global_mutex, &rm_internal);
	mtx_lock(&(mutexes[id]));
	counters[id].packets++;
	counters[id].bytes += size;
	mtx_unlock(&(mutexes[id]));
	rm_runlock(&global_mutex, &rm_internal);
}

static void
counter_reset(uint16_t id)
{
	rm_rlock(&global_mutex, &rm_internal);
	mtx_lock(&(mutexes[id]));
	counters[id].packets = 0;
	counters[id].bytes = 0;
	mtx_unlock(&(mutexes[id]));
	rm_runlock(&global_mutex, &rm_internal);
}

static void
counter_reset_all(void)
{
	rm_wlock(&global_mutex);
	bzero(counters, sizeof(counters));
	rm_wunlock(&global_mutex);
}

static void
counter_get(uint16_t id, struct counter *dst)
{
	rm_rlock(&global_mutex, &rm_internal);
	mtx_lock(&(mutexes[id]));
	dst->packets = counters[id].packets;
	dst->bytes = counters[id].bytes;
	mtx_unlock(&(mutexes[id]));
	rm_runlock(&global_mutex, &rm_internal);
}

static int
arg_is_int(const userfw_arg *arg)
{
	switch(arg->type)
	{
	case T_UINT16:
	case T_UINT32:
	case T_UINT64:
		return 1;
	}
	return 0;
}

static uint16_t arg_to_uint16(const userfw_arg *arg)
{
	switch(arg->type)
	{
	case T_UINT16:
		return arg->uint16.value;
	case T_UINT32:
		return (uint16_t)(arg->uint32.value);
	case T_UINT64:
		return (uint16_t)(arg->uint64.value);
	}
	return 0;
}

static int
action_count(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	*continue_ = 1;
	VERIFY_OPCODE(action, USERFW_COUNTERS_MOD, A_COUNT, 0);

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		counter_inc(action->args[0].uint16.value, (*mb)->m_pkthdr.len);
	}

	return 0;
}


static int
action_count_match(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	userfw_arg marg;

	marg.type = T_INVAL;

	*continue_ = 1;
	VERIFY_OPCODE(action, USERFW_COUNTERS_MOD, A_MCOUNT, 0);

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		if (action->args[0].match.p->do_match(mb, args, action->args[0].match.p, cache, &marg))
		{
			if (arg_is_int(&marg))
				counter_inc(arg_to_uint16(&marg), (*mb)->m_pkthdr.len);
		}
	}

	return 0;
}

static userfw_action_descr counters_actions[] =
{
	{A_COUNT,	1,	{T_UINT16},	"count",	action_count}
	,{A_MCOUNT,	1,	{T_MATCH},	"match-count",	action_count_match}
};

static int
cmd_list(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	uint16_t count = 0;
	int i, next;
	struct userfw_io_block *msg = NULL, *item = NULL;
	unsigned char *buf;
	size_t len;

	/* try to do this atomically */
	rm_wlock(&global_mutex);
	for(i = 0; i < NCOUNTERS; i++)
	{
		if (counters[i].packets > 0)
			count++;
	}
	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, count+1, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW);
	next = 1;

	for(i = 0; i < NCOUNTERS; i++)
	{
		if (counters[i].packets > 0)
		{
			item = userfw_msg_alloc_container(T_CONTAINER, ST_UNSPEC, 3, M_USERFW);
			userfw_msg_insert_uint16(item, ST_UNSPEC, i, 0, M_USERFW);
			userfw_msg_insert_uint64(item, ST_UNSPEC, counters[i].packets, 1, M_USERFW);
			userfw_msg_insert_uint64(item, ST_UNSPEC, counters[i].bytes, 2, M_USERFW);
			userfw_msg_set_arg(msg, item, next);
			next++;
		}
	}
	rm_wunlock(&global_mutex);

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
cmd_get(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	struct counter data;
	struct userfw_io_block *msg;
	unsigned char *buf;
	size_t len;

	counter_get(args[0].uint16.value, &data);

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW);
	userfw_msg_set_arg(msg, userfw_msg_alloc_container(T_CONTAINER, ST_UNSPEC, 3, M_USERFW), 1);

	userfw_msg_insert_uint16(msg->args[2], ST_UNSPEC, args[0].uint16.value, 0, M_USERFW);
	userfw_msg_insert_uint64(msg->args[2], ST_UNSPEC, data.packets, 1, M_USERFW);
	userfw_msg_insert_uint64(msg->args[2], ST_UNSPEC, data.bytes, 2, M_USERFW);
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
cmd_reset(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	counter_reset(args[0].uint16.value);
	userfw_msg_reply_error(so, cookie, 0);
	return 0;
}

static int
cmd_reset_all(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	counter_reset_all();
	userfw_msg_reply_error(so, cookie, 0);
	return 0;
}

static userfw_cmd_descr counters_cmds[] = 
{
	{CMD_LIST,	0,	{},	"show",	cmd_list}
	,{CMD_GET,	1,	{T_UINT16},	"get",	cmd_get}
	,{CMD_RESET,	1,	{T_UINT16},	"reset",	cmd_reset}
	,{CMD_RESET_ALL,	0,	{},	"reset-all",	cmd_reset_all}
};

static userfw_modinfo counters_modinfo =
{
	.id = USERFW_COUNTERS_MOD,
	.name = "counters",
	.nactions = sizeof(counters_actions)/sizeof(counters_actions[0]),
	.nmatches = 0,
	.ncmds = sizeof(counters_cmds)/sizeof(counters_cmds[0]),
	.actions = counters_actions,
	.matches = NULL,
	.cmds = counters_cmds
};

static int
counters_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&counters_modinfo);
		if (err == 0)
		{
			bzero(counters, sizeof(counters));
			bzero(mutexes, sizeof(mutexes));
			bzero(&global_mutex, sizeof(global_mutex));
			rm_init(&global_mutex, "userfw_counters global lock");
			int i;
			for(i = 0; i < NCOUNTERS; i++)
				mtx_init(&(mutexes[i]), "userfw_counters mtx", NULL, MTX_DEF);
		}
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_COUNTERS_MOD);
		if (err == 0)
		{
			rm_destroy(&global_mutex);
			int i;
			for(i = 0; i < NCOUNTERS; i++)
				mtx_destroy(&(mutexes[i]));
		}
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t counters_mod =
{
	"userfw_counters",
	counters_modevent,
	0
};

MODULE_VERSION(userfw_counters, 1);
MODULE_DEPEND(userfw_counters, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_counters, counters_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
