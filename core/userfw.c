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
#include "userfw_pfil.h"
#include "userfw_module.h"
#include "userfw_domain.h"
#include "userfw_util.h"
#include <userfw/ruleset.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <sys/sysctl.h>

MALLOC_DEFINE(M_USERFW, "userfw", "Memory for userfw rules and cache");
SYSCTL_NODE(_net, OID_AUTO, userfw, CTLFLAG_RW, 0, "userfw parameters");

#define MTAG_USERFW_CALL_STACK	1325855656

struct call_stack_entry
{
	SLIST_ENTRY(call_stack_entry)	next;
	userfw_ruleset *ruleset;
	uint16_t	rule_number;
};

struct call_stack_mtag
{
	struct m_tag	tag;
	SLIST_HEAD(call_stack_head, call_stack_entry) call_stack;
};

static struct call_stack_entry * get_stack_entry(struct mbuf *m, userfw_ruleset *ruleset);
static int is_top_of_stack(struct mbuf *m, userfw_ruleset *ruleset);
static struct call_stack_entry * add_to_stack(struct mbuf *m, userfw_ruleset *ruleset);
static int remove_from_stack(struct mbuf *m, struct call_stack_entry *entry);

int userfw_init()
{
	int err = 0;

	SLIST_INIT(&userfw_modules_list);
	rw_init(&userfw_modules_list_mtx, "userfw modules list lock");

	userfw_ruleset_init(&global_rules, "userfw global ruleset lock");

	if (!err)
		err = userfw_pfil_register();

	if (!err)
		err = userfw_domain_init();

	return err;
}

int userfw_uninit()
{
	int err = 0;

	err = userfw_domain_uninit();
	
	if (!err)
		err = userfw_pfil_unregister();

	if (!err)
	{
		rw_destroy(&userfw_modules_list_mtx);

		userfw_ruleset_uninit(&global_rules, M_USERFW);
	}

	return err;
}

int
userfw_chk(struct mbuf **mb, userfw_chk_args *args)
{
	return check_packet(mb, args, &global_rules);
}

int
check_packet(struct mbuf **mb, userfw_chk_args *args, userfw_ruleset *ruleset)
{
	userfw_rule *rule = ruleset->rule;
	userfw_cache cache;
	int ret = 0, matched = 0, continue_ = 0, packet_seen = 0;
	struct call_stack_entry *cs_entry = NULL;

	if ((*mb) == NULL)
	{
		printf("check_packet: *mb == NULL\n");
		return EACCES;
	}

	cs_entry = get_stack_entry(*mb, ruleset);
	if (cs_entry == NULL)
	{
		cs_entry = add_to_stack(*mb, ruleset);
		if (cs_entry != NULL)
			cs_entry->rule_number = 0;
	}
	else
		packet_seen = 1;

	userfw_cache_init(&cache);

	USERFW_RLOCK(ruleset);

	if (packet_seen && cs_entry != NULL)
	{
		while(rule != NULL && rule->number < cs_entry->rule_number)
			rule = rule->next;
		if (rule != NULL && is_top_of_stack(*mb, ruleset) &&
				rule->number == cs_entry->rule_number)
			rule = rule->next;
	}

	while(rule != NULL)
	{
		if (cs_entry != NULL)
			cs_entry->rule_number = rule->number;
		if (rule->match.do_match(mb, args, &(rule->match), &cache))
		{
			if ((*mb) == NULL)
			{
				ret = EACCES;
				break;
			}
			ret = rule->action.do_action(mb, args, &(rule->action), &cache, &continue_);
			if (continue_ == 0)
			{
				matched = 1;
				break;
			}
		}
		if ((*mb) == NULL)
		{
			ret = EACCES;
			break;
		}
		rule = rule->next;
	}

	USERFW_RUNLOCK(ruleset);

	if ((*mb) != NULL)
		remove_from_stack(*mb, cs_entry);

	if (!matched)
#ifdef USERFW_DEFAULT_TO_DENY
		ret = EACCES;
#else
		ret = 0;
#endif

	userfw_cache_cleanup(&cache);

	return ret;
}

static struct call_stack_entry *
get_stack_entry(struct mbuf *m, userfw_ruleset *ruleset)
{
	struct call_stack_mtag *mtag;
	struct call_stack_entry *entry = NULL;

	mtag = (struct call_stack_mtag *)m_tag_locate(m, MTAG_USERFW_CALL_STACK, 0, NULL);
	if (mtag != NULL)
	{
		SLIST_FOREACH(entry, &(mtag->call_stack), next)
		{
			if (entry->ruleset == ruleset)
				return entry;
		}
	}
	return NULL;
}

static int
is_top_of_stack(struct mbuf *m, userfw_ruleset *ruleset)
{
	struct call_stack_mtag *mtag;

	mtag = (struct call_stack_mtag *)m_tag_locate(m, MTAG_USERFW_CALL_STACK, 0, NULL);
	if (mtag != NULL && SLIST_FIRST(&(mtag->call_stack))->ruleset == ruleset)
		return 1;
	return 0;
}

static void
free_call_stack(struct m_tag *tag)
{
	struct call_stack_mtag *mtag = (struct call_stack_mtag *)tag;
	struct call_stack_entry *entry;

	while(!SLIST_EMPTY(&(mtag->call_stack)))
	{
		entry = SLIST_FIRST(&(mtag->call_stack));
		SLIST_REMOVE_HEAD(&(mtag->call_stack), next);
		free(entry, M_TEMP);
	}
}

static struct call_stack_mtag *
init_call_stack(struct mbuf *m)
{
	struct call_stack_mtag *mtag;

	mtag = (struct call_stack_mtag *)m_tag_alloc(MTAG_USERFW_CALL_STACK, 0, sizeof(struct call_stack_mtag), M_NOWAIT);
	if (mtag != NULL)
	{
		SLIST_INIT(&(mtag->call_stack));
		mtag->tag.m_tag_free = free_call_stack;
		m_tag_prepend(m, &(mtag->tag));
	}
	return mtag;
}

/* Return value can be null if malloc(9) failed to allocate memory */
static struct call_stack_entry *
add_to_stack(struct mbuf *m, userfw_ruleset *ruleset)
{
	struct call_stack_mtag *mtag;
	struct call_stack_entry *entry = NULL;

	mtag = (struct call_stack_mtag *)m_tag_locate(m, MTAG_USERFW_CALL_STACK, 0, NULL);
	if (mtag == NULL)
		mtag = init_call_stack(m);
	if (mtag != NULL)
	{
		entry = malloc(sizeof(*entry), M_TEMP, M_NOWAIT);
		if (entry != NULL)
		{
			entry->ruleset = ruleset;
			SLIST_INSERT_HEAD(&(mtag->call_stack), entry, next);
		}
	}
	return entry;
}

static int
remove_from_stack(struct mbuf *m, struct call_stack_entry *entry)
{
	struct call_stack_mtag *mtag;

	mtag = (struct call_stack_mtag *)m_tag_locate(m, MTAG_USERFW_CALL_STACK, 0, NULL);
	if (mtag != NULL)
	{
		SLIST_REMOVE(&(mtag->call_stack), entry, call_stack_entry, next);
		free(entry, M_TEMP);
	}
	return 0;
}
