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

#include <userfw/ruleset.h>
#include <userfw/module.h>
#include <sys/types.h>
#include <sys/malloc.h>

userfw_ruleset global_rules;

void
userfw_ruleset_init(userfw_ruleset *p, const char *name)
{
	p->rule = NULL;
	USERFW_INIT_LOCK(p, name);
}

static void
free_rule_chain(userfw_rule *p, struct malloc_type *mtype)
{
	userfw_rule *next;
	while(p != NULL)
	{
		next = p->next;
		free_rule(p, mtype);
		p = next;
	}
}

void
userfw_ruleset_uninit(userfw_ruleset *p, struct malloc_type *mtype)
{
	USERFW_UNINIT_LOCK(p);
	free_rule_chain(p->rule, mtype);
}

int
userfw_ruleset_insert_rule(userfw_ruleset *ruleset, userfw_rule *rule)
{
	int err = 0;
	userfw_rule *p;

	USERFW_WLOCK(ruleset);
	if (ruleset->rule == NULL) /* ruleset is empty */
	{
		ruleset->rule = rule;
		rule->next = NULL;
	}
	else
	{
		if (ruleset->rule->number > rule->number) /* new rule becomes first */
		{
			rule->next = ruleset->rule;
			ruleset->rule = rule;
		}
		else if (ruleset->rule->number == rule->number)
		{
			err = EEXIST;
		}
		else /* look for place where rule should be inserted */
		{
			p = ruleset->rule;
			while(p->next != NULL && p->next->number < rule->number)
				p = p->next;
			if (p->next == NULL)
			{
				p->next = rule;
				rule->next = NULL;
			}
			else if (p->next->number == rule->number)
			{
				err = EEXIST;
			}
			else
			{
				rule->next = p->next;
				p->next = rule;
			}
		}
	}
	USERFW_WUNLOCK(ruleset);

	return err;
}

int
userfw_ruleset_delete_rule(userfw_ruleset *ruleset, uint32_t num, struct malloc_type *mtype)
{
	userfw_rule *p, *p2;
	int err = 0;

	USERFW_WLOCK(ruleset);
	if (ruleset->rule == NULL)
		err = ENOENT;
	else
	{
		if (ruleset->rule->number == num)
		{
			p = ruleset->rule;
			ruleset->rule = p->next;
			free_rule(p, mtype);
		}
		else
		{
			p = ruleset->rule;
			while(p->next != NULL && p->next->number != num)
				p = p->next;
			if (p->next == NULL)
				err = ENOENT;
			else
			{
				p2 = p->next;
				p->next = p2->next;
				free_rule(p2, mtype);
			}
		}
	}
	USERFW_WUNLOCK(ruleset);

	return err;
}

int
userfw_ruleset_replace(userfw_ruleset *p, userfw_rule *head, struct malloc_type *mtype)
{
	USERFW_WLOCK(p);
	free_rule_chain(p->rule, mtype);
	p->rule = head;
	USERFW_WUNLOCK(p);
	return 0;
}

struct userfw_io_block *
userfw_ruleset_serialize(userfw_ruleset *p, struct malloc_type *mtype)
{
	struct userfw_io_block *msg = NULL;
	userfw_rule *rule;
	int count = 0;

	USERFW_RLOCK(p);
	rule = p->rule;
	while(rule != NULL)
	{
		count++;
		rule = rule->next;
	}
	
	msg = userfw_msg_alloc_container(T_CONTAINER, ST_RULESET, count, mtype);
	rule = p->rule;
	count = 0;
	while(rule != NULL)
	{
		userfw_msg_set_arg(msg, userfw_ruleset_serialize_rule(rule, mtype), count);
		count++;
		rule = rule->next;
	}
	USERFW_RUNLOCK(p);

	return msg;
}

struct userfw_io_block *
userfw_ruleset_serialize_rule(userfw_rule *p, struct malloc_type *mtype)
{
	struct userfw_io_block *msg;

	if (p == NULL)
		return NULL;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_RULE, 3, mtype);
	userfw_msg_insert_uint32(msg, ST_UNSPEC, p->number, 0, mtype);
	userfw_msg_insert_action(msg, ST_UNSPEC, &(p->action), 1, mtype);
	userfw_msg_insert_match(msg, ST_UNSPEC, &(p->match), 2, mtype);

	return msg;
}
