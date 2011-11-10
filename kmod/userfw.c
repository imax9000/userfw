#include "userfw.h"
#include "userfw_dev.h"
#include "userfw_pfil.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>

userfw_ruleset global_rules;

userfw_modinfo *userfw_modules;
int userfw_modules_count;

void init_ruleset(userfw_ruleset *p);
void delete_ruleset(userfw_ruleset *p);
int check_packet(struct mbuf **mb, int global, userfw_chk_args *args, userfw_ruleset *ruleset);
void delete_match_data(userfw_match *match);
void delete_action_data(userfw_action *match);

MALLOC_DEFINE(M_USERFW, "userfw", "Memory for userfw rules and cache");

int userfw_init()
{
	int err = 0;

	err = userfw_dev_register();

	init_ruleset(&global_rules);

	USERFW_INIT_LOCK(&global_rules, "userfw global ruleset lock");

	if (!err)
		err = userfw_pfil_register();

	return err;
}

int userfw_uninit()
{
	int err = 0;

	err = userfw_pfil_unregister();

	USERFW_UNINIT_LOCK(&global_rules);
	
	delete_ruleset(&global_rules);

	if (!err)
		err = userfw_dev_unregister();

	return err;
}

int
userfw_chk(struct mbuf **mb, userfw_chk_args *args)
{
	return check_packet(mb, 1, args, &global_rules);
}

void
init_ruleset(userfw_ruleset *p)
{
	p->rule = NULL;
}

void
delete_match_data(userfw_match *match)
{
	int i;

	for(i = 0; i < match->nargs; i++)
	{
		switch (match->args[i].type)
		{
		case T_STRING:
			free(match->args[i].string.data, M_USERFW);
			break;
		case T_MATCH:
			delete_match_data(match->args[i].match.p);
			free(match->args[i].match.p, M_USERFW);
			break;
		}
	}
}

void
delete_action_data(userfw_action *match)
{
	int i;

	for(i = 0; i < match->nargs; i++)
	{
		switch (match->args[i].type)
		{
		case T_STRING:
			free(match->args[i].string.data, M_USERFW);
			break;
		}
	}
}

void
delete_ruleset(userfw_ruleset *p)
{
	userfw_rule *current = p->rule, *next;

	while(current != NULL)
	{
		next = current->next;
		delete_match_data(&(current->match));
		delete_action_data(&(current->action));
		free(current, M_USERFW);
		current = next;
	}
}

int
check_packet(struct mbuf **mb, int global, userfw_chk_args *args, userfw_ruleset *ruleset)
{
	userfw_rule *rule = ruleset->rule;
	userfw_cache cache;
	int ret, matched = 0;

	userfw_cache_init(&cache);

	USERFW_RLOCK(ruleset);

	while(rule != NULL)
	{
		if (rule->match.do_match(mb, args, &(rule->match), &cache))
		{
			ret = rule->action.do_action(mb, args, &(rule->action), &cache);
			matched = 1;
			break;
		}
		rule = rule->next;
	}

	USERFW_RUNLOCK(ruleset);

	if (!matched)
#ifdef USERFW_DEFAULT_TO_DENY
		ret = EACCES;
#else
		ret = 0;
#endif

	userfw_cache_cleanup(&cache);

	return ret;
}
