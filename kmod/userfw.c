#include "userfw.h"
#include "userfw_dev.h"
#include "userfw_pfil.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>

struct match_cache
{
	uint8_t	ports_found;
	uint8_t	uid_found;
	uint8_t	imagename_found;
	uint8_t	imagepath_found;
	uint8_t	imagemd5_found;

	uint16_t	src_port;
	uint16_t	dst_port;
	
	uint32_t	uid;
	char	*imagename;
	char	*imagepath;
	char	*imagemd5;
};

userfw_ruleset global_rules;

void init_ruleset(userfw_ruleset *p, int default_deny);
void delete_ruleset(userfw_ruleset *p);
userfw_action check_packet(struct mbuf **mb, int global, userfw_chk_args *args, userfw_ruleset *ruleset);
int match_packet(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, struct match_cache *cache);
void delete_match_data(userfw_match *match);

MALLOC_DEFINE(M_USERFW, "userfw", "Memory for userfw rules and cache");

int userfw_init()
{
	int err = 0;

	err = userfw_dev_register();

	init_ruleset(&global_rules,
#ifndef	USERFW_DEFAULT_TO_DENY
		0
#else
		1
#endif
		);

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

userfw_action
userfw_chk(struct mbuf **mb, userfw_chk_args *args)
{
	return check_packet(mb, 1, args, &global_rules);
}

void
init_ruleset(userfw_ruleset *p, int default_deny)
{
	p->rule = malloc(sizeof(userfw_rule), M_USERFW, M_WAITOK | M_ZERO);
	if (p->rule != NULL)
	{
		p->rule->next = NULL;
		p->rule->number = (uint16_t)0xffff;
		p->rule->action.type = default_deny ? A_DENY : A_ALLOW;
		p->rule->match.type = M_ANY;
	}
}

void
delete_match_data(userfw_match *match)
{
	int i;

	switch(match->type)
	{
	case M_AND:
	case M_OR:
		for(i = 0; i < match->LogicBlock.count; i++)
		{
			delete_match_data(&(match->LogicBlock.rules[i]));
			free(&(match->LogicBlock.rules[i]), M_USERFW);
		}
		break;
	case M_NOT:
		delete_match_data(match->NotBlock.rule);
		free(match->NotBlock.rule, M_USERFW);
		break;
	case M_IMAGENAME:
	case M_IMAGEPATH:
	case M_IMAGEMD5:
		free(match->MatchImage.str, M_USERFW);
		break;
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
		free(current, M_USERFW);
		current = next;
	}
}

userfw_action
check_packet(struct mbuf **mb, int global, userfw_chk_args *args, userfw_ruleset *ruleset)
{
	userfw_rule *rule = ruleset->rule;
	struct match_cache cache;
	userfw_action ret;
	struct ip *ip = mtod(*mb, struct ip *);
	struct mbuf *m = *mb;

	bzero(&cache, sizeof(struct match_cache));

	if ((ntohs(ip->ip_off) & IP_OFFMASK) != 0)
	{
		/* pass fragments untouched for now */
		ret.type = A_ALLOW;
		return ret;
	}

	switch(ip->ip_p)
	{
	case IPPROTO_TCP:
		m = m_pullup(*mb, sizeof(struct tcphdr));
		cache.ports_found = 1;
		cache.src_port = mtod(m, struct tcphdr *)->th_sport;
		cache.dst_port = mtod(m, struct tcphdr *)->th_dport;
		break;
	case IPPROTO_UDP:
		m = m_pullup(*mb, sizeof(struct udphdr));
		cache.ports_found = 1;
		cache.src_port = mtod(m, struct udphdr *)->uh_sport;
		cache.dst_port = mtod(m, struct udphdr *)->uh_dport;
		break;
	case IPPROTO_SCTP:
		m = m_pullup(*mb, sizeof(struct sctphdr));
		cache.ports_found = 1;
		cache.src_port = mtod(m, struct sctphdr *)->src_port;
		cache.dst_port = mtod(m, struct sctphdr *)->dest_port;
		break;
	}
	
	if (m == NULL)
	{
		printf("userfw: pullup failed\n");
		ret.type = A_DENY;
		return ret;
	}
	*mb = m;

	USERFW_RLOCK(ruleset);

	while(rule != NULL)
	{
		if (match_packet(mb, args, &(rule->match), &cache))
		{
			ret = rule->action;
			break;
		}
		rule = rule->next;
	}

	USERFW_RUNLOCK(ruleset);

	return ret;
}

int
match_packet(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, struct match_cache *cache)
{
	int i;
	struct mbuf *m = *mb;

	switch(match->type)
	{
	case M_ANY:
		return 1;
	case M_OR:
		for(i = 0; i < match->LogicBlock.count; i++)
		{
			if (match_packet(mb, args, &(match->LogicBlock.rules[i]), cache))
				return 1;
		}
		return 0;
	case M_AND:
		for(i = 0; i < match->LogicBlock.count; i++)
		{
			if (!match_packet(mb, args, &(match->LogicBlock.rules[i]), cache))
				return 0;
		}
		return 1;
	case M_NOT:
		return !match_packet(mb, args, match->NotBlock.rule, cache);
	case M_SRCIPV4:
		return (mtod(m, struct ip *))->ip_src.s_addr == match->MatchIPv4Addr.addr;
	case M_DSTIPV4:
		return (mtod(m, struct ip *))->ip_dst.s_addr == match->MatchIPv4Addr.addr;
	case M_SRCPORT:
		return cache->ports_found && match->MatchPort.port == cache->src_port;
	case M_DSTPORT:
		return cache->ports_found && match->MatchPort.port == cache->dst_port;
	}
	
	return 0;
}
