#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include "base.h"
#include <userfw/module.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <sys/mbuf.h>

enum __base_actions
{
	A_ALLOW
	,A_DENY
};

static int
action_allow(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache)
{
	return 0;
}

static int
action_deny(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache)
{
	return EACCES;
}

static userfw_action_descr base_actions[] = {
	{A_ALLOW,	0,	0,	{},	"allow",	action_allow}
	,{A_DENY,	0,	0,	{},	"deny",	action_deny}
};

enum __base_matches
{
	M_IN = USERFW_IN
	,M_OUT = USERFW_OUT
	,M_SRCIPV4
	,M_DSTIPV4
	,M_SRCPORT
	,M_DSTPORT
	,M_OR
	,M_AND
};

static int
match_direction(struct mbuf **mb, userfw_chk_args *args, userfw_match *m, userfw_cache *cache)
{
	if (args->dir == m->op)
		return 1;
	else
		return 0;
}

static int
match_ipv4(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache)
{
	struct mbuf *m = *mb;
	uint32_t	val = 0;
	struct ip *ip = mtod(m, struct ip *);

	if (ip->ip_v != 4)
		return 0;

	switch (match->op)
	{
	case M_SRCIPV4:
		val = ip->ip_src.s_addr;
		break;
	case M_DSTIPV4:
		val = ip->ip_dst.s_addr;
		break;
	}

	if ((val & match->args[0].ipv4.mask) ==
		(match->args[0].ipv4.addr & match->args[0].ipv4.mask))
		return 1;

	return 0;
}

static int
match_port(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache)
{
	struct mbuf	*m = *mb;
	uint16_t	val = 0;
	struct ip	*ip = mtod(m, struct ip *);
	struct tcphdr	*tcp;
	struct udphdr	*udp;
	struct sctphdr	*sctp;
	int	ip_header_len = (ip->ip_hl) << 2;

	switch (ip->ip_p)
	{
	case IPPROTO_TCP:
		(*mb) = m = m_pullup(m, ip_header_len + sizeof(struct tcphdr));
		if (m != NULL)
		{
			tcp = (struct tcphdr *)(mtod(m, uint8_t *) + ip_header_len);
			switch (match->op)
			{
			case M_SRCPORT:
				val = tcp->th_sport;
				break;
			case M_DSTPORT:
				val = tcp->th_dport;
				break;
			}
		}
		else
		{
			printf("userfw_base: TCP header pullup failed\n");
			return 0;
		}
		break;
	case IPPROTO_UDP:
		(*mb) = m = m_pullup(m, ip_header_len + sizeof(struct udphdr));
		if (m != NULL)
		{
			udp = (struct udphdr *)(mtod(m, uint8_t *) + ip_header_len);
			switch (match->op)
			{
			case M_SRCPORT:
				val = udp->uh_sport;
				break;
			case M_DSTPORT:
				val = udp->uh_dport;
				break;
			}
		}
		else
		{
			printf("userfw_base: UDP header pullup failed\n");
			return 0;
		}
		break;
	case IPPROTO_SCTP:
		(*mb) = m = m_pullup(m, ip_header_len + sizeof(struct sctphdr));
		if (m != NULL)
		{
			sctp = (struct sctphdr *)(mtod(m, uint8_t *) + ip_header_len);
			switch (match->op)
			{
			case M_SRCPORT:
				val = sctp->src_port;
				break;
			case M_DSTPORT:
				val = sctp->dest_port;
				break;
			}
		}
		else
		{
			printf("userfw_base: SCTP header pullup failed\n");
			return 0;
		}
		break;
	default:
		return 0;
	}

	if (val == match->args[0].uint16.value)
		return 1;
	else
		return 0;
};

static int
match_logic(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache)
{
	userfw_match	*match1 = match->args[0].match.p;
	userfw_match	*match2 = match->args[1].match.p;
	int	ret1 = match1->do_match(mb, args, match1, cache);

	if ((*mb) == NULL)
		return 0;

	if (ret1 == 0 && match->op == M_AND)
		return 0;

	if (ret1 != 0 && match->op == M_OR)
		return ret1;

	return match2->do_match(mb, args, match2, cache);
}

static userfw_match_descr base_matches[] = {
	{M_IN,	0,	0,	{},	"in",	match_direction}
	,{M_OUT,	0,	0,	{},	"out",	match_direction}
	,{M_SRCIPV4,	1,	0,	{T_IPv4},	"src-ip",	match_ipv4}
	,{M_DSTIPV4,	1,	0,	{T_IPv4},	"dst-ip",	match_ipv4}
	,{M_SRCPORT,	1,	0,	{T_UINT16},	"src-port",	match_port}
	,{M_DSTPORT,	1,	0,	{T_UINT16},	"dst-port",	match_port}
	,{M_OR,	2,	0,	{T_MATCH, T_MATCH},	"or",	match_logic}
	,{M_AND,	2,	0,	{T_MATCH, T_MATCH}, "and",	match_logic}
};

static userfw_modinfo base_modinfo =
{
	USERFW_BASE_MOD,
	2,	/* nactions */
	8,	/* nmatches */
	base_actions,
	base_matches,
	"base"
};

static int
userfw_base_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&base_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_BASE_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t	userfw_base_mod = {
	"userfw_base",
	userfw_base_modevent,
	0
};

MODULE_VERSION(userfw_base, 1);
MODULE_DEPEND(userfw_base, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_base, userfw_base_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
