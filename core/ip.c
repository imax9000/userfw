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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include "ip.h"
#include <userfw/module.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <sys/mbuf.h>
#include "userfw_module.h"
#include <userfw/io.h>
#include <userfw/ruleset.h>

static int
match_port(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	struct mbuf	*m = *mb;
	uint16_t	val = 0;
	struct ip	*ip = mtod(m, struct ip *);
	struct tcphdr	*tcp;
	struct udphdr	*udp;
	struct sctphdr	*sctp;
	int	ip_header_len = (ip->ip_hl) << 2;

	VERIFY_OPCODE2(match, USERFW_IP_MOD, M_SRCPORT, M_DSTPORT, 0);

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

	if (ntohs(val) == match->args[0].uint16.value)
		return 1;
	else
		return 0;
};

static int
match_ip_ver(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	struct mbuf *m = *mb;
	int needed_ver = 0;
	
	VERIFY_OPCODE2(match, USERFW_IP_MOD, M_IPV4, M_IPV6, 0);

	switch(match->op)
	{
	case M_IPV4:
		needed_ver = 4;
		break;
	case M_IPV6:
		needed_ver = 6;
		break;
	}

	if (((mtod(m, char *)[0] & 0xf0) >> 4) == needed_ver)
		return 1;
	else
		return 0;
}

static int
match_ip_proto(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	struct mbuf *m = *mb;
	struct ip *ip = mtod(m, struct ip *);
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	unsigned char val = 0;

	VERIFY_OPCODE2(match, USERFW_IP_MOD, M_IP_PROTO, M_IP_PROTO_NAME, 0);
	
	switch(ip->ip_v)
	{
	case 4:
		val = ip->ip_p;
		break;
	case 6:
		val = ip6->ip6_nxt;
		break;
	default:
		return 0; /* unknown IP version */
	}

	if ((match->op == M_IP_PROTO && val == match->args[0].uint16.value) ||
		(match->op == M_IP_PROTO_NAME && val == (long)(match->priv)))
		return 1;
	else
		return 0;
}

static const int proto_count = 5;
static const char *proto_names[] = {
	"tcp"
	,"udp"
	,"sctp"
	,"ip"
	,"icmp"
};

static const unsigned char proto_numbers[] = {
	IPPROTO_TCP
	,IPPROTO_UDP
	,IPPROTO_SCTP
	,IPPROTO_IPV4
	,IPPROTO_ICMP
};

static int
match_ip_proto_ctor(userfw_match *match)
{
	int i;

	for(i = 0; i < proto_count; i++)
	{
		if (memcmp(proto_names[i], match->args[0].string.data, match->args[0].string.length) == 0)
		{
			match->priv = (void*)(long)(proto_numbers[i]);
			return 0;
		}
	}

	return ENOENT;
}

static int
match_packet_len(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	uint32_t len = 0;

	VERIFY_OPCODE(match, USERFW_IP_MOD, M_PKT_LEN, 0);
	switch(mtod(*mb, struct ip *)->ip_v)
	{
	case 4:
		len = ntohs(mtod(*mb, struct ip *)->ip_len);
		break;
	case 6:
		len = ntohs(mtod(*mb, struct ip6_hdr *)->ip6_plen) + sizeof(struct ip6_hdr);
		break;
	}

	if (match->args[0].uint32.value == len)
		return 1;
	else
		return 0;
}

static userfw_match_descr ip_matches[] = {
	{M_SRCPORT,	1,	{T_UINT16},	"src-port",	match_port}
	,{M_DSTPORT,	1,	{T_UINT16},	"dst-port",	match_port}
	,{M_IPV4,	0,	{},	"ipv4",	match_ip_ver}
	,{M_IPV6,	0,	{},	"ipv6",	match_ip_ver}
	,{M_IP_PROTO,	1,	{T_UINT16},	"proto-num",	match_ip_proto}
	,{M_IP_PROTO_NAME,	1, {T_STRING},	"proto",	match_ip_proto, match_ip_proto_ctor}
	,{M_PKT_LEN,	1,	{T_UINT32},	"packet-len",	match_packet_len}
};

static userfw_modinfo ip_modinfo =
{
	.id = USERFW_IP_MOD,
	.nactions = 0,
	.nmatches = sizeof(ip_matches)/sizeof(ip_matches[0]),
	.ncmds = 0,
	.actions = NULL,
	.matches = ip_matches,
	.cmds = NULL,
	.name = "ip"
};

static int
userfw_ip_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ip_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_IP_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t	userfw_ip_mod = {
	"userfw_ip",
	userfw_ip_modevent,
	0
};

MODULE_VERSION(userfw_ip, 1);
DEPEND_ON_USERFW_CORE(userfw_ip);

DECLARE_MODULE(userfw_ip, userfw_ip_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
