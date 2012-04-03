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
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "log.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>

#define L3HDR(T, ip)    ((T *)((u_int32_t *)(ip) + (ip)->ip_hl))


/*
 * XXX: will not work correctly with IPv6 extension headers
 */
static void
log_packet(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache)
{
	char *dir = (args->dir == USERFW_IN) ? "in" : "out";
	char *proto, *ipproto;
	struct ip *ip = mtod(*mb, struct ip *);
	struct ip6_hdr *ip6 = mtod(*mb, struct ip6_hdr *);
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;
	struct sctphdr *sctp = NULL;
	char action[USERFW_NAME_LEN+1] = {0};
	char src[64] = {0};
	char dst[64] = {0};
	char iface[IFNAMSIZ+1] = "UNKNOWN";
	int l4proto = -1;
	char ipproto_buf[4] = {0};
	char portbuf[16] = {0};
	uint16_t srcport, dstport;
	int have_ports = 0;

	switch(ip->ip_v)
	{
	case 4:
		proto = "IPv4";
		l4proto = ip->ip_p;
		inet_ntoa_r(ip->ip_src, src);
		inet_ntoa_r(ip->ip_dst, dst);
		tcp = L3HDR(struct tcphdr, ip);
		udp = L3HDR(struct udphdr, ip);
		sctp = L3HDR(struct sctphdr, ip);
		break;
	case 6:
		proto = "IPv6";
		l4proto = ip6->ip6_nxt;
		char buf[INET6_ADDRSTRLEN];
		snprintf(src, sizeof(src), "[%s]", ip6_sprintf(buf, &(ip6->ip6_src)));
		snprintf(dst, sizeof(dst), "[%s]", ip6_sprintf(buf, &(ip6->ip6_dst)));
		tcp = (struct tcphdr *)(((char *)ip6) + sizeof(struct ip6_hdr));
		udp = (struct udphdr *)(((char *)ip6) + sizeof(struct ip6_hdr));
		sctp = (struct sctphdr *)(((char *)ip6) + sizeof(struct ip6_hdr));
		break;
	default:
		proto = "UNKNOWN_L3";
		break;
	}

	switch(l4proto)
	{
	case -1:
		ipproto = "UNKNOWN_L4";
		break;
	case IPPROTO_TCP:
		ipproto = "TCP";
		srcport = tcp->th_sport;
		dstport = tcp->th_dport;
		have_ports = 1;
		break;
	case IPPROTO_UDP:
		ipproto = "UDP";
		srcport = udp->uh_sport;
		dstport = udp->uh_dport;
		have_ports = 1;
		break;
	case IPPROTO_SCTP:
		ipproto = "SCTP";
		srcport = sctp->src_port;
		dstport = sctp->dest_port;
		have_ports = 1;
		break;
	case IPPROTO_ICMP:
		ipproto = "ICMP";
		break;
	default:
		sprintf(ipproto_buf, "%d", l4proto & 0xff);
		ipproto = ipproto_buf;
		break;
	}

	if (have_ports)
	{
		snprintf(portbuf, sizeof(portbuf), ":%u", ntohs(srcport));
		strlcat(src, portbuf, sizeof(src));
		snprintf(portbuf, sizeof(portbuf), ":%u", ntohs(dstport));
		strlcat(dst, portbuf, sizeof(dst));
	}

	if (args->ifp != NULL)
	{
		bcopy(args->ifp->if_xname, iface, IFNAMSIZ);
	}

	if (a != NULL)
	{
		const userfw_action_descr *descr = userfw_mod_find_action(a->mod, a->op);
		if (descr != NULL)
		{
			bcopy(descr->name, action, USERFW_NAME_LEN);
		}
	}

	log(LOG_SECURITY | LOG_INFO, "userfw: %s %s %s %s %s %s via %s\n", action, proto, ipproto, src, dst, dir, iface);
}

static int
action_log(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	int ret = 0;

	*continue_ = 1;
	VERIFY_OPCODE2(action, USERFW_LOG_MOD, A_LOG, A_LOG_AND, 0);

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		log_packet(mb, args,
				(action->op == A_LOG) ? action : action->args[0].action.p,
				cache);
		if (action->op == A_LOG_AND)
			ret = action->args[0].action.p->do_action(mb, args, action->args[0].action.p, cache, continue_, flags);
	}

	return ret;
}

static userfw_action_descr log_actions[] =
{
	{A_LOG,	0,	{},	"log",	action_log}
	,{A_LOG_AND,	1,	{T_ACTION},	"log-and",	action_log}
};

static userfw_modinfo log_modinfo =
{
	.id = USERFW_LOG_MOD,
	.name = "log",
	.nactions = sizeof(log_actions)/sizeof(log_actions[0]),
	.nmatches = 0,
	.ncmds = 0,
	.actions = log_actions,
	.matches = NULL,
	.cmds = NULL
};

static int
log_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&log_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_LOG_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t log_mod =
{
	"userfw_log",
	log_modevent,
	0
};

MODULE_VERSION(userfw_log, 1);
MODULE_DEPEND(userfw_log, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_log, log_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
