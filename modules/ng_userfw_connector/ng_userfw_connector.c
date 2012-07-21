/*-
 * Copyright (C) 2012 by Maxim Ignatenko <gelraen.ua@gmail.com>
 * Some parts taken from ng_ipfw.c by Gleb Smirnoff <glebius@FreeBSD.org>
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
#include <sys/ctype.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include <userfw/ruleset.h>
#include "ng_userfw_connector.h"

/*
 * netgraph part
 */

static ng_constructor_t	ng_userfw_constructor;
static ng_shutdown_t	ng_userfw_shutdown;
static ng_newhook_t	ng_userfw_newhook;
static ng_connect_t	ng_userfw_connect;
static ng_rcvdata_t	ng_userfw_rcvdata;
static ng_disconnect_t	ng_userfw_disconnect;
static ng_findhook_t	ng_userfw_findhook;
static int ng_connector_modevent(module_t, int, void *);

static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =	NG_USERFW_CONNECTOR_NODE_TYPE,
	.constructor =	ng_userfw_constructor,
	.shutdown =	ng_userfw_shutdown,
	.newhook =	ng_userfw_newhook,
	.connect =	ng_userfw_connect,
	.rcvdata =	ng_userfw_rcvdata,
	.disconnect = ng_userfw_disconnect,
	.mod_event = ng_connector_modevent,
	.findhook = ng_userfw_findhook
};

struct hookprivate
{
	hook_p	hook;
	uint32_t	cookie;
};
typedef struct hookprivate *hpriv_p;

static node_p	userfw_connector_node = NULL;

static int
ng_userfw_constructor(node_p node)
{
	return EINVAL;
}

static int
ng_userfw_newhook(node_p node, hook_p hook, const char *name)
{
	hpriv_p	hpriv;
	uint32_t	cookie;
	const char	*cp;
	char	*endptr;

	/* Protect from leading zero */
	if (name[0] == '0' && name[1] != '\0')
		return EINVAL;

	/* Check that name contains only digits */
	for (cp = name; *cp != '\0'; cp++)
		if (!isdigit(*cp))
			return EINVAL;

	/* Convert it to integer */
	cookie = (uint32_t)strtol(name, &endptr, 10);
	if (*endptr != '\0')
		return EINVAL;

	/* Allocate memory for this hook's private data */
	hpriv = malloc(sizeof(*hpriv), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (hpriv== NULL)
		return ENOMEM;

	hpriv->hook = hook;
	hpriv->cookie = cookie;

	NG_HOOK_SET_PRIVATE(hook, hpriv);

	return 0;
}

static int
ng_userfw_rcvdata(hook_p hook, item_p item)
{
	struct mbuf *mb;
	int err = 0;

	NGI_GET_M(item, mb);
	NG_FREE_ITEM(item);

	err = userfw_return_packet(&mb);
	if (mb != NULL)
	{
		NG_FREE_M(mb);
	}

	return err;
}

static int
ng_userfw_shutdown(node_p node)
{
	NG_NODE_UNREF(node);
	return 0;
}

static int
ng_userfw_connect(hook_p hook)
{
	NG_HOOK_FORCE_QUEUE(hook);
	return 0;
}

static int
ng_userfw_disconnect(hook_p hook)
{
	hpriv_p hpriv = NG_HOOK_PRIVATE(hook);

	free(hpriv, M_NETGRAPH);
	NG_HOOK_SET_PRIVATE(hook, NULL);

	return 0;
}

static hook_p
ng_userfw_findhook_by_cookie(node_p node, uint32_t cookie)
{
	hook_p	hook;
	hpriv_p	hpriv;

	LIST_FOREACH(hook, &node->nd_hooks, hk_hooks) {
		hpriv = NG_HOOK_PRIVATE(hook);
		if (NG_HOOK_IS_VALID(hook) && (hpriv->cookie == cookie))
			return hook;
	}

	return NULL;
}

static hook_p
ng_userfw_findhook(node_p node, const char *name)
{
	uint32_t	n;
	char	*endptr;

	n = (uint32_t)strtol(name, &endptr, 10);
	if (*endptr != '\0')
		return NULL;
	return ng_userfw_findhook_by_cookie(node, n);
}

static int
send_to_netgraph(struct mbuf *mb, uint32_t hook)
{
	hook_p	hookp;
	int err = 0;

	hookp = ng_userfw_findhook_by_cookie(userfw_connector_node, hook);
	if (hookp == NULL)
		return ESRCH;

	SET_NET_IPLEN(mtod(mb, struct ip *));
	NG_SEND_DATA_ONLY(err, hookp, mb);

	return err;
}

/*
 * userfw part
 */

static int
action_netgraph(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	uint32_t	hook;

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		hook = action->args[0].uint32.value;

		if (send_to_netgraph(*mb, hook) != 0)
		{
			// sending packet to netgraph failed for some reason, so we are responsible to free mbuf
			m_freem(*mb);
		}
		*mb = NULL;
	}

	*continue_ = 0;
	return 0;
}

static int
action_ngtee(struct mbuf **mb, userfw_chk_args *args, userfw_action *action, userfw_cache *cache, int *continue_, uint32_t flags)
{
	uint32_t	hook;
	struct mbuf	*copied = NULL;

	if ((flags & USERFW_ACTION_FLAG_SECOND_PASS) == 0)
	{
		hook = action->args[0].uint32.value;
		copied = m_dup(*mb, M_NOWAIT);

		if (copied != NULL && send_to_netgraph(copied, hook) != 0)
		{
			// sending packet to netgraph failed for some reason, so we are responsible to free mbuf
			m_freem(copied);
		}
	}

	*continue_ = 1;
	return 0;
}

static userfw_action_descr ng_connector_actions[] = {
	{A_NETGRAPH,	1,	{T_UINT32},	"netgraph",	action_netgraph}
	,{A_NGTEE,	1,	{T_UINT32},	"ngtee",	action_ngtee}
};

static userfw_modinfo ng_connector_modinfo =
{
	.id = USERFW_NG_CONNECTOR_MOD,
	.name = "ng_connector",
	.nactions = sizeof(ng_connector_actions)/sizeof(ng_connector_actions[0]),
	.nmatches = 0,
	.ncmds = 0,
	.actions = ng_connector_actions,
	.matches = NULL,
	.cmds = NULL
};

static int
ng_connector_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ng_connector_modinfo);
		if (err == 0)
		{
			err = ng_make_node_common(&typestruct, &userfw_connector_node);
			if (err != 0)
			{
				printf("ng_userfw_connector: unable to create node\n");
				break;
			}
			if (ng_name_node(userfw_connector_node, "userfw") != 0)
			{
				printf("ng_userfw_connector: unable to name created node\n");
			}
		}
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_NG_CONNECTOR_MOD);
		userfw_connector_node = NULL;
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ng_connector_mod =
{
	"ng_userfw_connector",
	ng_mod_event,
	&typestruct
};

MODULE_VERSION(ng_userfw_connector, 1);
MODULE_DEPEND(ng_userfw_connector, userfw_core, 1, 1, 1);
MODULE_DEPEND(ng_userfw_connector, netgraph, NG_ABI_VERSION, NG_ABI_VERSION, NG_ABI_VERSION);

DECLARE_MODULE(ng_userfw_connector, ng_connector_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
