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


#include <userfw/io.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>

#include "userfw_domain.h"
#include "userfw_module.h"

int userfw_reg_domain(struct pr_usrreqs *);
int userfw_unreg_domain(struct pr_usrreqs *);

#ifdef I_AM_DOMAIN_STUB

#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/module.h>

struct pr_usrreqs *ufwreqs;

static struct rwlock ufw_domain_lock;

#define UFWDOMAIN_LOCK_INIT	rw_init(&ufw_domain_lock, "userfw domain stub lock")
#define UFWDOMAIN_LOCK_UNINIT	rw_destroy(&ufw_domain_lock)
#define UFWDOMAIN_RLOCK	rw_rlock(&ufw_domain_lock)
#define UFWDOMAIN_RUNLOCK	rw_unlock(&ufw_domain_lock)
#define UFWDOMAIN_WLOCK	rw_wlock(&ufw_domain_lock)
#define UFWDOMAIN_WUNLOCK	rw_wunlock(&ufw_domain_lock)

int
userfw_reg_domain(struct pr_usrreqs *reqs)
{
	if (ufwreqs != NULL)
		return -1;

	UFWDOMAIN_WLOCK;
	ufwreqs = reqs;
	UFWDOMAIN_WUNLOCK;

	return 0;	
}

int
userfw_unreg_domain(struct pr_usrreqs *reqs)
{
	if (reqs != ufwreqs)
		return -1;

	UFWDOMAIN_WLOCK;
	ufwreqs = NULL;
	UFWDOMAIN_WUNLOCK;

	return 0;
}

static int
userfw_domain_stub_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		ufwreqs = NULL;
		UFWDOMAIN_LOCK_INIT;
		break;
	case MOD_UNLOAD:
		/* if (ufwreqs != NULL)
			err = EBUSY;
		else
		{
			UFWDOMAIN_LOCK_UNINIT;
		} */
		err = EBUSY;
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}

	return err;
}

static moduledata_t userfw_domain_stub_mod = {
	"userfw_domain_stub",
	userfw_domain_stub_modevent,
	0
};

MODULE_VERSION(userfw_domain_stub, 1);

DECLARE_MODULE(userfw_domain_stub,
		userfw_domain_stub_mod,
		SI_SUB_USERFW,
		SI_ORDER_USERFW_CORE-1);

static int
userfw_soattach(struct socket *so,
		int proto,
		struct thread *td)
{
	int r = EOPNOTSUPP;

	UFWDOMAIN_RLOCK;
	if (ufwreqs != NULL && ufwreqs->pru_attach != NULL)
		r = ufwreqs->pru_attach(so,proto,td);
	UFWDOMAIN_RUNLOCK;

	return r;
}

static void
userfw_sodetach(struct socket *so)
{
	UFWDOMAIN_RLOCK;
	if (ufwreqs != NULL && ufwreqs->pru_detach != NULL)
		ufwreqs->pru_detach(so);
	UFWDOMAIN_RUNLOCK;
}

static int
userfw_sosend(struct socket *so,
		int flags,
		struct mbuf *m,
		struct sockaddr *addr,
		struct mbuf *control,
		struct thread *td)
{
	int r = EOPNOTSUPP;

	UFWDOMAIN_RLOCK;
	if (ufwreqs != NULL && ufwreqs->pru_send != NULL)
		r = ufwreqs->pru_send(so,flags,m,addr,control,td);
	UFWDOMAIN_RUNLOCK;

	return r;
}

static int
userfw_connect(struct socket *so,
		struct sockaddr *nam,
		struct thread *td)
{
	int r = EOPNOTSUPP;
	
	UFWDOMAIN_RLOCK;
	if (ufwreqs != NULL && ufwreqs->pru_connect != NULL)
		r = ufwreqs->pru_connect(so,nam,td);
	UFWDOMAIN_RUNLOCK;

	return r;
}


#else /* I_AM_DOMAIN_STUB */

#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/mchain.h>
#include "userfw_cmd.h"

struct userfwpcb
{
	SLIST_ENTRY(userfwpcb) next;
	struct socket *sock;
	userfw_module_id_t	module;	/* to which module socket is connected */
	uid_t	uid;
};

/* TODO: make sysctl variables for so{rcv,snd}space */
static unsigned long sorcvspace = 8192;
static unsigned long sosndspace = 8192;

#define sotopcb(so)	((struct userfwpcb *)((so)->so_pcb))

SLIST_HEAD(socket_list, userfwpcb) socket_list_head =
	SLIST_HEAD_INITIALIZER(socket_list_head);

struct socket_list *so_list = NULL;
static struct mtx so_list_mtx;

extern struct pr_usrreqs userfwreqs;

int
userfw_domain_init(void)
{
	so_list = &socket_list_head;
	SLIST_INIT(so_list);

	mtx_init(&so_list_mtx, "userfw socket list", NULL, MTX_DEF);

#ifndef SKIP_DOMAIN_STUB
	userfw_reg_domain(&userfwreqs);
#endif

	return 0;
}

int
userfw_domain_uninit(void)
{
	if (!SLIST_EMPTY(so_list))
		return EBUSY;

#ifdef SKIP_DOMAIN_STUB
	return EBUSY; /* we cannot unregister domain */
#endif
#ifndef SKIP_DOMAIN_STUB
	userfw_unreg_domain(&userfwreqs);
#endif

	mtx_destroy(&so_list_mtx);

	return 0;
}

static int
userfw_soattach(struct socket *so,
		int proto,
		struct thread *td)
{
	struct userfwpcb *pcb = sotopcb(so);
	int err = 0;
	struct ucred *cred;

	if (pcb != NULL)
		return EISCONN;

	/* Reserve space for socket */
	err = soreserve(so, sosndspace, sorcvspace);
	if (err != 0)
		return err;

	/* Allocate pcb */
	pcb = malloc(sizeof(struct userfwpcb), M_PCB, M_WAITOK | M_ZERO);
	pcb->sock = so;
	cred = crhold(td->td_ucred);
	pcb->uid = cred->cr_uid;
	crfree(cred);
	so->so_pcb = (caddr_t)pcb;

	/* Add socket to list */
	mtx_lock(&so_list_mtx);
	SLIST_INSERT_HEAD(so_list, pcb, next);
	mtx_unlock(&so_list_mtx);

	so->so_state = so->so_state | SS_ISCONNECTED;

	return 0;
}

static void
userfw_sodetach(struct socket *so)
{
	struct userfwpcb *pcb = sotopcb(so);

	pcb->sock->so_pcb = NULL;
	/* remove socket from list */
	mtx_lock(&so_list_mtx);
	SLIST_REMOVE(so_list, pcb, userfwpcb, next);
	mtx_unlock(&so_list_mtx);

	/* destroy pcb */
	free(pcb, M_PCB);
}

#define SOCKBUF_LEN(sb) (sb).sb_cc

static int
userfw_sosend(struct socket *so,
		int flags,
		struct mbuf *m,
		struct sockaddr *addr_,
		struct mbuf *control,
		struct thread *td)
{
	int err = 0;
	userfw_module_id_t	dst_mod;
	struct userfwpcb *pcb = sotopcb(so);
	struct userfw_io_header msg;
	int cmd_ready = 0;
	unsigned char *data = NULL;
	struct sockaddr_userfw *addr = (struct sockaddr_userfw *)addr_;
	struct mdchain chain;

	if (pcb == NULL)
		err = ENOTCONN;

	if (control != NULL)
		err = EINVAL;

	SOCKBUF_LOCK(&(so->so_snd));

	if (err == 0)
	{
		if (addr == NULL)
			dst_mod = pcb->module;
		else
			dst_mod = addr->module;
		
		sbappendstream_locked(&(so->so_snd), m);
		m = NULL;

		md_initm(&chain, so->so_snd.sb_mb);
		if (SOCKBUF_LEN(so->so_snd) >= sizeof(msg))
		{
			md_get_mem(&chain, (caddr_t)(&msg), sizeof(msg), MB_MSYSTEM);
			if (SOCKBUF_LEN(so->so_snd) >= msg.length)
				cmd_ready = 1;
		}
	}

	if (err == 0 && cmd_ready)
	{
		if (msg.type != T_CONTAINER || (msg.subtype != ST_MESSAGE && msg.subtype != ST_CMDCALL))
		{
			cmd_ready = 0;
			sbdrop_locked(&(so->so_snd), msg.length);
		}
	}

	if (err == 0 && cmd_ready)
	{
		data = malloc(msg.length, M_USERFW, M_WAITOK);
		md_initm(&chain, so->so_snd.sb_mb);
		md_get_mem(&chain, data, msg.length, MB_MSYSTEM);

		err = userfw_cmd_dispatch(data, dst_mod, so, td);
		sbdrop_locked(&(so->so_snd), msg.length);
		free(data, M_USERFW);
	}

	SOCKBUF_UNLOCK(&(so->so_snd));

	if (control != NULL)
		m_freem(control);
	if (m != NULL)
		m_freem(m);

	return err;
}

static int
userfw_connect(struct socket *so,
		struct sockaddr *nam,
		struct thread *td)
{
	struct userfwpcb *pcb = sotopcb(so);
	struct sockaddr_userfw *addr = (struct sockaddr_userfw *)nam;

	if (pcb == NULL || nam == NULL || nam->sa_family != AF_USERFW)
		return EINVAL;

	if (userfw_mod_find(addr->module) == NULL)
	{
		return ECONNREFUSED;
	}
	pcb->module = addr->module;

	return 0;
}

int
userfw_domain_send_to_socket(struct socket *so, unsigned char *buf, size_t len)
{
	struct mbchain m;
	int err;

	mb_init(&m);
	err = mb_put_mem(&m, buf, len, MB_MSYSTEM);
	if (err != 0)
	{
		mb_done(&m);
		return err;
	}

	sbappendstream(&(so->so_rcv), mb_detach(&m));
	sorwakeup(so);

	return 0;
}

int
userfw_domain_send_to_uid(uid_t uid, unsigned char *buf, size_t len)
{
	struct userfwpcb *p;
	int count = 0;

	mtx_lock(&so_list_mtx);
	SLIST_FOREACH(p, so_list, next)
	{
		if (p->uid == uid)
		{
			if (userfw_domain_send_to_socket(p->sock, buf, len) == 0)
				count++;
		}
	}
	mtx_unlock(&so_list_mtx);

	return count;
}

#endif /* I_AM_DOMAIN_STUB */

struct pr_usrreqs userfwreqs = {
	.pru_attach = userfw_soattach,
	.pru_detach = userfw_sodetach,
	.pru_send = userfw_sosend,
	.pru_connect = userfw_connect
};

extern struct domain userfwdomain;

static struct protosw userfwsw[] = {
	{
		.pr_type = SOCK_STREAM,
		.pr_domain = &userfwdomain,
		.pr_protocol = 0,
		.pr_flags = 0,
		.pr_usrreqs = &userfwreqs
	}
};

struct domain userfwdomain = {
	.dom_family = AF_USERFW,
	.dom_name = "userfw",
	.dom_protosw = userfwsw,
	.dom_protoswNPROTOSW = &userfwsw[sizeof(userfwsw) / sizeof(userfwsw[0])]
};

#if defined(SKIP_DOMAIN_STUB) || defined (I_AM_DOMAIN_STUB)
DOMAIN_SET(userfw);
#endif
