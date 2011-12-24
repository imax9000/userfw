/*-
 * Copyright (C) 2011 by Maxim Ignatenko <gelraen.ua@gmail.com>
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
		if (ufwreqs != NULL)
			err = EBUSY;
		else
		{
			UFWDOMAIN_LOCK_UNINIT;
		}
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
};

static void
userfw_sodetach(struct socket *so)
{
	UFWDOMAIN_RLOCK;
	if (ufwreqs != NULL && ufwreqs->pru_detach != NULL)
		ufwreqs->pru_detach(so);
	UFWDOMAIN_RUNLOCK;
};

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
};


#else /* I_AM_DOMAIN_STUB */

struct userfwpcb
{
	struct socket *sock;
};

static int
userfw_soattach(struct socket *so,
		int proto,
		struct thread *td)
{
	return 0;
};

static void
userfw_sodetach(struct socket *so)
{
};

static int
userfw_sosend(struct socket *so,
		int flags,
		struct mbuf *m,
		struct sockaddr *addr,
		struct mbuf *control,
		struct thread *td)
{
	return 0;
};

#endif /* I_AM_DOMAIN_STUB */

struct pr_usrreqs userfwreqs = {
	.pru_attach = userfw_soattach,
	.pru_detach = userfw_sodetach,
	.pru_send = userfw_sosend
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
