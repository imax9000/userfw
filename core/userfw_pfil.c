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


#include "userfw_pfil.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/pfil.h>
#include "userfw.h"

int userfw_pfil_hook(void *arg, struct mbuf **mb, struct ifnet *ifp, int dir, struct inpcb *pcb);
int userfw_pfil_attach(int attach);

int
userfw_pfil_register(void)
{
	return userfw_pfil_attach(1);
}

int
userfw_pfil_unregister(void)
{
	return userfw_pfil_attach(0);
}

int
userfw_pfil_hook(void *arg, struct mbuf **mb, struct ifnet *ifp, int dir, struct inpcb *pcb)
{
	userfw_chk_args args;
	
	args.af = (long)arg;
	args.ifp = ifp;
	args.dir = (dir == PFIL_IN) ? USERFW_IN : USERFW_OUT; /* looks ugly */
	args.inpcb = pcb;

	return userfw_chk(mb, &args);
}

int
userfw_pfil_attach(int attach)
{
	struct pfil_head *ip4_head;
	int err = 0;
	
	ip4_head = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	if (ip4_head == NULL)
		return ENOENT;

	err = (attach ? pfil_add_hook : pfil_remove_hook)
		(userfw_pfil_hook, (void*)AF_INET, PFIL_IN | PFIL_OUT | PFIL_WAITOK, ip4_head);

	return err;
}
