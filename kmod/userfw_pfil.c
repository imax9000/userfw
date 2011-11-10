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
	
	args.af = (int)arg;
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
