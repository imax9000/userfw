#include "userfw.h"
#include "userfw_dev.h"
#include "userfw_pfil.h"

int userfw_init()
{
	int err = 0;

	err = userfw_dev_register();

	if (!err)
		err = userfw_pfil_register();

	return err;
}

int userfw_uninit()
{
	int err = 0;

	err = userfw_pfil_unregister();

	if (!err)
		err = userfw_dev_unregister();

	return err;
}

userfw_action
userfw_chk(struct mbuf **mb, userfw_chk_args *args)
{
	userfw_action ret;
	ret.type = A_ALLOW;
	
	return ret;
}
