#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include "userfw.h"

static int
userfw_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		err = userfw_init();
		printf("userfw loaded\n");
		break;
	case MOD_UNLOAD:
		err = userfw_uninit();
		printf("userfw unloaded\n");
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t userfw_mod = {
	"userfw_core",
	userfw_modevent,
	0
};

MODULE_VERSION(userfw_core, 1);

DECLARE_MODULE(userfw_core, userfw_mod, SI_SUB_USERFW, SI_ORDER_USERFW_CORE);
