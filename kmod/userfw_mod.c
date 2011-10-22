#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>

static int
userfw_modevent(module_t mod, int type, void *p)
{
	int err = 0;

	switch (type)
	{
	case MOD_LOAD:
		printf("userfw loaded\n");
		break;
	case MOD_UNLOAD:
		printf("userfw unloaded\n");
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t userfw_mod = {
	"userfw",
	userfw_modevent,
	0
};

DECLARE_MODULE(userfw, userfw_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);
