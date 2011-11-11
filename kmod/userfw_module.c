#include <userfw/module.h>
#include "userfw.h"
#include "userfw_module.h"

userfw_modules_head_t userfw_modules_list = SLIST_HEAD_INITIALIZER(userfw_modules_list);
struct rwlock userfw_modules_list_mtx;

int
userfw_mod_register(userfw_modinfo * mod)
{
	/* TODO */
	return 0;
}

int
userfw_mod_unregister(userfw_module_id_t id)
{
	/* TODO */
	return 0;
}
