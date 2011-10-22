#include "userfw.h"
#include "userfw_dev.h"

int userfw_init()
{
	int err = 0;

	err = userfw_dev_register();

	return err;
}

int userfw_uninit()
{
	int err = 0;

	err = userfw_dev_unregister();

	return err;
}
