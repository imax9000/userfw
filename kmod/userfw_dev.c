#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include "userfw_dev.h"

static struct cdevsw userfw_cdevsw = {
	.d_version = D_VERSION,
	.d_open = userfw_dev_open,
	.d_close = userfw_dev_close,
	.d_ioctl = userfw_dev_ioctl,
	.d_read = userfw_dev_read,
	.d_write = userfw_dev_write,
	.d_name = "userfw"
};

static struct cdev *userfw_dev;

int userfw_dev_register(void)
{
	int err = 0;

	userfw_dev = make_dev(&userfw_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666, "userfw");

	if (userfw_dev == NULL)
		err = EINVAL;

	return err;
}

int userfw_dev_unregister(void)
{
	if (userfw_dev != NULL)
	{
		destroy_dev(userfw_dev);
		userfw_dev = NULL;
	}

	return 0;
}

int
userfw_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return 0;
}

int
userfw_dev_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return 0;
}

int
userfw_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	return 0;
}

int
userfw_dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	return 0;
}

int
userfw_dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	return 0;
}
