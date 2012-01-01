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
