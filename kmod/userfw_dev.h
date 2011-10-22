#ifndef USERFW_DEV_H
#define USERFW_DEV_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>

int userfw_dev_register(void);
int userfw_dev_unregister(void);

d_open_t	userfw_dev_open;
d_close_t	userfw_dev_close;
d_ioctl_t	userfw_dev_ioctl;
d_read_t	userfw_dev_read;
d_write_t	userfw_dev_write;

#endif /* USERFW_DEV_H */
