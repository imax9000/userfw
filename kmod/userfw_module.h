#ifndef __USERFW_MODULE_H
#define __USERFW_MODULE_H

#include <userfw/types.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/queue.h>

struct modinfo_entry
{
	userfw_modinfo	*data;
	SLIST_ENTRY(modinfo_entry) entries;
};

typedef SLIST_HEAD(__userfw_modules_head, modinfo_entry) userfw_modules_head_t;

extern userfw_modules_head_t userfw_modules_list;
extern struct rwlock userfw_modules_list_mtx;

#endif /* __USERFW_MODULE_H */
