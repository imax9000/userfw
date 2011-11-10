#include "userfw.h"
#include <userfw/cache.h>

int
userfw_cache_init(userfw_cache * p)
{
	return 0;
}

int
userfw_cache_cleanup(userfw_cache * p)
{
	return 0;
}

int
userfw_cache_write(userfw_cache * p, userfw_module_id_t mod, uint16_t id, size_t len, void* data)
{
	return 0;	
}

void *
userfw_cache_read(userfw_cache * p, userfw_module_id_t mod, uint16_t id, size_t *len)
{
	return NULL;
}
