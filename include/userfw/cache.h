#ifndef USERFW_CACHE_H
#define USERFW_CACHE_H

#include <userfw/types.h>

typedef struct __userfw_cache
{
	
} userfw_cache;

int userfw_cache_init(userfw_cache *);
int userfw_cache_cleanup(userfw_cache *);

int userfw_cache_write(userfw_cache *, userfw_module_id_t mod, uint16_t id, size_t len, void* data);
void *userfw_cache_read(userfw_cache *, userfw_module_id_t mod, uint16_t id, size_t *len);

#endif /* USERFW_CACHE_H */
