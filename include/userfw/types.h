#ifndef USERFW_TYPES_H
#define USERFW_TYPES_H

#include <sys/types.h>

typedef	uint32_t	userfw_module_id_t;
typedef	uint16_t	userfw_module_t;
typedef	uint16_t	opcode_t;

enum userfw_direction
{
	USERFW_IN = 0
	,USERFW_OUT
};

#endif /* USERFW_TYPES_H */
