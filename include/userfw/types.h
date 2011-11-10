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

typedef enum __userfw_type
{
	T_STRING = 0
	,T_UINT16
	,T_UINT32
	,T_IPv4
	,T_MATCH
} userfw_type;

#define T_PORT	T_UINT16

#endif /* USERFW_TYPES_H */
