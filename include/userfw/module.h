#ifndef USERFW_MODULE_H
#define USERFW_MODULE_H

#include <userfw/types.h>
#include <userfw/cache.h>

struct mbuf;

#define	USERFW_ARGS_MAX	8
#define	USERFW_NAME_LEN	16

typedef enum __userfw_type
{
	T_STRING = 0
	,T_UINT16
	,T_UINT32
	,T_MATCH
} userfw_type;

typedef struct __userfw_chk_args
{
	int	af;
	struct ifnet	*ifp;
	int	dir;
	struct inpcb	*inpcb;
} userfw_chk_args;

typedef struct __userfw_arg
{
	uint8_t	type;
	void	*data;
} userfw_arg;

typedef struct __userfw_match userfw_match;
typedef struct __userfw_action userfw_action;

typedef int (*userfw_match_fn)(struct mbuf **, userfw_chk_args *, userfw_match *, userfw_cache *);
typedef int (*userfw_action_fn)(struct mbuf **, userfw_chk_args *, userfw_action *, userfw_cache *);

typedef struct __userfw_match_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	_pad1; /* padding */
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_match_fn	do_match;
} userfw_match_descr;

typedef struct __userfw_action_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	_pad1; /* padding */
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_action_fn	do_action;
} userfw_action_descr;

struct __userfw_match
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	uint8_t	_pad1; /* padding */
	userfw_match_fn	do_match;
	userfw_arg	args[USERFW_ARGS_MAX];
};

struct __userfw_action
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	uint8_t	_pad1; /* padding */
	userfw_action_fn	do_action;
	userfw_arg	args[USERFW_ARGS_MAX];
};

typedef struct __userfw_modinfo
{
	userfw_module_id_t	id;
	uint16_t	nactions;
	uint16_t	nmatches;
	userfw_action	*actions;
	userfw_match	*matches;
} userfw_modinfo;

int userfw_mod_register(userfw_modinfo *);
int userfw_mod_unregister(userfw_module_id_t);

#endif /* USERFW_MODULE_H */
