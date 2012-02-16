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


#ifndef USERFW_MODULE_H
#define USERFW_MODULE_H

#include <userfw/types.h>
#include <userfw/cache.h>
#ifdef _KERNEL
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>

struct mbuf;
struct thread;
struct socket;

MALLOC_DECLARE(M_USERFW);
#endif

#define	USERFW_ARGS_MAX	8
#define	USERFW_NAME_LEN	16

#ifdef _KERNEL
#define SI_SUB_USERFW	SI_SUB_PROTO_IFATTACHDOMAIN
#define SI_ORDER_USERFW_CORE	(SI_ORDER_ANY-1)
#define SI_ORDER_USERFW_MOD	(SI_ORDER_USERFW_CORE+1)

SYSCTL_DECL(_net_userfw);

typedef struct __userfw_chk_args
{
	int	af;
	struct ifnet	*ifp;
	int	dir;
	struct inpcb	*inpcb;
} userfw_chk_args;

#endif /* _KERNEL */

typedef struct __userfw_match userfw_match;
typedef struct __userfw_action userfw_action;
typedef struct __userfw_cmd_descr userfw_cmd_descr;

typedef union __userfw_arg
{
	uint8_t type;
	struct
	{
		uint8_t type;
		uint16_t    length;
		char    *data;
	} string;
	struct
	{
		uint8_t type;
		uint16_t    value;
	} uint16;
	struct
	{
		uint8_t type;
		uint32_t    value;
	} uint32;
	struct
	{
		uint8_t	type;
		uint64_t	value;
	} uint64;
	struct
	{
		uint8_t type;
		uint32_t    addr;
		uint32_t    mask;
	} ipv4;
	struct
	{
		uint8_t	type;
		uint32_t	addr[4];
		uint32_t	mask[4];
	} ipv6;
	struct
	{
		uint8_t type;
		userfw_match *p;
	} match;
	struct
	{
		uint8_t type;
		userfw_action *p;
	} action;
} userfw_arg;
#ifdef _KERNEL

typedef int (*userfw_match_fn)(struct mbuf **, userfw_chk_args *, userfw_match *, userfw_cache *, userfw_arg *);
typedef int (*userfw_action_fn)(struct mbuf **, userfw_chk_args *, userfw_action *, userfw_cache *, int *, uint32_t);
typedef int (*userfw_match_ctor)(userfw_match *);
typedef int (*userfw_match_dtor)(userfw_match *);
typedef int (*userfw_action_ctor)(userfw_action *);
typedef int (*userfw_action_dtor)(userfw_action *);
typedef int (*userfw_cmd_handler)(opcode_t, uint32_t, userfw_arg *, struct socket *, struct thread *);
typedef int (*userfw_cmd_access_check)(userfw_module_id_t, const userfw_cmd_descr *, const userfw_arg *, struct socket *, struct thread *);

int userfw_cmd_access_only_root(userfw_module_id_t, const userfw_cmd_descr *, const userfw_arg *, struct socket *, struct thread *);
int userfw_cmd_access_anybody(userfw_module_id_t, const userfw_cmd_descr *, const userfw_arg *, struct socket *, struct thread *);

/*
 * USERFW_ACTION_FLAG_SECOND_PASS flag is set when packet returned from other subsystem
 * and core needs to get return value and continue_ flag from action. So when this flag 
 * is set action should not do any real work, just return those two values */
#define USERFW_ACTION_FLAG_SECOND_PASS	0x00000001

typedef struct __userfw_match_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_match_fn	do_match;
	userfw_match_ctor	ctor;
	userfw_match_dtor	dtor;
} userfw_match_descr;

typedef struct __userfw_action_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_action_fn	do_action;
	userfw_action_ctor	ctor;
	userfw_action_dtor	dtor;
} userfw_action_descr;

struct __userfw_cmd_descr
{
	opcode_t	opcode;
	uint8_t nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_cmd_handler	do_cmd;
	userfw_cmd_access_check is_allowed;
};

struct __userfw_match
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_match_fn	do_match;
	userfw_arg	args[USERFW_ARGS_MAX];
	userfw_match_dtor	dtor;
	void *priv;
};

struct __userfw_action
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_action_fn	do_action;
	userfw_arg	args[USERFW_ARGS_MAX];
	userfw_action_dtor	dtor;
	void *priv;
};

typedef struct __userfw_modinfo
{
	userfw_module_id_t	id;
	uint16_t	nactions;
	uint16_t	nmatches;
	uint16_t	ncmds;
	userfw_action_descr	*actions;
	userfw_match_descr	*matches;
	userfw_cmd_descr	*cmds;
	char	name[USERFW_NAME_LEN];
} userfw_modinfo;

int userfw_mod_register(userfw_modinfo *);
int userfw_mod_unregister(userfw_module_id_t);
const userfw_modinfo *userfw_mod_find(userfw_module_id_t);
const userfw_match_descr *userfw_mod_find_match(userfw_module_id_t, opcode_t);
const userfw_action_descr *userfw_mod_find_action(userfw_module_id_t, opcode_t);
const userfw_cmd_descr *userfw_mod_find_cmd(userfw_module_id_t, opcode_t);
int userfw_mod_inc_refcount(userfw_module_id_t);
int userfw_mod_dec_refcount(userfw_module_id_t);

struct malloc_type;
void free_match_args(userfw_match *, struct malloc_type *);
void free_action_args(userfw_action *, struct malloc_type *);
void free_arg(userfw_arg *, struct malloc_type *);

#ifndef SKIP_OPCODE_VERIFICATION
#define VERIFY_OPCODE(obj, module, opcode, retval) do { \
		if ((obj)->mod != (module) || (obj)->op != (opcode)) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d\n", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)

#define VERIFY_OPCODE2(obj, module, opcode1, opcode2, retval) do { \
		if ((obj)->mod != (module) || ((obj)->op != (opcode1) && (obj)->op != (opcode2))) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d\n", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)

#define VERIFY_OPCODE3(obj, module, opcode1, opcode2, opcode3, retval) do { \
		if ((obj)->mod != (module) || ((obj)->op != (opcode1) && (obj)->op != (opcode2) && (obj)->op != (opcode3))) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d\n", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)
#else /* SKIP_OPCODE_VERIFICATION */
#define VERIFY_OPCODE(obj, module, opcode, retval)
#define VERIFY_OPCODE2(obj, module, opcode1, opcode2, retval)
#define VERIFY_OPCODE3(obj, module, opcode1, opcode2, opcode3, retval)
#endif /* SKIP_OPCODE_VERIFICATION */

#endif /* _KERNEL */

#endif /* USERFW_MODULE_H */
