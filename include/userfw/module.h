/*-
 * Copyright (C) 2011 by Maxim Ignatenko <gelraen.ua@gmail.com>
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

typedef struct __userfw_chk_args
{
	int	af;
	struct ifnet	*ifp;
	int	dir;
	struct inpcb	*inpcb;
} userfw_chk_args;

typedef struct __userfw_match userfw_match;
typedef struct __userfw_action userfw_action;

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
		uint8_t type;
		uint32_t    addr;
		uint32_t    mask;
	} ipv4;
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

typedef int (*userfw_match_fn)(struct mbuf **, userfw_chk_args *, userfw_match *, userfw_cache *);
typedef int (*userfw_action_fn)(struct mbuf **, userfw_chk_args *, userfw_action *, userfw_cache *);
typedef int (*userfw_cmd_handler)(opcode_t, uint32_t, userfw_arg *, struct socket *, struct thread *);

typedef struct __userfw_match_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_match_fn	do_match;
} userfw_match_descr;

typedef struct __userfw_action_descr
{
	opcode_t	opcode;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_action_fn	do_action;
} userfw_action_descr;

typedef struct __userfw_cmd_descr
{
	opcode_t	opcode;
	uint8_t nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
	userfw_cmd_handler	do_cmd;
} userfw_cmd_descr;

struct __userfw_match
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_match_fn	do_match;
	userfw_arg	args[USERFW_ARGS_MAX];
};

struct __userfw_action
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_action_fn	do_action;
	userfw_arg	args[USERFW_ARGS_MAX];
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

#define VERIFY_OPCODE(obj, module, opcode, retval) do { \
		if ((obj)->mod != (module) || (obj)->op != (opcode)) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)

#define VERIFY_OPCODE2(obj, module, opcode1, opcode2, retval) do { \
		if ((obj)->mod != (module) || ((obj)->op != (opcode1) && (obj)->op != (opcode2))) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)

#define VERIFY_OPCODE3(obj, module, opcode1, opcode2, opcode3, retval) do { \
		if ((obj)->mod != (module) || ((obj)->op != (opcode1) && (obj)->op != (opcode2) && (obj)->op != (opcode3))) \
		{ \
			printf("userfw: %s: called with wrong opcode %d:%d", __func__, (obj)->mod, (obj)->op); \
			return (retval); \
		} } while(0)

#endif /* _KERNEL */

#endif /* USERFW_MODULE_H */
