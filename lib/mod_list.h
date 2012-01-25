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

#ifndef USERFW_MOD_LIST_H
#define USERFW_MOD_LIST_H

#include <userfw/module.h>
#include "connection.h"

#define DESCR_STRUCT(x) struct userfw_ ## x ## _descr \
{ \
	userfw_module_id_t	module; \
	opcode_t	opcode; \
	uint8_t	nargs; \
	uint8_t	arg_types[USERFW_ARGS_MAX]; \
	char	name[USERFW_NAME_LEN]; \
}

DESCR_STRUCT(action);
DESCR_STRUCT(match);
DESCR_STRUCT(cmd);

struct userfw_modinfo
{
	userfw_module_id_t	id;
	uint16_t	nactions;
	uint16_t	nmatches;
	uint16_t	ncmds;
	struct userfw_action_descr	*actions;
	struct userfw_match_descr	*matches;
	struct userfw_cmd_descr	*cmds;
	char	name[USERFW_NAME_LEN];
};

struct userfw_modlist
{
	uint32_t	nmodules;
	struct userfw_modinfo	*modules;
};

#ifdef __cplusplus
extern "C" {
#endif

struct userfw_modlist * userfw_modlist_get(struct userfw_connection *);
void userfw_modlist_destroy(struct userfw_modlist *);

int userfw_find_module_by_name(const struct userfw_modlist *, const char *, size_t, struct userfw_modinfo**);
int userfw_find_module_by_id(const struct userfw_modlist *, userfw_module_id_t, struct userfw_modinfo**);
int userfw_find_action(const struct userfw_modlist *, const char *, size_t, struct userfw_action_descr**);
int userfw_find_action_in_module(const struct userfw_modinfo*, const char *, size_t, struct userfw_action_descr**);
int userfw_find_action_by_opcode(struct userfw_modinfo*, opcode_t, struct userfw_action_descr**);
int userfw_find_match(const struct userfw_modlist *, const char *, size_t, struct userfw_match_descr**);
int userfw_find_match_in_module(const struct userfw_modinfo*, const char *, size_t, struct userfw_match_descr**);
int userfw_find_match_by_opcode(struct userfw_modinfo*, opcode_t, struct userfw_match_descr**);
int userfw_find_cmd(const struct userfw_modlist *, const char *, size_t, struct userfw_cmd_descr**);
int userfw_find_cmd_in_module(const struct userfw_modinfo*, const char *, size_t, struct userfw_cmd_descr**);
int userfw_find_cmd_by_opcode(struct userfw_modinfo*, opcode_t, struct userfw_cmd_descr**);

#ifdef __cplusplus
}
#endif

#endif /* USERFW_MOD_LIST_H */
