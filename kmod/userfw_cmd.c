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

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include "userfw_cmd.h"
#include "userfw.h"
#include <userfw/module.h>
#include "userfw_util.h"

int parse_arg(unsigned char *, userfw_arg *);
int parse_arg_list(unsigned char *, int, userfw_arg *, int, uint8_t const *);

int
userfw_cmd_dispatch(unsigned char *buf,
		userfw_module_id_t dst,
		struct socket *so,
		struct thread *td)
{
	int err = 0;
	struct userfw_message_header *msg = (struct userfw_message_header *)buf;
	const userfw_modinfo *modinfo = NULL;
	const userfw_cmd_descr *cmdinfo = NULL;
	struct userfw_command_header *cmd = NULL;
	struct userfw_data_header *arg = NULL;
	userfw_arg *parsed_args = NULL;
	int i, length_left;

	modinfo = userfw_mod_find(dst);
	if (modinfo == NULL)
		return ECONNREFUSED;
	if (msg->type != USERFW_MSG_COMMAND)
		return EOPNOTSUPP;
	if (msg->length < sizeof(*msg) + sizeof(*cmd))
		return EINVAL;

	cmd = (struct userfw_command_header *)(buf + sizeof(*msg));
	if (cmd->length != msg->length - sizeof(*msg))
		return EINVAL;

	cmdinfo = userfw_mod_find_cmd(dst, cmd->opcode);
	if (cmdinfo == NULL)
		return EINVAL;

	parsed_args = malloc(sizeof(userfw_arg)*(cmdinfo->nargs),
				M_USERFW, M_WAITOK | M_ZERO);

	length_left = cmd->length - sizeof(*cmd);
	arg = (struct userfw_data_header *)(((unsigned char *)cmd) + sizeof(*cmd));

	err = parse_arg_list((unsigned char *)arg, length_left, parsed_args, cmdinfo->nargs, cmdinfo->arg_types);

	if (err == 0)
		err = cmdinfo->do_cmd(cmd->opcode, msg->cookie, parsed_args, so, td);

	for(i = 0; i < cmdinfo->nargs; i++)
	{
		if (parsed_args[i].type != T_INVAL)
			free_arg(&(parsed_args[i]));
	}

	free(parsed_args, M_USERFW);

	return err;
}

int
parse_arg_list(unsigned char *buf, int len, userfw_arg *dst, int count, uint8_t const *types)
{
	struct userfw_data_header *arg = (struct userfw_data_header *)buf;
	int err = 0, i;

	if (len < sizeof(*arg))
		return EINVAL;

	for(i = 0; i < count; i++)
	{
		if (arg->type != types[i] || arg->length > len)
			return EINVAL;

		if ((err = parse_arg((unsigned char *)arg, &(dst[i]))) != 0 )
			return err;

		len -= arg->length;
		arg = (struct userfw_data_header *)(((unsigned char *)arg) + arg->length);
	}

	return 0;
}

int
parse_arg(unsigned char *buf, userfw_arg *dst)
{
	struct userfw_data_header *arg = (struct userfw_data_header *)buf;
	unsigned char *data = buf + sizeof(*arg);

	dst->type = arg->type;

	switch (arg->type)
	{
	case T_STRING:
		dst->string.length = arg->length - sizeof(*arg);
		dst->string.data = buf + sizeof(*arg);
		break;
	case T_UINT16:
		bcopy(data, &(dst->uint16.value), sizeof(uint16_t));
		break;
	case T_UINT32:
		bcopy(data, &(dst->uint32.value), sizeof(uint32_t));
		break;
	case T_IPv4:
		bcopy(data, &(dst->ipv4.addr), sizeof(uint32_t));
		bcopy(data + sizeof(uint32_t), &(dst->ipv4.mask), sizeof(uint32_t));
		break;
	case T_MATCH:
		{
		userfw_match *match = NULL;
		struct userfw_match_data *matchdata = NULL;
		const userfw_match_descr *matchdescr = NULL;
		int err = 0;

		if (arg->length < sizeof(*arg) + sizeof(*matchdata))
			return EINVAL;

		matchdata = (struct userfw_match_data *)data;
		matchdescr = userfw_mod_find_match(matchdata->mod, matchdata->op);

		if (matchdescr == NULL)
			return EHOSTUNREACH;

		match = malloc(sizeof(userfw_match), M_USERFW, M_WAITOK | M_ZERO);

		match->mod = matchdata->mod;
		match->op = matchdata->op;
		match->nargs = matchdescr->nargs;
		match->do_match = matchdescr->do_match;

		err = parse_arg_list(data + sizeof(*matchdata),
				arg->length - sizeof(*arg) - sizeof(*matchdata),
				match->args, match->nargs, matchdescr->arg_types);
		if (err != 0)
			return err;
		dst->match.p = match;
		}
		break;
	case T_ACTION:
		{
		userfw_action *action = NULL;
		struct userfw_action_data *actiondata = NULL;
		const userfw_action_descr *actiondescr = NULL;
		int err = 0;

		if (arg->length < sizeof(*arg) + sizeof(*actiondata))
			return EINVAL;

		actiondata = (struct userfw_action_data *)data;
		actiondescr = userfw_mod_find_action(actiondata->mod, actiondata->op);

		if (actiondescr == NULL)
			return EHOSTUNREACH;

		action = malloc(sizeof(userfw_action), M_USERFW, M_WAITOK | M_ZERO);

		action->mod = actiondata->mod;
		action->op = actiondata->op;
		action->nargs = actiondescr->nargs;
		action->do_action = actiondescr->do_action;

		err = parse_arg_list(data + sizeof(*actiondata),
				arg->length - sizeof(*arg) - sizeof(*actiondata),
				action->args, action->nargs, actiondescr->arg_types);
		if (err != 0)
			return err;
		dst->action.p = action;
		}
		break;
	default:
		dst->type = T_INVAL;
		return EINVAL;
	}

	return 0;
}
