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
		struct socket *so,
		struct thread *td)
{
	int err = 0;
	userfw_module_id_t dst = 0;
	struct userfw_io_header *msg = (struct userfw_io_header *)buf;
	const userfw_modinfo *modinfo = NULL;
	const userfw_cmd_descr *cmdinfo = NULL;
	struct userfw_io_header *cmd, *opcode, *cookie = NULL, *mod_id;
	userfw_arg *parsed_args = NULL;
	int i;

	if (msg->type != T_CONTAINER || (msg->subtype != ST_MESSAGE && msg->subtype != ST_CMDCALL))
		return EOPNOTSUPP;
	if (msg->length < sizeof(*msg) + sizeof(*cmd))
		return EINVAL;

	if (msg->subtype == ST_CMDCALL)
		cmd = msg;
	else
	{
		cmd = userfw_io_find_block(buf + sizeof(*msg), msg->length - sizeof(*msg), T_CONTAINER, ST_CMDCALL);
		cookie = userfw_io_find_block(buf + sizeof(*msg), msg->length - sizeof(*msg), T_UINT32, ST_COOKIE);
	}

	if (cmd == NULL || (cmd != msg && !BLOCK_FITS_INTO_OUTER(cmd, msg)))
		return EINVAL;
	if (cookie != NULL && (!BLOCK_FITS_INTO_OUTER(cookie, cmd) || cookie->length != sizeof(*cookie) + sizeof(uint32_t)))
		return EINVAL;

	mod_id = userfw_io_find_block((char*)cmd + sizeof(*cmd), cmd->length - sizeof(*cmd), T_UINT32, ST_MOD_ID);
	if (mod_id == NULL || ! BLOCK_FITS_INTO_OUTER(mod_id, cmd) ||
		mod_id->length != sizeof(*mod_id) + sizeof(uint32_t))
		return EINVAL;

	dst = *((uint32_t*)((char*)mod_id + sizeof(*mod_id)));
	modinfo = userfw_mod_find(dst);
	if (modinfo == NULL)
		return ECONNREFUSED;

	opcode = userfw_io_find_block((char*)cmd + sizeof(*cmd), cmd->length - sizeof(*cmd), T_UINT32, ST_OPCODE);
	if (opcode == NULL || ! BLOCK_FITS_INTO_OUTER(opcode, cmd) ||
		opcode->length != sizeof(*opcode) + sizeof(uint32_t))
		return EINVAL;

	cmdinfo = userfw_mod_find_cmd(dst, *((uint32_t*)((char*)opcode + sizeof(*opcode))));
	if (cmdinfo == NULL)
		return EINVAL;

	parsed_args = malloc(sizeof(userfw_arg)*(cmdinfo->nargs),
				M_USERFW, M_WAITOK | M_ZERO);

	err = parse_arg_list((unsigned char *)cmd + sizeof(*cmd), cmd->length - sizeof(*cmd),
				parsed_args, cmdinfo->nargs, cmdinfo->arg_types);

	if (err == 0)
		err = cmdinfo->do_cmd(*((uint32_t*)((char*)opcode + sizeof(*opcode))),
				cookie != NULL ? (*((uint32_t*)((char*)cookie + sizeof(*cookie)))) : 0,
				parsed_args, so, td);

	for(i = 0; i < cmdinfo->nargs; i++)
	{
		if (parsed_args[i].type != T_INVAL)
			free_arg(&(parsed_args[i]), M_USERFW);
	}

	free(parsed_args, M_USERFW);

	return err;
}

int
parse_arg_list(unsigned char *buf, int len, userfw_arg *dst, int count, uint8_t const *types)
{
	struct userfw_io_header *arg = (struct userfw_io_header *)buf;
	int err = 0, i;

	for(i = 0; i < count; i++)
	{
		if (len < sizeof(*arg))
			return EINVAL;

		if (arg->subtype == ST_ARG)
		{
			if (arg->type != types[i] || arg->length > len)
				return EINVAL;

			if ((err = parse_arg((unsigned char *)arg, &(dst[i]))) != 0 )
				return err;
		}
		else
			i--;

		len -= arg->length;
		arg = (struct userfw_io_header *)(((unsigned char *)arg) + arg->length);
	}

	if (i != count)
		return EINVAL;

	return 0;
}

int
parse_arg(unsigned char *buf, userfw_arg *dst)
{
	struct userfw_io_header *arg = (struct userfw_io_header *)buf;
	unsigned char *data = buf + sizeof(*arg);

	dst->type = arg->type;

	switch (arg->type)
	{
	case T_STRING:
		dst->string.length = arg->length - sizeof(*arg);
		dst->string.data = malloc(arg->length - sizeof(*arg), M_USERFW, M_WAITOK);
		bcopy(buf + sizeof(*arg), dst->string.data, arg->length - sizeof(*arg));
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
	case T_ACTION:
		{
		userfw_match *match = NULL;
		userfw_action *action = NULL;
		struct userfw_io_header *opcode_p, *mod_id_p;
		const userfw_match_descr *matchdescr = NULL;
		const userfw_action_descr *actiondescr = NULL;
		opcode_t opcode;
		userfw_module_id_t mod_id;
		int err = 0;

		if (arg->length < sizeof(*arg) + sizeof(*opcode_p) + sizeof(*mod_id_p))
			return EINVAL;

		opcode_p = userfw_io_find_block(data, arg->length - sizeof(*arg), T_UINT32, ST_OPCODE);
		if (opcode_p == NULL || ! BLOCK_FITS_INTO_OUTER(opcode_p, arg) ||
			opcode_p->length != sizeof(*opcode_p) + sizeof(uint32_t))
			return EINVAL;
		opcode = *((uint32_t*)((char*)opcode_p + sizeof(*opcode_p)));

		mod_id_p = userfw_io_find_block(data, arg->length - sizeof(*arg), T_UINT32, ST_MOD_ID);
		if (mod_id_p == NULL || ! BLOCK_FITS_INTO_OUTER(mod_id_p, arg) ||
			mod_id_p->length != sizeof(*mod_id_p) + sizeof(uint32_t))
			return EINVAL;
		mod_id = *((uint32_t*)((char*)mod_id_p + sizeof(*mod_id_p)));

		switch(arg->type)
		{
		case T_MATCH:
			matchdescr = userfw_mod_find_match(mod_id, opcode);

			if (matchdescr == NULL)
				return EHOSTUNREACH;

			if (userfw_mod_inc_refcount(mod_id) == 0)
			{
				match = malloc(sizeof(userfw_match), M_USERFW, M_WAITOK | M_ZERO);

				match->mod = mod_id;
				match->op = opcode;
				match->nargs = matchdescr->nargs;
				match->do_match = matchdescr->do_match;
				match->dtor = matchdescr->dtor;

				err = parse_arg_list(data, arg->length - sizeof(*arg),
						match->args, match->nargs, matchdescr->arg_types);
				if (err == 0 && matchdescr->ctor != NULL)
					err = matchdescr->ctor(match);
				dst->match.p = match;
			}
			else
			{
				err = EHOSTUNREACH;
				dst->type = T_INVAL;
			}
			break;
		case T_ACTION:
			actiondescr = userfw_mod_find_action(mod_id, opcode);

			if (actiondescr == NULL)
				return EHOSTUNREACH;

			if (userfw_mod_inc_refcount(mod_id) == 0)
			{
				action = malloc(sizeof(userfw_action), M_USERFW, M_WAITOK | M_ZERO);

				action->mod = mod_id;
				action->op = opcode;
				action->nargs = actiondescr->nargs;
				action->do_action = actiondescr->do_action;
				action->dtor = actiondescr->dtor;

				err = parse_arg_list(data, arg->length - sizeof(*arg),
						action->args, action->nargs, actiondescr->arg_types);
				if (err == 0 && actiondescr->ctor != NULL)
					err = actiondescr->ctor(action);
				dst->action.p = action;
			}
			else
			{
				err = EHOSTUNREACH;
				dst->type = T_INVAL;
			}
			break;
		}
		if (err != 0)
			return err;
		}
		break;
	default:
		dst->type = T_INVAL;
		return EINVAL;
	}

	return 0;
}
