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

#include <sys/types.h>
#include <sys/malloc.h>

#include "userfw_util.h"
#include "userfw.h"

void
free_match_args(userfw_match *match, struct malloc_type *mtype)
{
	int i;

	for(i = 0; i < match->nargs; i++)
		free_arg(&(match->args[i]), mtype);
}

void
free_action_args(userfw_action *action, struct malloc_type *mtype)
{
	int i;

	for(i = 0; i < action->nargs; i++)
		free_arg(&(action->args[i]), mtype);
}

void
free_arg(userfw_arg *arg, struct malloc_type *mtype)
{
	switch (arg->type)
	{
	case T_STRING:
		free(arg->string.data, mtype);
		break;
	case T_MATCH:
		free_match_args(arg->match.p, mtype);
		userfw_mod_dec_refcount(arg->action.p->mod);
		free(arg->match.p, mtype);
		break;
	case T_ACTION:
		free_action_args(arg->action.p, mtype);
		userfw_mod_dec_refcount(arg->match.p->mod);
		free(arg->match.p, mtype);
		break;
	}
}
