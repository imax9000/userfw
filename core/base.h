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


#ifndef USERFW_MOD_BASE_H
#define USERFW_MOD_BASE_H

#include <userfw/types.h>

#define	USERFW_BASE_MOD	0

enum __base_actions
{
	A_ALLOW
	,A_DENY
	,A_CONTINUE
	,A_STOP
};

enum __base_matches
{
	M_IN = USERFW_IN
	,M_OUT = USERFW_OUT
	,M_OR
	,M_AND
	,M_NOT
	,M_ANY
	,M_FRAME_LEN
};

enum __base_cmds
{
	CMD_MODLIST
	,CMD_MODINFO
	,CMD_LIST_RULESET
	,CMD_DELETE_RULE
	,CMD_INSERT_RULE
	,CMD_FLUSH_RULESET
};

#endif /* USERFW_MOD_BASE_H */
