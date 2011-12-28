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


#ifndef USERFW_IO_H
#define USERFW_IO_H

#include <userfw/module.h>
#include <sys/socket.h>

#define AF_USERFW	145 /* just random unused number */

struct sockaddr_userfw
{
	uint8_t	sa_len;
	sa_family_t	sa_family;
	userfw_module_id_t	module;
};

#define PACKED	__attribute__((packed))

/* Basic header structure
 * Values that gets matched against parts of network packet should be in
 * network byte order, all other - in host byte order */
struct userfw_message_header
{
	uint32_t	type;
	uint32_t	length;
	uint32_t	cookie;
} PACKED;

enum
{
	USERFW_MSG_COMMAND
	,USERFW_MSG_STATUS
	,USERFW_MSG_DATA
};

struct userfw_command_header
{
	uint32_t	opcode; /* opcode is module-specific */
	uint32_t	length;
} PACKED;

struct userfw_status_header
{
	uint32_t	result;
	uint32_t	length;
} PACKED;

enum
{
	USERFW_STATUS_OK
	,USERFW_STATUS_FAILED
};

struct userfw_data_header
{
	uint32_t	type;
	uint32_t	length;
} PACKED;

struct userfw_match_data
{
	userfw_module_id_t	mod;
	opcode_t	op;
} PACKED;

struct userfw_action_data
{
	userfw_module_id_t	mod;
	opcode_t	op;
} PACKED;

struct userfw_io_modinfo
{
	userfw_module_id_t	id;
	uint16_t	nactions;
	uint16_t	nmatches;
	char	name[USERFW_NAME_LEN];
} PACKED;

struct userfw_io_action_descr
{
	opcode_t	op;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
} PACKED;

struct userfw_io_match_descr
{
	opcode_t	op;
	uint8_t	nargs;
	uint8_t	arg_types[USERFW_ARGS_MAX];
	char	name[USERFW_NAME_LEN];
} PACKED;

#endif /* USERFW_IO_H */
