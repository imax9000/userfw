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

#include <sys/ioccom.h>
#include <userfw/module.h>

#define AF_USERFW	145 /* just random unused number */

#define PACKED	__attribute__((packed))

#define USERFW_IO_RULESET	1
#define	USERFW_IO_MODLIST	2

#define USERFW_IO_MODINFO	100
#define USERFW_IO_ACTION_DESCR	101
#define	USERFW_IO_MATCH_DESCR	102

#define	USERFW_IO_STRING	200
#define USERFW_IO_UINT16	201
#define USERFW_IO_UINT32	202
#define USERFW_IO_IPv4	203
#define USERFW_IO_MATCH	204
#define USERFW_IO_ACTION	205

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


/* ioctl interfaces */

#ifdef _KERNEL
struct ucred;
typedef int (*userfw_ioctl_handler)(u_long cmd, caddr_t addr, struct ucred *);
extern int userfw_register_ioctl(u_long cmd, userfw_ioctl_handler fn);
extern int userfw_unregister_ioctl(u_long cmd);
#endif

#endif /* USERFW_IO_H */
