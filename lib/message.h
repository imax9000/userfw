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

#ifndef USERFW_MESSAGE_H
#define USERFW_MESSAGE_H

#include <userfw/io.h>

struct __userfw_match
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_arg	args[USERFW_ARGS_MAX];
};

struct __userfw_action
{
	userfw_module_id_t	mod;
	opcode_t	op;
	uint8_t	nargs;
	userfw_arg	args[USERFW_ARGS_MAX];
};

struct userfw_io_block * userfw_msg_alloc_block(uint32_t type, uint32_t subtype);
struct userfw_io_block * userfw_msg_alloc_container(uint32_t type, uint32_t subtype, uint32_t nargs);
void userfw_msg_free(struct userfw_io_block *);
int userfw_msg_set_arg(struct userfw_io_block *parent, struct userfw_io_block *child, uint32_t pos);
size_t  userfw_msg_calc_size(struct userfw_io_block *);
int     userfw_msg_serialize(struct userfw_io_block *, unsigned char *, size_t);
struct userfw_io_block * userfw_msg_parse(unsigned char *, size_t);

int userfw_msg_insert_uint16(struct userfw_io_block *parent, uint32_t subtype, uint16_t value, uint32_t pos);
int userfw_msg_insert_uint32(struct userfw_io_block *parent, uint32_t subtype, uint32_t value, uint32_t pos);
int userfw_msg_insert_uint64(struct userfw_io_block *parent, uint32_t subtype, uint64_t value, uint32_t pos);
int userfw_msg_insert_string(struct userfw_io_block *parent, uint32_t subtype, const char *str, size_t len, uint32_t pos);
int userfw_msg_insert_ipv4(struct userfw_io_block *parent, uint32_t subtype, uint32_t addr, uint32_t mask, uint32_t pos);
int userfw_msg_insert_ipv6(struct userfw_io_block *parent, uint32_t subtype, const uint32_t addr[4], const uint32_t mask[4], uint32_t pos);
int userfw_msg_insert_action(struct userfw_io_block *parent, uint32_t subtype, const userfw_action *, uint32_t pos);
int userfw_msg_insert_match(struct userfw_io_block *parent, uint32_t subtype, const userfw_match *, uint32_t pos);
int userfw_msg_insert_arg(struct userfw_io_block *parent, uint32_t subtype, const userfw_arg *, uint32_t pos);

#endif /* USERFW_MESSAGE_H */
