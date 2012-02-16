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
struct userfw_io_header
{
	uint32_t	type;
	uint32_t	subtype;
	uint32_t	length;
} PACKED;

/* Additional types, should be used only in communication */
enum {
	T_CONTAINER = 1024
};

/* Subtypes used to describe what data should mean */
enum {
	ST_UNSPEC = 0
	,ST_MESSAGE = 2048	/* T_CONTAINER (T_UINT32/ST_COOKIE, ...) */
	,ST_COOKIE	/* T_UINT32 */
	,ST_CMDCALL	/* T_CONTAINER (T_UINT32/ST_MOD_ID, T_UINT32/ST_OPCODE, ST_ARG, ...) */
	,ST_OPCODE	/* T_UINT32 */
	,ST_MOD_ID	/* T_UINT32 */
	,ST_ARG	/* T_* */
	,ST_RESULT	/* T_CONTAINER */
	,ST_RULE	/* T_CONTAINER (T_UINT32, T_ACTION, T_MATCH) */
	,ST_RULESET	/* T_CONTAINER (ST_RULE, ...) */
	,ST_ERRNO	/* T_UINT32 */
	,ST_MOD_DESCR	/* T_CONTAINER (T_STRING/ST_NAME, T_UINT32/ST_MOD_ID) */
	,ST_ACTION_DESCR	/* T_CONTAINER (T_UINT32/ST_OPCODE, T_STRING/ST_NAME, T_UINT32/ST_ARGTYPE, ...) */
	,ST_MATCH_DESCR	/* T_CONTAINER (T_UINT32/ST_OPCODE, T_STRING/ST_NAME, T_UINT32/ST_ARGTYPE, ...) */
	,ST_CMD_DESCR	/* T_CONTAINER (T_UINT32/ST_OPCODE, T_STRING/ST_NAME, T_UINT32/ST_ARGTYPE, ...) */
	,ST_NAME	/* T_STRING */
	,ST_ARGTYPE	/* T_UINT32 */
};

inline static struct userfw_io_header *
userfw_io_find_block(unsigned char *buf, size_t len, uint32_t type, uint32_t subtype)
{
	struct userfw_io_header *r = (struct userfw_io_header *)buf;

	while(len >= sizeof(*r))
	{
		if ((type != T_INVAL && r->type != type) ||
			(subtype != ST_UNSPEC && r->subtype != subtype))
		{
			buf += r->length;
			len -= r->length;
			r = (struct userfw_io_header *)buf;
			continue;
		}
		return r;
	}
	return NULL;
}

#define to_io(t)	((struct userfw_io_header *)(t))
#define BLOCK_FITS_INTO_OUTER(inner, outer)	((outer) < (inner) && to_io(inner)->length <= to_io(outer)->length - ((char*)(inner) - (char*)(outer)))

struct userfw_io_block
{
	uint32_t	type;
	uint32_t	subtype;
	uint8_t	nargs;
	struct userfw_io_block **args;
	userfw_arg data;
};

#ifdef _KERNEL
int userfw_domain_send_to_socket(struct socket *, unsigned char *, size_t);
int userfw_domain_send_to_uid(uid_t, unsigned char *, size_t);

struct malloc_type;

struct userfw_io_block * userfw_msg_alloc_block(uint32_t type, uint32_t subtype, struct malloc_type *);
struct userfw_io_block * userfw_msg_alloc_container(uint32_t type, uint32_t subtype, uint32_t nargs, struct malloc_type *);
void userfw_msg_free(struct userfw_io_block *, struct malloc_type *);
int userfw_msg_set_arg(struct userfw_io_block *parent, struct userfw_io_block *child, uint32_t pos);
size_t	userfw_msg_calc_size(struct userfw_io_block *);
int	userfw_msg_serialize(struct userfw_io_block *, unsigned char *, size_t);

int userfw_msg_insert_uint16(struct userfw_io_block *parent, uint32_t subtype, uint16_t value, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_uint32(struct userfw_io_block *parent, uint32_t subtype, uint32_t value, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_uint64(struct userfw_io_block *parent, uint32_t subtype, uint64_t value, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_string(struct userfw_io_block *parent, uint32_t subtype, const char *str, size_t len, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_ipv4(struct userfw_io_block *parent, uint32_t subtype, uint32_t addr, uint32_t mask, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_ipv6(struct userfw_io_block *parent, uint32_t subtype, const uint32_t addr[4], const uint32_t mask[4], uint32_t pos, struct malloc_type *);
int userfw_msg_insert_action(struct userfw_io_block *parent, uint32_t subtype, const userfw_action *, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_match(struct userfw_io_block *parent, uint32_t subtype, const userfw_match *, uint32_t pos, struct malloc_type *);
int userfw_msg_insert_arg(struct userfw_io_block *parent, uint32_t subtype, const userfw_arg *, uint32_t pos, struct malloc_type *);

void userfw_msg_reply_error(struct socket *so, int cookie, int errno);
#endif /* _KERNEL */

#endif /* USERFW_IO_H */
