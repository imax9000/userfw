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
#include <userfw/io.h>
#include <userfw/types.h>
#include <sys/systm.h>

static int
is_container(struct userfw_io_block *p)
{
	if (p == NULL)
		return 0;
	switch(p->type)
	{
	case T_CONTAINER:
	case T_MATCH:
	case T_ACTION:
		return 1;
	default:
		return 0;
	}
}

struct userfw_io_block *
userfw_msg_alloc_block(uint32_t type, uint32_t subtype, struct malloc_type *mtype)
{
	struct userfw_io_block *ret;

	ret = malloc(sizeof(*ret), mtype, M_WAITOK | M_ZERO);
	ret->type = type;
	ret->subtype = subtype;
	ret->nargs = 0;
	ret->args = NULL;
	ret->data.type = type;

	return ret;
}

struct userfw_io_block *
userfw_msg_alloc_container(uint32_t type, uint32_t subtype, uint32_t nargs, struct malloc_type *mtype)
{
	struct userfw_io_block *ret;

	ret = malloc(sizeof(*ret), mtype, M_WAITOK | M_ZERO);
	ret->type = type;
	ret->subtype = subtype;
	ret->nargs = nargs;
	ret->args = malloc(sizeof(ret)*nargs, mtype, M_WAITOK | M_ZERO);

	return ret;
}

void
userfw_msg_free(struct userfw_io_block *p, struct malloc_type *mtype)
{
	int i;

	if (p == NULL)
	{
		printf("userfw_msg_free(): p == NULL\n");
		return;
	}

	if (is_container(p))
	{
		for(i = 0; i < p->nargs; i++)
		{
			userfw_msg_free((p->args)[i], mtype);
		}
		free(p->args, mtype);
	}
	if ((p->type == T_STRING || p->type == T_HEXSTRING) && p->data.string.data != NULL)
	{
		free(p->data.string.data, mtype);
	}
	free(p, mtype);
}

int
userfw_msg_set_arg(struct userfw_io_block *parent, struct userfw_io_block *child, uint32_t pos)
{
	if (!is_container(parent) || pos >= parent->nargs)
		return EINVAL;
	parent->args[pos] = child;
	return 0;
}

static size_t
type_size(uint32_t type)
{
	size_t ret = 0;
	switch(type)
	{
	case T_UINT16:
		ret = sizeof(uint16_t);
		break;
	case T_UINT32:
		ret = sizeof(uint32_t);
		break;
	case T_UINT64:
		ret = sizeof(uint64_t);
		break;
	case T_IPv4:
		ret = sizeof(uint32_t)*2;
		break;
	case T_IPv6:
		ret = sizeof(uint32_t)*8;
		break;
	}
	return ret;
}

size_t
userfw_msg_calc_size(struct userfw_io_block *p)
{
	int ret = sizeof(struct userfw_io_header);
	int i;

	if (p == NULL)
		return 0;

	if (is_container(p))
	{
		for(i = 0; i < p->nargs; i++)
		{
			if (p->args[i] != NULL)
				ret += userfw_msg_calc_size(p->args[i]);
		}
	}
	else if (p->type == T_STRING || p->type == T_HEXSTRING)
	{
		ret += p->data.string.length;
	}
	else
		ret += type_size(p->type);
	return ret;
}

int
userfw_msg_serialize(struct userfw_io_block *p, unsigned char *buf, size_t len)
{
	size_t block_len = userfw_msg_calc_size(p);
	struct userfw_io_header *hdr = (struct userfw_io_header *)buf;
	unsigned char *data = buf + sizeof(*hdr);

	if (block_len > len)
		return -ENOMEM;
	if (p == NULL || buf == NULL)
		return 0;

	hdr->type = p->type;
	hdr->subtype = p->subtype;
	hdr->length = block_len;

	if (is_container(p))
	{
		int i, err;
		for(i = 0; i < p->nargs; i++)
		{
			if (p->args[i] != NULL)
			{
				err = userfw_msg_serialize(p->args[i], data, len - (data - buf));
				if (err < 0) return err;
				data += err;
			}
		}
	}
	else
	{
		switch(p->type)
		{
		case T_STRING:
		case T_HEXSTRING:
			bcopy(p->data.string.data, data, p->data.string.length);
			break;
		case T_UINT16:
			*((uint16_t*)data) = p->data.uint16.value;
			break;
		case T_UINT32:
			*((uint32_t*)data) = p->data.uint32.value;
			break;
		case T_UINT64:
			*((uint64_t*)data) = p->data.uint64.value;
			break;
		case T_IPv4:
			*((uint32_t*)data) = p->data.ipv4.addr;
			*((uint32_t*)(data + sizeof(uint32_t))) = p->data.ipv4.mask;
			break;
		case T_IPv6:
			bcopy(p->data.ipv6.addr, data, sizeof(uint32_t)*4);
			bcopy(p->data.ipv6.mask, data + sizeof(uint32_t)*4, sizeof(uint32_t)*4);
			break;
		}
	}
	return block_len;
}

int
userfw_msg_insert_uint16(struct userfw_io_block *msg, uint32_t subtype, uint16_t value, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_UINT16, subtype, mtype), pos);
	msg->args[pos]->data.uint16.value = value;
	return 0;
}

int
userfw_msg_insert_uint32(struct userfw_io_block *msg, uint32_t subtype, uint32_t value, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_UINT32, subtype, mtype), pos);
	msg->args[pos]->data.uint32.value = value;
	return 0;
}

int
userfw_msg_insert_uint64(struct userfw_io_block *msg, uint32_t subtype, uint64_t value, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_UINT64, subtype, mtype), pos);
	msg->args[pos]->data.uint64.value = value;
	return 0;
}

int
userfw_msg_insert_string(struct userfw_io_block *msg, uint32_t subtype, const char *str, size_t len, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_STRING, subtype, mtype), pos);
	msg->args[pos]->data.string.length = len;
	msg->args[pos]->data.string.data = malloc(len, mtype, M_WAITOK);
	bcopy(str, msg->args[pos]->data.string.data, len);
	return 0;
}

int
userfw_msg_insert_hexstring(struct userfw_io_block *msg, uint32_t subtype, const char *str, size_t len, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_HEXSTRING, subtype, mtype), pos);
	msg->args[pos]->data.string.length = len;
	msg->args[pos]->data.string.data = malloc(len, mtype, M_WAITOK);
	bcopy(str, msg->args[pos]->data.string.data, len);
	return 0;
}

int
userfw_msg_insert_ipv4(struct userfw_io_block *msg, uint32_t subtype, uint32_t addr, uint32_t mask, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_IPv4, subtype, mtype), pos);
	msg->args[pos]->data.ipv4.addr = addr;
	msg->args[pos]->data.ipv4.mask = mask;
	return 0;
}

int
userfw_msg_insert_ipv6(struct userfw_io_block *msg, uint32_t subtype, const uint32_t addr[4], const uint32_t mask[4], uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_IPv6, subtype, mtype), pos);
	bcopy(addr, msg->args[pos]->data.ipv6.addr, sizeof(uint32_t)*4);
	bcopy(mask, msg->args[pos]->data.ipv6.mask, sizeof(uint32_t)*4);
	return 0;
}

int
userfw_msg_insert_action(struct userfw_io_block *msg, uint32_t subtype, const userfw_action *action, uint32_t pos, struct malloc_type *mtype)
{
	int i;

	userfw_msg_set_arg(msg, userfw_msg_alloc_container(T_ACTION, subtype, action->nargs + 2, mtype), pos);
	userfw_msg_insert_uint32(msg->args[pos], ST_MOD_ID, action->mod, 0, mtype);
	userfw_msg_insert_uint32(msg->args[pos], ST_OPCODE, action->op, 1, mtype);
	for(i = 0; i < action->nargs; i++)
	{
		userfw_msg_insert_arg(msg->args[pos], ST_ARG, &(action->args[i]), i + 2, mtype);
	}
	return 0;
}

int
userfw_msg_insert_match(struct userfw_io_block *msg, uint32_t subtype, const userfw_match *match, uint32_t pos, struct malloc_type *mtype)
{
	int i;

	userfw_msg_set_arg(msg, userfw_msg_alloc_container(T_MATCH, subtype, match->nargs + 2, mtype), pos);
	userfw_msg_insert_uint32(msg->args[pos], ST_MOD_ID, match->mod, 0, mtype);
	userfw_msg_insert_uint32(msg->args[pos], ST_OPCODE, match->op, 1, mtype);
	for(i = 0; i < match->nargs; i++)
	{
		userfw_msg_insert_arg(msg->args[pos], ST_ARG, &(match->args[i]), i + 2, mtype);
	}
	return 0;
}

int
userfw_msg_insert_arg(struct userfw_io_block *msg, uint32_t subtype, const userfw_arg *arg, uint32_t pos, struct malloc_type *mtype)
{
	switch(arg->type)
	{
	case T_STRING:
		userfw_msg_insert_string(msg, subtype, arg->string.data, arg->string.length, pos, mtype);
		break;
	case T_HEXSTRING:
		userfw_msg_insert_hexstring(msg, subtype, arg->string.data, arg->string.length, pos, mtype);
		break;
	case T_UINT16:
		userfw_msg_insert_uint16(msg, subtype, arg->uint16.value, pos, mtype);
		break;
	case T_UINT32:
		userfw_msg_insert_uint32(msg, subtype, arg->uint32.value, pos, mtype);
		break;
	case T_UINT64:
		userfw_msg_insert_uint64(msg, subtype, arg->uint64.value, pos, mtype);
		break;
	case T_IPv4:
		userfw_msg_insert_ipv4(msg, subtype, arg->ipv4.addr, arg->ipv4.mask, pos, mtype);
		break;
	case T_IPv6:
		userfw_msg_insert_ipv6(msg, subtype, arg->ipv6.addr, arg->ipv6.mask, pos, mtype);
		break;
	case T_MATCH:
		userfw_msg_insert_match(msg, subtype, arg->match.p, pos, mtype);
		break;
	case T_ACTION:
		userfw_msg_insert_action(msg, subtype, arg->action.p, pos, mtype);
		break;
	}
	return 0;
}

void
userfw_msg_reply_error(struct socket *so, int cookie, int errno)
{
	struct userfw_io_block *msg;
	size_t len;
	unsigned char *buf;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW);
	userfw_msg_insert_uint32(msg, ST_ERRNO, errno, 1, M_USERFW);

	len = userfw_msg_calc_size(msg);
	buf = malloc(len, M_USERFW, M_WAITOK);
	if (userfw_msg_serialize(msg, buf, len) > 0)
		userfw_domain_send_to_socket(so, buf, len);
	free(buf, M_USERFW);
	userfw_msg_free(msg, M_USERFW);
}
