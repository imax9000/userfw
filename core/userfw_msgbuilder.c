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
	ret->args = malloc(sizeof(ret), mtype, M_WAITOK | M_ZERO);

	return ret;
}

void
userfw_msg_free(struct userfw_io_block *p, struct malloc_type *mtype)
{
	int i;

	if (is_container(p))
	{
		for(i = 0; i < p->nargs; i++)
		{
			userfw_msg_free((p->args)[i], mtype);
		}
		free(p->args, mtype);
	}
	if (p->type == T_STRING && p->data.string.data != NULL)
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
	case T_IPv4:
		ret = sizeof(uint32_t)*2;
		break;
	}
	return ret;
}

size_t
userfw_msg_calc_size(struct userfw_io_block *p)
{
	int ret = sizeof(struct userfw_io_header);
	int i;

	if (is_container(p))
	{
		for(i = 0; i < p->nargs; i++)
		{
			if (p->args[i] != NULL)
				ret += userfw_msg_calc_size(p->args[i]);
		}
	}
	else if (p->type == T_STRING)
	{
		ret += sizeof(uint16_t) + p->data.string.length;
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
			*((uint16_t*)data) = p->data.string.length;
			bcopy(p->data.string.data, data + sizeof(uint16_t), p->data.string.length);
			break;
		case T_UINT16:
			*((uint16_t*)data) = p->data.uint16.value;
			break;
		case T_UINT32:
			*((uint32_t*)data) = p->data.uint32.value;
			break;
		case T_IPv4:
			*((uint32_t*)data) = p->data.ipv4.addr;
			*((uint32_t*)(data + sizeof(uint32_t))) = p->data.ipv4.mask;
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
userfw_msg_insert_string(struct userfw_io_block *msg, uint32_t subtype, const char *str, size_t len, uint32_t pos, struct malloc_type *mtype)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_STRING, subtype, mtype), pos);
	msg->args[pos]->data.string.length = len;
	msg->args[pos]->data.string.data = malloc(len, M_USERFW, M_WAITOK);
	bcopy(str, msg->args[pos]->data.string.data, len);
	return 0;
}
