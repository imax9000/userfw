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

#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <userfw/types.h>
#include "message.h"

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
userfw_msg_alloc_block(uint32_t type, uint32_t subtype)
{
	struct userfw_io_block *ret;

	ret = malloc(sizeof(*ret));
	if (ret != NULL)
	{
		ret->type = type;
		ret->subtype = subtype;
		ret->nargs = 0;
		ret->args = NULL;
		ret->data.type = type;
	}

	return ret;
}

struct userfw_io_block *
userfw_msg_alloc_container(uint32_t type, uint32_t subtype, uint32_t nargs)
{
	struct userfw_io_block *ret;

	ret = malloc(sizeof(*ret));
	if (ret != NULL)
	{
		ret->type = type;
		ret->subtype = subtype;
		ret->nargs = nargs;
		ret->args = malloc(sizeof(ret)*nargs);
		if (ret->args == NULL)
		{
			free(ret);
			ret = NULL;
			errno = ENOMEM;
		}
		bzero(ret->args, sizeof(ret)*nargs);
	}

	return ret;
}

void
userfw_msg_free(struct userfw_io_block *p)
{
	int i;

	if (p == NULL)
	{
		return;
	}

	if (is_container(p))
	{
		for(i = 0; i < p->nargs; i++)
		{
			userfw_msg_free((p->args)[i]);
		}
		free(p->args);
	}
	if (p->type == T_STRING && p->data.string.data != NULL)
	{
		free(p->data.string.data);
	}
	free(p);
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
			bcopy(p->data.string.data, data, p->data.string.length);
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
		case T_IPv6:
			bcopy(p->data.ipv6.addr, data, sizeof(uint32_t)*4);
			bcopy(p->data.ipv6.mask, data + sizeof(uint32_t)*4, sizeof(uint32_t)*4);
			break;
		}
	}
	return block_len;
}

int
userfw_msg_insert_uint16(struct userfw_io_block *msg, uint32_t subtype, uint16_t value, uint32_t pos)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_UINT16, subtype), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	msg->args[pos]->data.uint16.value = value;
	return 0;
}

int
userfw_msg_insert_uint32(struct userfw_io_block *msg, uint32_t subtype, uint32_t value, uint32_t pos)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_UINT32, subtype), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	msg->args[pos]->data.uint32.value = value;
	return 0;
}

int
userfw_msg_insert_string(struct userfw_io_block *msg, uint32_t subtype, const char *str, size_t len, uint32_t pos)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_STRING, subtype), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	msg->args[pos]->data.string.length = len;
	msg->args[pos]->data.string.data = malloc(len);
	if (msg->args[pos]->data.string.data == NULL)
	{
		free(msg->args[pos]);
		msg->args[pos] = NULL;
		return ENOMEM;
	}
	bcopy(str, msg->args[pos]->data.string.data, len);
	return 0;
}

int
userfw_msg_insert_ipv4(struct userfw_io_block *msg, uint32_t subtype, uint32_t addr, uint32_t mask, uint32_t pos)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_IPv4, subtype), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	msg->args[pos]->data.ipv4.addr = addr;
	msg->args[pos]->data.ipv4.mask = mask;
	return 0;
}

int
userfw_msg_insert_ipv6(struct userfw_io_block *msg, uint32_t subtype, const uint32_t addr[4], const uint32_t mask[4], uint32_t pos)
{
	userfw_msg_set_arg(msg, userfw_msg_alloc_block(T_IPv6, subtype), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	bcopy(addr, msg->args[pos]->data.ipv6.addr, sizeof(uint32_t)*4);
	bcopy(mask, msg->args[pos]->data.ipv6.mask, sizeof(uint32_t)*4);
	return 0;
}

int
userfw_msg_insert_action(struct userfw_io_block *msg, uint32_t subtype, const userfw_action *action, uint32_t pos)
{
	int i, ret = 0, j;

	userfw_msg_set_arg(msg, userfw_msg_alloc_container(T_ACTION, subtype, action->nargs + 2), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	userfw_msg_insert_uint32(msg->args[pos], ST_MOD_ID, action->mod, 0);
	userfw_msg_insert_uint32(msg->args[pos], ST_OPCODE, action->op, 1);
	for(i = 0; i < action->nargs; i++)
	{
		ret = userfw_msg_insert_arg(msg->args[pos], ST_ARG, &(action->args[i]), i + 2);
		userfw_msg_set_arg(msg->args[pos], NULL, i + 2);
		if (ret != 0)
		{
			for(j = 0; j < i + 2; j++)
			{
				userfw_msg_free(msg->args[pos]->args[j]);
				userfw_msg_set_arg(msg->args[pos], NULL, j);
			}
			userfw_msg_free(msg->args[pos]);
		}
	}
	return ret;
}

int
userfw_msg_insert_match(struct userfw_io_block *msg, uint32_t subtype, const userfw_match *match, uint32_t pos)
{
	int i, ret = 0, j;

	userfw_msg_set_arg(msg, userfw_msg_alloc_container(T_MATCH, subtype, match->nargs + 2), pos);
	if (msg->args[pos] == NULL)
		return ENOMEM;
	userfw_msg_insert_uint32(msg->args[pos], ST_MOD_ID, match->mod, 0);
	userfw_msg_insert_uint32(msg->args[pos], ST_OPCODE, match->op, 1);
	for(i = 0; i < match->nargs; i++)
	{
		userfw_msg_insert_arg(msg->args[pos], ST_ARG, &(match->args[i]), i + 2);
		if (ret != 0)
		{
			for(j = 0; j < i + 2; j++)
			{
				userfw_msg_free(msg->args[pos]->args[j]);
				userfw_msg_set_arg(msg->args[pos], NULL, j);
			}
			userfw_msg_free(msg->args[pos]);
		}
	}
	return 0;
}

int
userfw_msg_insert_arg(struct userfw_io_block *msg, uint32_t subtype, const userfw_arg *arg, uint32_t pos)
{
	int ret = 0;
	switch(arg->type)
	{
	case T_STRING:
		ret = userfw_msg_insert_string(msg, subtype, arg->string.data, arg->string.length, pos);
		break;
	case T_UINT16:
		ret = userfw_msg_insert_uint16(msg, subtype, arg->uint16.value, pos);
		break;
	case T_UINT32:
		ret = userfw_msg_insert_uint32(msg, subtype, arg->uint32.value, pos);
		break;
	case T_IPv4:
		ret = userfw_msg_insert_ipv4(msg, subtype, arg->ipv4.addr, arg->ipv4.mask, pos);
		break;
	case T_IPv6:
		ret = userfw_msg_insert_ipv6(msg, subtype, arg->ipv6.addr, arg->ipv6.mask, pos);
		break;
	case T_MATCH:
		ret = userfw_msg_insert_match(msg, subtype, arg->match.p, pos);
		break;
	case T_ACTION:
		ret = userfw_msg_insert_action(msg, subtype, arg->action.p, pos);
		break;
	}
	return ret;
}

static int
subblocks_count(unsigned char *buf, size_t len)
{
	int ret = 0;
	struct userfw_io_header *hdr = (struct userfw_io_header *)buf;

	if (len < sizeof(*hdr) || len < hdr->length)
		return 0;

	len = hdr->length - sizeof(*hdr);
	buf += sizeof(*hdr);

	while(len >= sizeof(*hdr))
	{
		/* TODO: add some validation */
		hdr = (struct userfw_io_header *)buf;
		len -= hdr->length;
		buf += hdr->length;
		ret++;
	}
	return ret;
}

#include <stdio.h>

struct userfw_io_block *
userfw_msg_parse(unsigned char *buf, size_t len)
{
	struct userfw_io_block *ret = NULL;
	struct userfw_io_header *hdr = (struct userfw_io_header*)buf;
	unsigned char *data = buf + sizeof(*hdr);

	if (len < sizeof(*hdr) || len < hdr->length)
		return NULL;

	switch(hdr->type)
	{
	case T_STRING:
		if (hdr->length < sizeof(*hdr))
			break;
		ret = userfw_msg_alloc_block(hdr->type, hdr->subtype);
		if (ret != NULL)
		{
			ret->data.string.length = hdr->length - sizeof(*hdr);
			if ((ret->data.string.data = malloc(ret->data.string.length)) != NULL)
			{
				bcopy(data, ret->data.string.data, ret->data.string.length);
			}
			else
			{
				userfw_msg_free(ret);
				ret = NULL;
			}
		}
		break;
	case T_UINT16:
		if (hdr->length != sizeof(*hdr) + sizeof(uint16_t))
			break;
		ret = userfw_msg_alloc_block(hdr->type, hdr->subtype);
		if (ret != NULL)
			ret->data.uint16.value = *((uint16_t*)data);
		break;
	case T_UINT32:
		if (hdr->length != sizeof(*hdr) + sizeof(uint32_t))
			break;
		ret = userfw_msg_alloc_block(hdr->type, hdr->subtype);
		if (ret != NULL)
			ret->data.uint32.value = *((uint32_t*)data);
		break;
	case T_IPv4:
		if (hdr->length != sizeof(*hdr) + sizeof(uint32_t)*2)
			break;
		ret = userfw_msg_alloc_block(hdr->type, hdr->subtype);
		if (ret != NULL)
		{
			ret->data.ipv4.addr = *((uint32_t*)data);
			ret->data.ipv4.mask = *((uint32_t*)(data + sizeof(uint32_t)));
		}
		break;
	case T_IPv6:
		if (hdr->length != sizeof(*hdr) + sizeof(uint32_t)*8)
			break;
		ret = userfw_msg_alloc_block(hdr->type, hdr->subtype);
		if (ret != NULL)
		{
			bcopy(data, ret->data.ipv6.addr, sizeof(uint32_t)*4);
			bcopy(data + sizeof(uint32_t)*4, ret->data.ipv6.mask, sizeof(uint32_t)*4);
		}
		break;
	case T_CONTAINER:
	case T_ACTION:
	case T_MATCH:
		{
			int subblocks = subblocks_count(buf, len), i;
			struct userfw_io_block *arg = NULL;

			ret = userfw_msg_alloc_container(hdr->type, hdr->subtype, subblocks);
			if (ret != NULL)
			{
				hdr = (struct userfw_io_header *)(buf + sizeof(*hdr));
				for(i = 0; i < subblocks; i++)
				{
					arg = userfw_msg_parse((unsigned char *)hdr, hdr->length);
					if (arg == NULL)
					{
						userfw_msg_free(ret);
						ret = NULL;
						break;
					}
					userfw_msg_set_arg(ret, arg, i);
					hdr = (struct userfw_io_header *)((unsigned char *)hdr + hdr->length);
				}
			}
		}
		break;
	}

	return ret;
}
