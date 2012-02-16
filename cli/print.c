/*-
 * Copyright (C) 2012 by Maxim Ignatenko <gelraen.ua@gmail.com>
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/param.h>
#include "print.h"

static void
print_indent(int n)
{
	for(; n > 0; n--)
		printf("\t");
}

const char *type_names[] = {
"T_INVAL",
"T_STRING",
"T_UINT16",
"T_UINT32",
"T_IPv4",
"T_IPv6",
"T_MATCH",
"T_ACTION",
"T_UINT64",
"T_HEXSTRING"
};

char type_buf[256] = {0};

const char *
type_name(uint32_t type)
{
	switch(type)
	{
	case T_CONTAINER:
		return "T_CONTAINER";
	case T_INVAL:
	case T_STRING:
	case T_HEXSTRING:
	case T_UINT16:
	case T_UINT32:
	case T_UINT64:
	case T_IPv4:
	case T_IPv6:
	case T_MATCH:
	case T_ACTION:
		return type_names[type];
	}
	snprintf(type_buf, 256, "Unknown type: %d", type);
	return type_buf;
}

const char *subtype_names[] = {
"ST_MESSAGE",
"ST_COOKIE",
"ST_CMDCALL",
"ST_OPCODE",
"ST_MOD_ID",
"ST_ARG",
"ST_RESULT",
"ST_RULE",
"ST_RULESET",
"ST_ERRNO",
"ST_MOD_DESCR",
"ST_ACTION_DESCR",
"ST_MATCH_DESCR",
"ST_CMD_DESCR",
"ST_NAME",
"ST_ARGTYPE"
};

char subtype_buf[256] = {0};

const char *
subtype_name(uint32_t subtype)
{
	switch(subtype)
	{
	case ST_UNSPEC:
		return "ST_UNSPEC";
	case ST_MESSAGE:
	case ST_COOKIE:
	case ST_CMDCALL:
	case ST_OPCODE:
	case ST_MOD_ID:
	case ST_ARG:
	case ST_RESULT:
	case ST_RULE:
	case ST_RULESET:
	case ST_ERRNO:
	case ST_MOD_DESCR:
	case ST_ACTION_DESCR:
	case ST_MATCH_DESCR:
	case ST_CMD_DESCR:
	case ST_NAME:
	case ST_ARGTYPE:
		return subtype_names[subtype - ST_MESSAGE];
	}
	snprintf(subtype_buf, 256, "Unknown subtype: %d", subtype);
	return subtype_buf;
}

static void
print_simple_block(const struct userfw_io_block *msg)
{
	char *buf = NULL;
	struct in_addr addr;
	struct in6_addr addr6;
	switch(msg->type)
	{
	case T_STRING:
		buf = malloc(msg->data.string.length + 1);
		if (buf != NULL)
		{
			bcopy(msg->data.string.data, buf, msg->data.string.length);
			buf[msg->data.string.length] = '\0';
			printf("%s", buf);
			free(buf);
		}
		else
		{
			fprintf(stderr, "Failed to allocate memory for string\n");
		}
		break;
	case T_HEXSTRING:
		{
			uint32_t i;
			for(i = 0; i < msg->data.string.length; i++)
				printf("%02X", (uint8_t)(msg->data.string.data[i]));
		}
		break;
	case T_UINT16:
		printf("%hu", msg->data.uint16.value);
		break;
	case T_UINT32:
		printf("%lu", msg->data.uint32.value);
		break;
	case T_UINT64:
		printf("%llu", msg->data.uint64.value);
		break;
	case T_IPv4:
		buf = malloc(INET_ADDRSTRLEN + 1);
		if (buf != NULL)
		{
			addr.s_addr = msg->data.ipv4.addr;
			inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN + 1);
			printf("%s", buf);
			int masklen = 0;
			uint32_t mask = ntohl(msg->data.ipv4.mask);
			while(mask & 0x80000000)
			{
				mask <<= 1;
				masklen++;
			}
			if (mask != 0)
			{
				addr.s_addr = msg->data.ipv4.mask;
				inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN + 1);
				printf(":%s", buf);
			}
			else if (masklen != 32)
			{
				printf("/%d", masklen);
			}
			free(buf);
		}
		else
		{
			fprintf(stderr, "Failed to allocate memory for IPv4 address\n");
		}
		break;
	case T_IPv6:
		buf = malloc(INET6_ADDRSTRLEN + 1);
		if (buf != NULL)
		{
			bcopy(msg->data.ipv6.addr, addr6.__u6_addr.__u6_addr32, sizeof(uint32_t)*4);
			inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN + 1);
			printf("%s", buf);
			int len = 0, i;
			uint32_t mask;
			for(i = 0; i < 4; i++)
			{
				if (msg->data.ipv6.mask[i] == 0xffffffff)
				{
					len += 32;
				}
				else
				{
					if (msg->data.ipv6.mask[i] != 0)
					{
						mask = ntohl(msg->data.ipv6.mask[i]);
						while((mask & 0x1) == 0)
						{
							len++;
							mask >>= 1;
						}
					}
					break;
				}
			}
			printf("/%d", len);
			free(buf);
		}
		else
		{
			fprintf(stderr, "Failed to allocate memory for IPv6 address\n");
		}
		break;
	}
}

static void
print_msg_full_recursive(const struct userfw_io_block *msg, const struct userfw_modlist* modlist, int indent)
{
	int i;

	print_indent(indent);
	printf("Type: %s\n", type_name(msg->type));
	print_indent(indent);
	printf("Subtype: %s\n", subtype_name(msg->subtype));
	switch(msg->type)
	{
	case T_STRING:
	case T_HEXSTRING:
	case T_UINT16:
	case T_UINT32:
	case T_UINT64:
	case T_IPv4:
	case T_IPv6:
		print_indent(indent);
		printf("Value: ");
		print_simple_block(msg);
		printf("\n");
		break;
	case T_MATCH:
	case T_ACTION:
	case T_CONTAINER:
		for(i = 0; i < msg->nargs; i++)
		{
			print_msg_full_recursive(msg->args[i], modlist, indent + 1);
		}
		break;
	}
}

void
print_msg_full(const struct userfw_io_block *msg, const struct userfw_modlist* modlist)
{
	print_msg_full_recursive(msg, modlist, 0);
}

static void
print_op_descr(const struct userfw_io_block *msg)
{
	opcode_t opcode;
	char name[USERFW_NAME_LEN + 1] = {0};
	int i;

	for(i = 0; i < msg->nargs; i++)
	{
		switch(msg->args[i]->subtype)
		{
		case ST_OPCODE:
			if (msg->args[i]->type == T_UINT32)
			{
				opcode = msg->args[i]->data.uint32.value;
			}
			else
			{
				printf("Error: wrong type for ST_OPCODE\n");
				return;
			}
			break;
		case ST_NAME:
			if (msg->args[i]->type == T_STRING)
			{
				bcopy(msg->args[i]->data.string.data, name,
					MIN(USERFW_NAME_LEN, msg->args[i]->data.string.length));
			}
			else
			{
				printf("Error: wrong type for ST_NAME\n");
				return;
			}
			break;
		}
	}

	switch(msg->subtype)
	{
	case ST_ACTION_DESCR:
		printf("Action:\t");
		break;
	case ST_MATCH_DESCR:
		printf("Match:\t");
		break;
	case ST_CMD_DESCR:
		printf("Command:\t");
		break;
	}

	printf("%s\tOpcode:\t%d\tArgs:\t", name, opcode);

	for(i = 0; i < msg->nargs; i++)
	{
		if (msg->args[i]->subtype == ST_ARGTYPE && msg->args[i]->type == T_UINT32)
		{
			printf("%s ", type_name(msg->args[i]->data.uint32.value));
		}
	}
}

static void
print_mod_descr(const struct userfw_io_block *msg)
{
	userfw_module_id_t	id = 0;
	char name[USERFW_NAME_LEN + 1] = {0};
	int i;

	for(i = 0; i < msg->nargs; i++)
	{
		switch(msg->args[i]->subtype)
		{
		case ST_MOD_ID:
			if (msg->args[i]->type == T_UINT32)
			{
				id = msg->args[i]->data.uint32.value;
			}
			else
			{
				printf("Error: wrong type for ST_MOD_ID\n");
				return;
			}
			break;
		case ST_NAME:
			if (msg->args[i]->type == T_STRING)
			{
				bcopy(msg->args[i]->data.string.data, name,
					MIN(USERFW_NAME_LEN, msg->args[i]->data.string.length));
			}
			else
			{
				printf("Error: wrong type for ST_NAME\n");
				return;
			}
			break;
		}
	}

	printf("ID: %u\tName: %s", id, name);

	for(i = 0; i < msg->nargs; i++)
	{
		switch(msg->args[i]->subtype)
		{
		case ST_ACTION_DESCR:
		case ST_MATCH_DESCR:
		case ST_CMD_DESCR:
			printf("\n");
			print_op_descr(msg->args[i]);
			break;
		}
	}
}

static void print_block(const struct userfw_io_block *msg, const struct userfw_modlist *modlist);

static void
print_ruleset(const struct userfw_io_block *msg, const struct userfw_modlist *modlist)
{
	int i;

	for(i = 0; i < msg->nargs; i++)
		print_block(msg->args[i], modlist);
}

static void print_action(const struct userfw_io_block *, const struct userfw_modlist *);
static void print_match(const struct userfw_io_block *, const struct userfw_modlist *);

#define PRINT_FUNCTION(x) static void \
print_ ## x(const struct userfw_io_block *msg, const struct userfw_modlist *modlist) \
{ \
	struct userfw_io_block *mod = NULL, *op = NULL; \
	struct userfw_modinfo *modinfo = NULL; \
	struct userfw_ ## x ## _descr *descr = NULL; \
	int i; \
 \
	for(i = 0; i < msg->nargs; i++) \
	{ \
		if (msg->args[i]->type == T_UINT32) \
		{ \
			switch(msg->args[i]->subtype) \
			{ \
			case ST_MOD_ID: \
				mod = msg->args[i]; \
				break; \
			case ST_OPCODE: \
				op = msg->args[i]; \
				break; \
			} \
		} \
	} \
 \
	if (mod == NULL || op == NULL) \
	{ \
		fprintf(stderr, "Not fully specfied entry\n"); \
		return; \
	} \
 \
	if (userfw_find_module_by_id(modlist, mod->data.uint32.value, &modinfo) == 0) \
	{ \
		fprintf(stderr, "Module %u not found.\n", mod->data.uint32.value); \
		return; \
	} \
 \
	if (userfw_find_ ## x ## _by_opcode(modinfo, op->data.uint32.value, &descr) == 0) \
	{ \
		fprintf(stderr, "Opcode %u not found in module %u.\n", op->data.uint32.value, mod->data.uint32.value); \
		return; \
	} \
 \
	printf("%s:%s ", modinfo->name, descr->name); \
	for(i = 0; i < msg->nargs; i++) \
	{ \
		if (msg->args[i]->subtype == ST_ARG) \
		{ \
			switch(msg->args[i]->type) \
			{ \
			case T_STRING: \
			case T_HEXSTRING: \
			case T_UINT16: \
			case T_UINT32: \
			case T_UINT64: \
			case T_IPv4: \
			case T_IPv6: \
				print_simple_block(msg->args[i]); \
				printf(" "); \
				break; \
			case T_MATCH: \
				print_match(msg->args[i], modlist); \
				break; \
			case T_ACTION: \
				print_action(msg->args[i], modlist); \
				break; \
			} \
		} \
	} \
}

PRINT_FUNCTION(action);
PRINT_FUNCTION(match);

static void
print_rule(const struct userfw_io_block *msg, const struct userfw_modlist *modlist)
{
	uint32_t number;
	struct userfw_io_block *action = NULL, *match = NULL;
	int i;

	for(i = 0; i < msg->nargs; i++)
	{
		switch(msg->args[i]->type)
		{
		case T_UINT32:
			number = msg->args[i]->data.uint32.value;
			break;
		case T_ACTION:
			action = msg->args[i];
			break;
		case T_MATCH:
			match = msg->args[i];
			break;
		}
	}

	printf("%u\t", number);
	if (action != NULL)
	{
		printf("Action:\t");
		print_action(action, modlist);
	}
	if (match != NULL)
	{
		printf("\tMatch:\t");
		print_match(match, modlist);
	}
}

static void
print_block(const struct userfw_io_block *msg, const struct userfw_modlist *modlist)
{
	switch(msg->type)
	{
	case T_UINT32:
		switch(msg->subtype)
		{
		case ST_COOKIE:
			return;
		case ST_ERRNO:
			switch(msg->data.uint32.value)
			{
			case 0:
				printf("OK\n");
				break;
			default:
				printf("Error: %d %s\n", msg->data.uint32.value,
					strerror(msg->data.uint32.value));
			}
			break;
		default:
			print_simple_block(msg);
			break;
		}
		break;
	case T_STRING:
	case T_HEXSTRING:
	case T_UINT16:
	case T_IPv4:
	case T_IPv6:
	case T_UINT64:
		print_simple_block(msg);
		printf("\t");
		break;
	case T_ACTION:
		print_action(msg, modlist);
		printf("\t");
		break;
	case T_MATCH:
		print_match(msg, modlist);
		printf("\t");
		break;
	case T_CONTAINER:
		switch(msg->subtype)
		{
		case ST_MOD_DESCR:
			print_mod_descr(msg);
			break;
		case ST_RULESET:
			print_ruleset(msg, modlist);
			break;
		case ST_RULE:
			print_rule(msg, modlist);
			printf("\n");
			break;
		default:
			print_msg(msg, modlist);
			printf("\n");
			break;
		}
		break;
	}
}

void
print_msg(const struct userfw_io_block *msg, const struct userfw_modlist *modlist)
{
	int i;

	for(i = 0; i < msg->nargs; i++)
	{
		print_block(msg->args[i], modlist);
	}
}
