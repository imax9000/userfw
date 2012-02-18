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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "parse.h"

#define SEARCH_FUNCTION(x) static struct userfw_ ## x ## _descr * find_ ## x(const char *name, const struct userfw_modlist *modlist) \
{ \
	char *c = strchr(name, ':'); \
	struct userfw_ ## x ## _descr *ret = NULL; \
	int n; \
	 \
	if (c == NULL) \
	{ \
		switch (n = userfw_find_ ## x(modlist, name, strlen(name), &ret)) \
		{ \
		case 0: \
			fprintf(stderr, "Not found: %s\n", name); \
			ret = NULL; \
			break; \
		case 1: \
			break; \
		default: \
			fprintf(stderr, "Too ambiguous: %s (%d occurences)\n", name, n); \
			ret = NULL; \
			break; \
		} \
	} \
	else \
	{ \
		struct userfw_modinfo *mod = NULL; \
		*c = '\0'; \
 \
		switch (n = userfw_find_module_by_name(modlist, name, strlen(name), &mod)) \
		{ \
		case 0: \
			n = strtol(name, NULL, 0); \
			if (n != 0 || errno == 0) \
			{ \
				switch(n = userfw_find_module_by_id(modlist, n, &mod)) \
				{ \
				case 0: \
					fprintf(stderr, "Module not found: %s\n", name); \
					mod = NULL; \
					break; \
				case 1: \
					break; \
				default: /* This should never happen */ \
					fprintf(stderr, "Found %d modules with id %s\n. Probably this is a bug.\n", n, name); \
					mod = NULL; \
					break; \
				} \
			} \
			else \
			{ \
				fprintf(stderr, "Module not found: %s\n", name); \
				mod = NULL; \
			} \
			break; \
		case 1: \
			break; \
		default: \
			fprintf(stderr, "Too ambiguous: %s (%d occurences)\n", name, n); \
			mod = NULL; \
			break; \
		} \
 \
		*c = ':'; \
 \
		if (mod != NULL) \
		{ \
			switch (n = userfw_find_ ## x ## _in_module(mod, c + 1, strlen(c + 1), &ret)) \
			{ \
			case 0: \
				fprintf(stderr, "Not found: %s\n", name); \
				ret = NULL; \
				break; \
			case 1: \
				break; \
			default: \
				fprintf(stderr, "Too ambiguous: %s (%d occurences)\n", name, n); \
				ret = NULL; \
				break; \
			} \
		} \
	} \
 \
	return ret; \
}

SEARCH_FUNCTION(cmd);
SEARCH_FUNCTION(action);
SEARCH_FUNCTION(match);

static struct userfw_io_block *
parse_uint32(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_UINT32, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_UINT32;
		ret->data.uint32.value = strtoul(argv[0], NULL, 0);
		if (errno != 0)
		{
			perror("strtoul");
			fprintf(stderr, "Failed to parse %s as T_UINT32\n", argv[0]);
			userfw_msg_free(ret);
			ret = NULL;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_UINT32\n");
	}

	return ret;
}

static struct userfw_io_block *
parse_uint16(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_UINT16, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_UINT16;
		ret->data.uint16.value = strtoul(argv[0], NULL, 0);
		if (errno != 0)
		{
			perror("strtoul");
			fprintf(stderr, "Failed to parse %s as T_UINT16\n", argv[0]);
			userfw_msg_free(ret);
			ret = NULL;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_UINT16\n");
	}

	return ret;
}

static struct userfw_io_block *
parse_uint64(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_UINT64, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_UINT64;
		ret->data.uint64.value = strtoull(argv[0], NULL, 0);
		if (errno != 0)
		{
			perror("strtoull");
			fprintf(stderr, "Failed to parse %s as T_UINT64\n", argv[0]);
			userfw_msg_free(ret);
			ret = NULL;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_UINT64\n");
	}

	return ret;
}


static struct userfw_io_block *
parse_string(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_STRING, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_STRING;
		size_t len = strlen(argv[0]);
		ret->data.string.data = malloc(len);
		if (ret->data.string.data != NULL)
		{
			ret->data.string.length = len;
			bcopy(argv[0], ret->data.string.data, len);
		}
		else
		{
			fprintf(stderr, "Failed to allocate %zu bytes for T_STRING\n", len);
			userfw_msg_free(ret);
			ret = NULL;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_STRING\n");
	}

	return ret;
}

static struct userfw_io_block *
parse_hexstring(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_HEXSTRING, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_HEXSTRING;
		size_t len = strlen(argv[0]), i;
		char buf[3] = {0};
		if (len % 2 == 0)
		{
			len /= 2;
			ret->data.string.data = malloc(len);
			ret->data.string.length = len;
			if (ret->data.string.data != NULL)
			{
				for(i = 0; i < len; i++)
				{
					buf[0] = argv[0][i*2];
					buf[1] = argv[0][i*2+1];
					if ((ret->data.string.data[i] = strtol(buf, NULL, 16)) == 0 && errno != 0)
					{
						fprintf(stderr, "Failed to convert \"%s\" to number: %s", buf, strerror(errno));
						userfw_msg_free(ret);
						ret = NULL;
						break;
					}
				}
			}
			else
			{
				fprintf(stderr, "Failed to allocate %zu bytes for T_HEXSTRING\n", len);
				userfw_msg_free(ret);
				ret = NULL;
			}
		}
		else
		{
			fprintf(stderr, "Incorrect hexstring length\n");
			userfw_msg_free(ret);
			ret = NULL;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_HEXSTRING\n");
	}

 	return ret;
}

static struct userfw_io_block *
parse_ipv4(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;
	struct in_addr addr;
	char *c;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_IPv4, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_IPv4;
		c = strchr(argv[0], ':');
		if (c == NULL)
			c = strchr(argv[0], '/');

		if (c == NULL) // only address
		{
			ret->data.ipv4.mask = 0xffffffff;
		}
		else if (*c == ':') // bitmask
		{
			switch(inet_pton(AF_INET, c + 1, &addr))
			{
			case 1:
				ret->data.ipv4.mask = addr.s_addr;
				break;
			case -1:
				perror("inet_pton");
			case 0:
				fprintf(stderr, "Failed to parse bitmask in %s\n", argv[0]);
				userfw_msg_free(ret);
				ret = NULL;
				break;
			}
		}
		else if (*c == '/') // CIDR notation
		{
			int n;
			n = strtonum(c + 1, 0, 32, NULL);
			if (errno == 0)
			{
				ret->data.ipv4.mask = htonl(0xffffffff << (32 - n));
			}
			else
			{
				perror("strtonum");
				fprintf(stderr, "Failed to parse prefix length in %s\n", argv[0]);
			}
		}

		if (c != NULL)
			*c = '\0';

		switch(inet_pton(AF_INET, argv[0], &addr))
		{
		case 1:
			ret->data.ipv4.addr = addr.s_addr;
			break;
		case -1:
			perror("inet_pton");
		case 0:
			fprintf(stderr, "Failed to parse address %s\n", argv[0]);
			userfw_msg_free(ret);
			ret = NULL;
			break;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_IPv4\n");
	}

	return ret;
}

static struct userfw_io_block *
parse_ipv6(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed)
{
	struct userfw_io_block *ret = NULL;
	struct in6_addr addr;
	char *c;

	if (argc < 1)
		return NULL;

	ret = userfw_msg_alloc_block(T_IPv6, ST_ARG);

	if (ret != NULL)
	{
		ret->data.type = T_IPv6;
		c = strchr(argv[0], '/');

		if (c == NULL) // only address
		{
			memset(ret->data.ipv6.mask, 0xff, sizeof(uint32_t)*4);
		}
		else if (*c == '/') // CIDR notation
		{
			int n, i;
			n = strtonum(c + 1, 0, 128, NULL);
			if (errno == 0)
			{
				bzero(ret->data.ipv6.mask, sizeof(uint32_t)*4);
				for(i = 0; i < 4; i++)
				{
					if (n >= 32)
					{
						ret->data.ipv6.mask[i] = 0xffffffff;
						n -= 32;
					}
					else
					{
						ret->data.ipv6.mask[i] = htonl(0xffffffff << (32 - n));
						break;
					}
				}
			}
			else
			{
				perror("strtonum");
				fprintf(stderr, "Failed to parse prefix length in %s\n", argv[0]);
			}
		}

		if (c != NULL)
			*c = '\0';

		switch(inet_pton(AF_INET6, argv[0], &addr))
		{
		case 1:
			bcopy(addr.__u6_addr.__u6_addr32, ret->data.ipv6.addr, sizeof(uint32_t)*4);
			break;
		case -1:
			perror("inet_pton");
		case 0:
			fprintf(stderr, "Failed to parse address %s\n", argv[0]);
			userfw_msg_free(ret);
			ret = NULL;
			break;
		}
		*consumed = 1;
	}
	else
	{
		fprintf(stderr, "Failed to allocate memory for T_IPv6\n");
	}

	return ret;
}

struct userfw_io_block * parse_arg(int argc, char *argv[], int type, struct userfw_modlist *modlist, int *consumed);

#define PARSE_FUNCTION(x, y) struct userfw_io_block * \
parse_ ## x(int argc, char *argv[], struct userfw_modlist *modlist, int *consumed) \
{ \
	struct userfw_io_block *ret = NULL, *arg; \
	struct userfw_ ## x ## _descr *descr = NULL; \
	int d, i; \
 \
	if (argc < 1) \
		return NULL; \
 \
	descr = find_ ## x(argv[0], modlist); \
 \
	if (descr != NULL) \
	{ \
		ret = userfw_msg_alloc_container(y, ST_ARG, descr->nargs + 2); \
		if (ret != NULL) \
		{ \
			userfw_msg_insert_uint32(ret, ST_MOD_ID, descr->module, 0); \
			userfw_msg_insert_uint32(ret, ST_OPCODE, descr->opcode, 1); \
			argc--; \
			argv++; \
			*consumed = 1; \
			for(i = 0; i < descr->nargs && argc > 0; i++) \
			{ \
				arg = parse_arg(argc, argv, descr->arg_types[i], modlist, &d); \
				if (arg == NULL) \
				{ \
					userfw_msg_free(ret); \
					ret = NULL; \
					break; \
				} \
				argc -= d; \
				argv += d; \
				userfw_msg_set_arg(ret, arg, i + 2); \
				*consumed += d; \
			} \
			if (argc == 0 && i < descr->nargs) \
			{ \
				fprintf(stderr, "Not enough arguments for \"%s\"\n", descr->name); \
				userfw_msg_free(ret); \
				ret = NULL; \
			} \
		} \
	} \
	else \
	{ \
		fprintf(stderr, "Not found: %s\n", argv[0]); \
	} \
 \
	return ret; \
}

PARSE_FUNCTION(match, T_MATCH);
PARSE_FUNCTION(action, T_ACTION);

struct userfw_io_block *
parse_arg(int argc, char *argv[], int type, struct userfw_modlist *modlist, int *consumed)
{
	switch(type)
	{
	case T_STRING:
		return parse_string(argc, argv, modlist, consumed);
	case T_HEXSTRING:
		return parse_hexstring(argc, argv, modlist, consumed);
	case T_UINT16:
		return parse_uint16(argc, argv, modlist, consumed);
	case T_UINT32:
		return parse_uint32(argc, argv, modlist, consumed);
	case T_UINT64:
		return parse_uint64(argc, argv, modlist, consumed);
	case T_IPv4:
		return parse_ipv4(argc, argv, modlist, consumed);
	case T_IPv6:
		return parse_ipv6(argc, argv, modlist, consumed);
	case T_MATCH:
		return parse_match(argc, argv, modlist, consumed);
	case T_ACTION:
		return parse_action(argc, argv, modlist, consumed);
	}
	return NULL;
}

struct userfw_io_block *
parse_cmd(int argc, char *argv[], struct userfw_modlist *modlist)
{
	struct userfw_cmd_descr *cmd = NULL;
	struct userfw_io_block *ret = NULL, *arg;
	int i, d;

	cmd = find_cmd(argv[0], modlist);

	if (cmd != NULL)
	{
		ret = userfw_msg_alloc_container(T_CONTAINER, ST_CMDCALL, cmd->nargs + 2);
		if (ret != NULL)
		{
			userfw_msg_insert_uint32(ret, ST_MOD_ID, cmd->module, 0);
			userfw_msg_insert_uint32(ret, ST_OPCODE, cmd->opcode, 1);
			argc--;
			argv++;
			for(i = 0; i < cmd->nargs; i++)
			{
				arg = parse_arg(argc, argv, cmd->arg_types[i], modlist, &d);
				if (arg == NULL)
				{
					fprintf(stderr, "Failed to parse argument %d\n", i + 1);
					userfw_msg_free(ret);
					ret = NULL;
					break;
				}
				argc -= d;
				argv += d;
				userfw_msg_set_arg(ret, arg, i + 2);
			}
		}
	}

	return ret;
}
