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
#include <getopt.h>
#include <stdlib.h>
#ifdef CLI_SEPARATE_BUILD
#include <userfw/connection.h>
#include <userfw/message.h>
#include <userfw/mod_list.h>
#else
#include "../lib/connection.h"
#include "../lib/message.h"
#include "../lib/mod_list.h"
#endif
#include "parse.h"
#include "print.h"

enum { QUIET, NORMAL, DEBUG };

int mode = NORMAL;
struct userfw_modlist *modlist = NULL;

static struct option longopts[] = {
	{ "help",	no_argument,	NULL,	'h'},
	{ "mode",	required_argument,	NULL,	'm'},
	{ NULL,	0,	NULL,	0}
};

void
print_help(FILE *f, const char *name)
{
	fprintf(f, "Usage: %s [options] [command [args]]\n", name);
	fprintf(f, "\nOptions:\n");
	fprintf(f, "\t-h,--help\tshow this message\n");
	fprintf(f, "\t-m,--mode q|n|d\toutput mode: quiet, normal, debug\n");
}

int
parse_opts(int argc, char *argv[])
{
	char c;
	char *progname = argv[0];
	int start_argc = argc;

	while((c = getopt_long(argc, argv, "hm:", longopts, NULL)) != -1)
	{
		switch (c)
		{
		case 'h':
			print_help(stdout, progname);
			exit(0);
		case 'm':
			switch(optarg[0])
			{
			case 'q':
			case 'Q':
				mode = QUIET;
				break;
			case 'd':
			case 'D':
				mode = DEBUG;
				break;
			case 'n':
			case 'N':
				break;
			default:
				fprintf(stderr, "Unknown mode: %c\n", optarg[0]);
				print_help(stderr, progname);
				break;
			}
			break;
		default:
			print_help(stderr, progname);
			exit(1);
		}
		argc -= optind;
		argv += optind;
	}
	return start_argc - argc;
}

int main(int argc, char *argv[])
{
	int start_from;
	uint32_t cookie;
	struct userfw_connection *c = NULL;
	struct userfw_io_block *cmd = NULL;

	start_from = parse_opts(argc, argv);
	if (start_from == 0) // no options was given
		start_from = 1;
	if (start_from >= argc)
	{
		fprintf(stderr, "No command specified\n");
		print_help(stderr, argv[0]);
		exit(1);
	}

	c = userfw_connect();
	if (c == NULL)
	{
		fprintf(stderr, "Failed to create connection\n");
		return 1;
	}

	modlist = userfw_modlist_get(c);
	if (modlist == NULL)
	{
		fprintf(stderr, "Failed to get module list\n");
		return 1;
	}

	cmd = parse_cmd(argc - start_from, argv + start_from, modlist);
	if (cmd == NULL)
	{
		fprintf(stderr, "Failed to parse command\n");
		return 1;
	}

	if (mode == DEBUG)
	{
		printf("Message:\n");
		print_msg_full(cmd, modlist);
	}

	if (userfw_send(c, cmd, &cookie) < 0)
	{
		perror("userfw_send");
		fprintf(stderr, "Failed to send command\n");
		return 1;
	}

	userfw_msg_free(cmd);

	cmd = userfw_recv_wait(c, cookie, NULL);
	if (cmd == NULL)
	{
		fprintf(stderr, "Failed to read reply\n");
		return 1;
	}

	switch(mode)
	{
	case QUIET:
		break;
	case NORMAL:
		print_msg(cmd, modlist);
		break;
	case DEBUG:
		printf("Answer:\n");
		print_msg_full(cmd, modlist);
		break;
	}

	userfw_msg_free(cmd);
	userfw_modlist_destroy(modlist);
	userfw_disconnect(c);

	return 0;
}
