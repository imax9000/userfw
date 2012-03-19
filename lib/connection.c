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
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <userfw/io.h>
#include "connection.h"
#ifdef LIB_SEPARATE_BUILD
#include <userfw/modules/base.h>
#else
#include "../core/base.h"
#endif

#define MSG_SIZE_WARN	1024*1024

struct userfw_connection *
userfw_connect()
{
	struct userfw_connection *c = NULL;

	c = malloc(sizeof(*c));

	if (c != NULL)
	{
		c->fd = socket(AF_USERFW, SOCK_STREAM, 0);
		c->d = NULL;

		if (c->fd < 0)
		{
			free(c);
			c = NULL;
			perror("userfw_connect: socket()");
		}
	}

	return c;
}

int
userfw_disconnect(struct userfw_connection *c)
{
	int ret = 0;

	if (c != NULL)
	{
		ret = close(c->fd);
		free(c);
	}

	return ret;
}

int
userfw_send(struct userfw_connection *c, unsigned char *buf, size_t len)
{
	int written = 0, ret = 0;

	while(written < len)
	{
		if ((ret = write(c->fd, buf + written, len - written)) > 0)
		{
			written += ret;
		}
		else
		{
			if (errno != EAGAIN)
			{
				written = -1;
				break;
			}
		}
	}

	return written;
}

int
userfw_send_modlist_cmd(struct userfw_connection *c)
{
	struct userfw_io_block *msg = NULL;
	unsigned char *buf = NULL;
	int ret = -1, len;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_CMDCALL, 2);
	if (msg != NULL)
	{
		if ((errno = userfw_msg_insert_uint32(msg, ST_MOD_ID, USERFW_BASE_MOD, 0)) == 0 &&
				(errno = userfw_msg_insert_uint32(msg, ST_OPCODE, CMD_MODLIST, 1)) == 0)
		{
			len = userfw_msg_calc_size(msg);
			buf = malloc(len);
			if (buf != NULL)
			{
				userfw_msg_serialize(msg, buf, len);
				ret = userfw_send(c, buf, len) > 0 ? 0 : -1;
				free(buf);
			}
		}
		userfw_msg_free(msg);
	}

	return ret;
}

int
userfw_send_modinfo_cmd(struct userfw_connection *c, userfw_module_id_t mod)
{
	struct userfw_io_block *msg = NULL;
	unsigned char *buf = NULL;
	int ret = -1, len;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_CMDCALL, 3);
	if (msg != NULL)
	{
		if ((errno = userfw_msg_insert_uint32(msg, ST_MOD_ID, USERFW_BASE_MOD, 0)) == 0 &&
				(errno = userfw_msg_insert_uint32(msg, ST_OPCODE, CMD_MODINFO, 1)) == 0 &&
				(errno = userfw_msg_insert_uint32(msg, ST_ARG, mod, 2)) == 0)
		{
			len = userfw_msg_calc_size(msg);
			buf = malloc(len);
			if (buf != NULL)
			{
				userfw_msg_serialize(msg, buf, len);
				ret = userfw_send(c, buf, len) > 0 ? 0 : -1;
				free(buf);
			}
		}
		userfw_msg_free(msg);
	}

	return ret;
}

static ssize_t
read_(int fd, void *buf_, size_t nbytes)
{
	char *buf = buf_;
	size_t ret = 0, bytes_read = 0;

	while(bytes_read < nbytes)
	{
		ret = read(fd, buf + bytes_read, nbytes - bytes_read);
		if (ret > 0)
			bytes_read += ret;
		else if (errno != EAGAIN)
			break;
	}

	return bytes_read;
}

struct userfw_io_block *
userfw_recv_msg(struct userfw_connection *c)
{
	struct userfw_io_header hdr;
	struct userfw_io_block *msg = NULL;
	unsigned char *buf;
	size_t ret;

	ret = read_(c->fd, (void*)(&hdr), sizeof(hdr));
	if (ret > 0)
	{
		if (hdr.length >= MSG_SIZE_WARN)
			fprintf(stderr, "userfw_recv_msg: Warning: incoming message size == %u\n", hdr.length);
		buf = malloc(hdr.length);
		if (buf != NULL)
		{
			bcopy(&hdr, buf, sizeof(hdr));
			ret = read_(c->fd, buf + sizeof(hdr), hdr.length - sizeof(hdr));
			msg = userfw_msg_parse(buf, hdr.length);
			free(buf);
		}
	}

	return msg;
}
