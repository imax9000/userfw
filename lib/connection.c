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
#include <sys/queue.h>
#include <assert.h>
#include <poll.h>
#include <fcntl.h>
#include "connection.h"
#ifdef LIB_SEPARATE_BUILD
#include <userfw/modules/base.h>
#else
#include "../core/base.h"
#endif

#define MSG_SIZE_WARN	1024*1024

struct queue_item
{
	STAILQ_ENTRY(queue_item)	next;
	uint32_t	cookie;
	struct userfw_io_block	*data;
};

STAILQ_HEAD(queue, queue_item);

static int queue_init(struct queue *);
static int queue_uninit(struct queue *);
static int queue_append(struct queue *, uint32_t, struct userfw_io_block *);
static struct userfw_io_block *queue_find_first(struct queue *, uint32_t);
static int queue_remove_first(struct queue *, uint32_t);
static struct userfw_io_block *queue_pop(struct queue *, uint32_t *);

struct userfw_connection_priv
{
	uint32_t	last_cookie;
	struct queue	queue;
	unsigned char	*rbuf, *wbuf;
	size_t	rbuflen, wbuflen;
	uint32_t	rmsglen, wmsglen;
	uint32_t	roffset, woffset;
	int	rstate;
};

enum rstate_values
{
	INIT, HEADER, BODY
};

static int process_readbuf(struct userfw_connection *c, int wait);
static int process_writebuf(struct userfw_connection *c, int wait);
static int append_to_writebuf(struct userfw_connection *c, unsigned char *data, size_t len);

static int
init_priv_data(struct userfw_connection_priv *p)
{
	p->last_cookie = 1; /* 0 reserved as "no cookie" */
	p->rbuf = p->wbuf = NULL;
	p->rbuflen = p->wbuflen = 0;
	p->rmsglen = p->wmsglen = p->roffset = p->woffset = 0;
	p->rstate = INIT;
	return queue_init(&(p->queue));
}

static void
uninit_priv_data(struct userfw_connection_priv *p)
{
	if (p->rbuf != NULL)
		free(p->rbuf);
	if (p->wbuf != NULL)
		free(p->wbuf);
	queue_uninit(&(p->queue));
}

static uint32_t
get_next_cookie(struct userfw_connection_priv *p)
{
	/* FIXME: integer overflow causes undefined behaviour :( */
	p->last_cookie++;
	if (p->last_cookie == 0)
		p->last_cookie++;
	return p->last_cookie;
}

struct userfw_connection *
userfw_connect(void)
{
	struct userfw_connection *c = NULL;

	c = malloc(sizeof(*c));

	if (c != NULL)
	{
		c->d = malloc(sizeof(*(c->d)));
		if (c->d != NULL)
		{
			c->fd = socket(AF_USERFW, SOCK_STREAM, 0);

			if (c->fd < 0 || init_priv_data(c->d) != 0)
			{
				free(c->d);
				free(c);
				c = NULL;
				perror("userfw_connect: socket()");
			}
			else
			{
				if (fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL) | O_NONBLOCK) == -1)
				{
					perror("userfw_connect: fcntl()");
				}
			}
		}
		else
		{
			free(c);
			c = NULL;
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
		uninit_priv_data(c->d);
		ret = close(c->fd);
		free(c->d);
		free(c);
	}

	return ret;
}

int
userfw_send(struct userfw_connection *c, struct userfw_io_block *data, uint32_t *cookie)
{
	int ret = 0, cookie_val = 0;
	struct userfw_io_block *msg;
	unsigned char *buf = NULL;
	size_t len;

	if (c == NULL || data == NULL)
		return -EINVAL;

	if (cookie != NULL)
		*cookie = cookie_val = get_next_cookie(c->d);

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2);
	if (msg != NULL)
	{
		if ((errno = userfw_msg_insert_uint32(msg, ST_COOKIE, cookie_val, 0) == 0) &&
			(errno = userfw_msg_set_arg(msg, data, 1)) == 0)
		{
			len = userfw_msg_calc_size(msg);
			buf = malloc(len);
			if (buf != NULL)
				len = userfw_msg_serialize(msg, buf, len);
			else
				ret = -EINVAL;
		}
		userfw_msg_set_arg(msg, NULL, 1); // avoid free()'ing data
		userfw_msg_free(msg);
	}
	else
		return -EINVAL;

	if (ret == 0 && len > 0)
	{
		append_to_writebuf(c, buf, len);
		ret = process_writebuf(c, 1);
	}
	if (buf != NULL)
		free(buf);

	return ret;
}

struct userfw_io_block *
userfw_recv(struct userfw_connection *c, uint32_t cookie, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL || cookie == 0)
		return NULL;

	ret = process_readbuf(c, 1);
	msg = queue_find_first(&(c->d->queue), cookie);
	if (msg != NULL)
	{
		queue_remove_first(&(c->d->queue), cookie);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_wait(struct userfw_connection *c, uint32_t cookie, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL || cookie == 0)
		return NULL;

	do {
		msg = queue_find_first(&(c->d->queue), cookie);
		if (msg == NULL)
			ret = process_readbuf(c, 1);
	} while(msg == NULL && ret == 0);

	if (msg != NULL)
	{
		queue_remove_first(&(c->d->queue), cookie);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_nowait(struct userfw_connection *c, uint32_t cookie, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL || cookie == 0)
		return NULL;

	ret = process_readbuf(c, 0);
	msg = queue_find_first(&(c->d->queue), cookie);
	if (msg != NULL)
	{
		queue_remove_first(&(c->d->queue), cookie);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_unhandled(struct userfw_connection *c, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL)
		return NULL;

	ret = process_readbuf(c, 1);
	msg = queue_find_first(&(c->d->queue), 0);
	if (msg != NULL)
	{
		queue_remove_first(&(c->d->queue), 0);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_unhandled_nowait(struct userfw_connection *c, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL)
		return NULL;

	ret = process_readbuf(c, 0);
	msg = queue_find_first(&(c->d->queue), 0);
	if (msg != NULL)
	{
		queue_remove_first(&(c->d->queue), 0);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_next(struct userfw_connection *c, uint32_t *cookie, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL || cookie == NULL)
		return NULL;

	while((msg = queue_pop(&(c->d->queue), cookie)) == NULL)
	{
		ret = process_readbuf(c, 1);
	}

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_recv_next_nowait(struct userfw_connection *c, uint32_t *cookie, int *result)
{
	int ret = 0;
	struct userfw_io_block *msg = NULL;

	if (c == NULL || cookie == NULL)
		return NULL;

	ret = process_readbuf(c, 0);
	msg = queue_pop(&(c->d->queue), cookie);

	if (result != NULL)
		*result = ret;

	return msg;
}

struct userfw_io_block *
userfw_exec_command(struct userfw_connection *c, userfw_module_id_t mod, opcode_t op, userfw_arg* args, uint8_t nargs)
{
	struct userfw_io_block *msg = NULL;
	int ret, i;
	uint32_t cookie;

	if (c == NULL)
		return NULL;

	msg = userfw_msg_alloc_container(T_CONTAINER, ST_CMDCALL, 2 + ((args != NULL) ? nargs : 0));
	if (msg != NULL)
	{
		ret = userfw_msg_insert_uint32(msg, ST_MOD_ID, mod, 0);
		if (ret == 0)
			ret = userfw_msg_insert_uint32(msg, ST_OPCODE, op, 1);
		for(i = 0; i < nargs && ret == 0; i++)
		{
			ret = userfw_msg_insert_arg(msg, ST_ARG, &(args[i]), i + 2);
		}

		userfw_send(c, msg, &cookie);
		userfw_msg_free(msg);

		msg = userfw_recv_wait(c, cookie, NULL);
	}
	return msg;
}

static int
realloc_readbuf(struct userfw_connection_priv *p, uint32_t size)
{
	unsigned char *newbuf = NULL;

	if (size > p->rbuflen)
	{
		newbuf = malloc(size);
		if (newbuf != NULL)
		{
			if (p->rbuf != NULL)
			{
				bcopy(p->rbuf, newbuf, p->rbuflen);
				free(p->rbuf);
			}
			p->rbuf = newbuf;
			p->rbuflen = size;
		}
		else
			return ENOMEM;
	}
	return 0;
}

static int
process_readbuf_wait(struct userfw_connection *c)
{
	struct pollfd fd;
	int ret, i;
	uint32_t cookie;
	ssize_t bytes_read;
	struct userfw_io_header *hdr;
	struct userfw_io_block *msg;

	fd.fd = c->fd;
	fd.events = POLLRDNORM;

	do
	{
		switch(c->d->rstate)
		{
		case INIT:
			c->d->rstate = HEADER;
			c->d->roffset = 0;
			c->d->rmsglen = sizeof(struct userfw_io_header);
			break;
		case HEADER:
			if (c->d->roffset >= sizeof(struct userfw_io_header))
			{
				hdr = (struct userfw_io_header *)c->d->rbuf;
				c->d->rmsglen = hdr->length;
				if (hdr->length >= MSG_SIZE_WARN)
					fprintf(stderr, "userfw_connection: Warning: incoming message size == %u, fd == %d\n", hdr->length, c->fd);
				c->d->rstate = BODY;
			}
			break;
		case BODY:
			if (c->d->roffset == c->d->rmsglen)
			{
				msg = userfw_msg_parse(c->d->rbuf, c->d->rmsglen);
				if (msg != NULL)
				{
					for(i = 0; i < msg->nargs; i++)
					{
						if (msg->args[i]->type == T_UINT32 && msg->args[i]->subtype == ST_COOKIE)
							cookie = msg->args[i]->data.uint32.value;
					}
					queue_append(&(c->d->queue), cookie, msg);
				}
				c->d->rmsglen = 0;
				c->d->roffset = 0;
				c->d->rstate = INIT;
			}
			break;
		}
		if (c->d->rstate != INIT)
		{
			if (realloc_readbuf(c->d, c->d->rmsglen) != 0)
				return ENOMEM;
			ret = poll(&fd, 1, INFTIM);
			if (ret != -1)
			{
				bytes_read = read(c->fd, c->d->rbuf + c->d->roffset, c->d->rmsglen - c->d->roffset);
				if (bytes_read >= 0)
					c->d->roffset += bytes_read;
				else
				{
					perror("userfw_connection: poll(2) returned success, but read(2) returned error");
					return errno;
				}
			}
			else
			{
				if (errno != EINTR)
					return errno;
			}
		}
	} while(c->d->rstate != INIT || poll(&fd, 1, 0) > 0);

	return 0;
}

static int
process_readbuf_nowait(struct userfw_connection *c)
{
	struct pollfd fd;
	int i;
	uint32_t cookie = 0;
	ssize_t bytes_read;
	struct userfw_io_header *hdr;
	struct userfw_io_block *msg;

	fd.fd = c->fd;
	fd.events = POLLRDNORM;

	do
	{
		switch(c->d->rstate)
		{
		case INIT:
			c->d->rstate = HEADER;
			c->d->roffset = 0;
			c->d->rmsglen = sizeof(struct userfw_io_header);
			break;
		case HEADER:
			if (c->d->roffset >= sizeof(struct userfw_io_header))
			{
				hdr = (struct userfw_io_header *)c->d->rbuf;
				c->d->rmsglen = hdr->length;
				if (hdr->length >= MSG_SIZE_WARN)
					fprintf(stderr, "userfw_connection: Warning: incoming message size == %u, fd == %d\n", hdr->length, c->fd);
				c->d->rstate = BODY;
			}
			break;
		case BODY:
			if (c->d->roffset == c->d->rmsglen)
			{
				msg = userfw_msg_parse(c->d->rbuf, c->d->rmsglen);
				if (msg != NULL)
				{
					for(i = 0; i < msg->nargs; i++)
					{
						if (msg->args[i]->type == T_UINT32 && msg->args[i]->subtype == ST_COOKIE)
							cookie = msg->args[i]->data.uint32.value;
					}
					queue_append(&(c->d->queue), cookie, msg);
				}
				c->d->rmsglen = 0;
				c->d->roffset = 0;
				c->d->rstate = INIT;
			}
			break;
		}
		if (realloc_readbuf(c->d, c->d->rmsglen) != 0)
			return ENOMEM;
		do {
			bytes_read = read(c->fd, c->d->rbuf + c->d->roffset, c->d->rmsglen - c->d->roffset);
		} while(bytes_read == -1 && errno == EINTR);
		if (bytes_read >= 0)
			c->d->roffset += bytes_read;
		else
		{
			if (errno != EAGAIN)
				return errno;
		}
	} while(poll(&fd, 1, 0) > 0);

	return 0;
}

static int
process_readbuf(struct userfw_connection *c, int wait)
{
	if (wait)
		return process_readbuf_wait(c);
	else
		return process_readbuf_nowait(c);
}

static int
realloc_writebuf(struct userfw_connection_priv *p, uint32_t size)
{
	unsigned char *newbuf = NULL;

	if (size > p->wbuflen)
	{
		newbuf = malloc(size);
		if (newbuf != NULL)
		{
			if (p->wbuf != NULL)
			{
				bcopy(p->wbuf, newbuf, p->wbuflen);
				free(p->wbuf);
			}
			p->wbuf = newbuf;
			p->wbuflen = size;
		}
		else
			return ENOMEM;
	}
	return 0;
}

static int
append_to_writebuf(struct userfw_connection *c, unsigned char *data, size_t len)
{
	if (realloc_writebuf(c->d, c->d->wmsglen + len) != 0)
		return ENOMEM;
	bcopy(data, c->d->wbuf + c->d->wmsglen, len);
	c->d->wmsglen += len;
	return 0;
}

static int
process_writebuf(struct userfw_connection *c, int wait)
{
	struct pollfd fd;
	ssize_t	ret;

	if (c->d->wbuf != NULL)
	{
		if (wait)
		{
			fd.fd = c->fd;
			fd.events = POLLWRNORM;
			fd.revents = 0;
			while(c->d->woffset < c->d->wmsglen)
			{
				while((ret = poll(&fd, 1, INFTIM)) == -1 && errno == EINTR);
				if (ret == -1)
					return errno;
				ret = write(c->fd, c->d->wbuf + c->d->woffset, c->d->wmsglen - c->d->woffset);
				if (ret > 0)
				{
					c->d->woffset += ret;
				}
				else
				{
					perror("userfw_connection: write");
					return errno;
				}
			}
			c->d->woffset = c->d->wmsglen = 0;
		}
		else
		{
			if (c->d->woffset < c->d->wmsglen)
			{
				ret = write(c->fd, c->d->wbuf + c->d->woffset, c->d->wmsglen - c->d->woffset);
				if (ret > 0)
				{
					c->d->woffset += ret;
				}
				else if (errno != EAGAIN)
				{
					perror("userfw_connection: write");
					return errno;
				}
			}
			if (c->d->woffset == c->d->wmsglen)
			{
				c->d->woffset = c->d->wmsglen = 0;
			}
		}
	}
	return 0;
}

/*
 * queue implementation
 */

static int
queue_init(struct queue *q)
{
	assert(q != NULL);
	STAILQ_INIT(q);
	return 0;
}

static int
queue_uninit(struct queue *q)
{
	struct queue_item *cur, *next;

	assert(q != NULL);
	cur = STAILQ_FIRST(q);
	while(cur != NULL)
	{
		next = STAILQ_NEXT(cur, next);
		if (cur->data != NULL)
			userfw_msg_free(cur->data);
		free(cur);
		cur = next;
	}
	return 0;
}

static int
queue_append(struct queue *q, uint32_t cookie, struct userfw_io_block *msg)
{
	struct queue_item *item;

	assert(q != NULL);
	item = malloc(sizeof(*item));
	if (item != NULL)
	{
		item->cookie = cookie;
		item->data = msg;
		STAILQ_INSERT_TAIL(q, item, next);
	}
	else
		return ENOMEM;
	return 0;
}

static struct userfw_io_block *
queue_find_first(struct queue *q, uint32_t cookie)
{
	struct queue_item *item;

	assert(q != NULL);
	STAILQ_FOREACH(item, q, next)
	{
		if (item->cookie == cookie)
			return item->data;
	}
	return NULL;
}

static int
queue_remove_first(struct queue *q, uint32_t cookie)
{
	struct queue_item *item;

	assert(q != NULL);
	STAILQ_FOREACH(item, q, next)
	{
		if (item->cookie == cookie)
			break;
	}
	if (item != NULL)
	{
		STAILQ_REMOVE(q, item, queue_item, next);
		free(item);
		return 0;
	}
	return ENOENT;
}

static struct userfw_io_block *
queue_pop(struct queue *q, uint32_t *cookie)
{
	struct queue_item *item;
	struct userfw_io_block *msg;

	assert(q != NULL);
	item = STAILQ_FIRST(q);
	if (item != NULL)
	{
		msg = item->data;
		if (cookie != NULL)
			*cookie = item->cookie;
		STAILQ_REMOVE_HEAD(q, next);
		free(item);
		return msg;
	}
	else
		return NULL;
}
