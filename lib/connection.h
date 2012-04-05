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

#ifndef USERFW_CONNECTION_H
#define USERFW_CONNECTION_H

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <userfw/types.h>

struct userfw_connection_priv;

struct userfw_connection
{
	struct userfw_connection_priv *d; /* private data */
	int fd;
};

struct userfw_connection * userfw_connect(void);
int userfw_disconnect(struct userfw_connection *);

/* sends message to kernel, sets cookie */
int userfw_send(struct userfw_connection *, struct userfw_io_block *, uint32_t *cookie);

/* waits for next message, returns NULL if cookie does not match */
struct userfw_io_block * userfw_recv(struct userfw_connection *, uint32_t cookie, int *result);

/* waits for message with specific cookie */
struct userfw_io_block * userfw_recv_wait(struct userfw_connection *, uint32_t cookie, int *result);

/* returns immediately even if message with specific cookie still not received */
struct userfw_io_block * userfw_recv_nowait(struct userfw_connection *, uint32_t cookie, int *result);

/* returns message without cookie */
struct userfw_io_block * userfw_recv_unhandled(struct userfw_connection *, int *result);
struct userfw_io_block * userfw_recv_unhandled_nowait(struct userfw_connection *, int *result);

/* returns message and it's cookie without any filtering (useful for custom dispatcher) */
struct userfw_io_block * userfw_recv_next(struct userfw_connection *, uint32_t *cookie, int *result);
struct userfw_io_block * userfw_recv_next_nowait(struct userfw_connection *, uint32_t *cookie, int *result);

/* sends message with command call and returns answer */
struct userfw_io_block * userfw_exec_command(struct userfw_connection *, userfw_module_id_t, opcode_t, userfw_arg*, uint8_t);

#ifdef __cplusplus
}
#endif

#endif /* USERFW_CONNECTION_H */
