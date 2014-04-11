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

#ifndef USERFW_RULESET_H
#define USERFW_RULESET_H

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <userfw/module.h>
#include <userfw/io.h>

typedef struct __userfw_rule
{
	struct __userfw_rule *next;

	uint32_t	number;
	userfw_action	action;
	userfw_match	match;
} userfw_rule;

typedef struct __userfw_ruleset
{
	userfw_rule	*rule;
	struct rmlock	mtx;
	struct rm_priotracker rm_internal;
} userfw_ruleset;

extern userfw_ruleset global_rules;

#define USERFW_RLOCK(p)	rm_rlock(&((p)->mtx), &((p)->rm_internal))
#define USERFW_WLOCK(p)	rm_wlock(&((p)->mtx))
#define USERFW_RUNLOCK(p)	rm_runlock(&((p)->mtx), &((p)->rm_internal))
#define USERFW_WUNLOCK(p)	rm_wunlock(&((p)->mtx))
#define USERFW_INIT_LOCK(p, s)	rm_init(&((p)->mtx), (s))
#define USERFW_UNINIT_LOCK(p)	rm_destroy(&((p)->mtx))

struct malloc_type;

void userfw_ruleset_init(userfw_ruleset *, const char *name);
void userfw_ruleset_uninit(userfw_ruleset *, struct malloc_type *);

/** Inserts single rule */
int userfw_ruleset_insert_rule(userfw_ruleset *, userfw_rule *);

/** Deletes single rule */
int userfw_ruleset_delete_rule(userfw_ruleset *, uint32_t, struct malloc_type *);

/** Replaces whole ruleset with new chain of rules and drops old chain */
int userfw_ruleset_replace(userfw_ruleset *, userfw_rule *head, struct malloc_type *);

/** Serialize ruleset or rule to buffer, return actual size or -(error code) */
struct userfw_io_block * userfw_ruleset_serialize(userfw_ruleset *, struct malloc_type *);
struct userfw_io_block * userfw_ruleset_serialize_rule(userfw_rule *, struct malloc_type *);

int check_packet(struct mbuf **mb, userfw_chk_args *args, userfw_ruleset *ruleset);

void free_rule(userfw_rule *, struct malloc_type *);

/*
 * This function should be called to continue packet processing after returning
 * packet from other subsystem (i.e. dummynet, netgraph).
 * Returns 0 upon success and any other value on error. If pointer to mbuf not
 * set to NULL then caller is the one who responsible to free mbuf.
 */
int userfw_return_packet(struct mbuf **);

#endif /* _KERNEL */
#endif /* USERFW_RULESET_H */
