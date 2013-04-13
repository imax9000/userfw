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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <net/bpf.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "bpf.h"

static int
validate_bpf_code(userfw_match *match)
{
	unsigned char *data = match->args[0].string.data;
	size_t len = match->args[0].string.length, i;
	int err = 0;
	struct bpf_insn *prog = NULL;
#define INSN_LEN	8	/* (sizeof(uint16_t)+sizeof(uint8_t)*2+sizeof(uint32_t)) */

	match->priv = NULL;
	if (len % INSN_LEN != 0)
		return EINVAL;

	prog = match->priv = malloc((len/INSN_LEN)*sizeof(struct bpf_insn), M_USERFW, M_WAITOK);
	for(i = 0; i < len; i += INSN_LEN)
	{
		prog[i/INSN_LEN].code = (data[i] << 8) + data[i+1];
		prog[i/INSN_LEN].jt = data[i+2];
		prog[i/INSN_LEN].jf = data[i+3];
		prog[i/INSN_LEN].k = (data[i+4] << 24) + (data[i+5] << 16) + (data[i+6] << 8) + data[i+7];
	}

	err = (bpf_validate(prog, len/INSN_LEN) != 0) ? 0 : EINVAL;

	if (err != 0)
	{
		free(match->priv, M_USERFW);
		match->priv = NULL;
	}

	return err;
}

static void
free_bpf_prog(userfw_match *match)
{
	if (match->priv != NULL)
		free(match->priv, M_USERFW);
}

static int
match_bpf(struct mbuf **mb, userfw_chk_args *args, userfw_match *match, userfw_cache *cache, userfw_arg *marg)
{
	int ret = 0;

	VERIFY_OPCODE(match, USERFW_BPF_MOD, M_BPFMATCH, 0);
	if (match->priv == NULL)
	{
		printf("userfw_bpf: match->priv == NULL\n");
		return 0;
	}
	ret = bpf_filter(match->priv, (u_char *)(*mb), (*mb)->m_pkthdr.len, 0);

	return ret;
}

static userfw_match_descr bpf_matches[] = {
	{M_BPFMATCH,	1,	{T_HEXSTRING},	"bpf",	match_bpf, validate_bpf_code, free_bpf_prog}
};

static userfw_modinfo bpf_modinfo =
{
	.id = USERFW_BPF_MOD,
	.name = "bpf",
	.nactions = 0,
	.nmatches = sizeof(bpf_matches)/sizeof(bpf_matches[0]),
	.ncmds = 0,
	.actions = NULL,
	.matches = bpf_matches,
	.cmds = NULL
};

static int
bpf_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&bpf_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_BPF_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t bpf_mod =
{
	"userfw_bpf",
	bpf_modevent,
	0
};

MODULE_VERSION(userfw_bpf, 1);
DEPEND_ON_USERFW_CORE(userfw_bpf);

DECLARE_MODULE(userfw_bpf, bpf_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
