#ifndef _BPF_GEN_INTERNAL_H
#define _BPF_GEN_INTERNAL_H

#include "bpf.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#include "include/linux/types.h"

struct ksym_relo_desc {
	const char *name;
	int kind;
	int insn_idx;
	bool is_weak;
	bool is_typeless;
	bool is_ld64;
};

struct ksym_desc {
	const char *name;
	int ref;
	int kind;
	union {
		/* used for kfunc */
		int off;
		/* used for typeless ksym */
		bool typeless;
	};
	int insn;
	bool is_ld64;
};

struct bpf_gen {
	struct gen_loader_opts *opts;
	void *data_start;
	void *data_cur;
	void *insn_start;
	void *insn_cur;
	ssize_t cleanup_label;
	__u32 nr_progs;
	__u32 nr_maps;
	int log_level;
	int error;
	struct ksym_relo_desc *relos;
	int relo_cnt;
	struct bpf_core_relo *core_relos;
	int core_relo_cnt;
	char attach_target[128];
	int attach_kind;
	struct ksym_desc *ksyms;
	__u32 nr_ksyms;
	int fd_array;
	int nr_fd_array;
};

void bpf_gen__free(struct bpf_gen *gen);

#endif /* _BPF_GEN_INTERNAL_H */
