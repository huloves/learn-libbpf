#include <libelf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define OPTS_VALID(opts, type)		(!(opts))

struct bpf_linker {
	char *filename;
	int fd;
	Elf *elf;
	Elf64_Ehdr *elf_hdr;

	/* Output sections metadata */
	// struct dst_sec *secs;
	// int sec_cnt;

	// struct strset *strtab_strs; /* STRTAB unique strings */
	// size_t strtab_sec_idx; /* STRTAB section index */
	// size_t symtab_sec_idx; /* SYMTAB section index */

	// struct btf *btf;
	// struct btf_ext *btf_ext;

	/* global (including extern) ELF symbols */
	// int glob_sym_cnt;
	// struct glob_sym *glob_syms;
};

struct bpf_linker *bpf_linker__new(const char *filename, void *opts)
{
	struct bpf_linker *linker;
	int err;

	if (!OPTS_VALID(opts, bpf_linker_opts))
		return errno = EINVAL, NULL;
	
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("libelf initialization failed");
		return errno = EINVAL, NULL;
	}
}
