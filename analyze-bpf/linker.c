#include <libelf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

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

struct dst_sec {
	char *sec_name;
	/* positional (not necessarily ELF) index in an array of sections */
	int id;

	bool ephemeral;

	/* ELF info */
	size_t sec_idx;
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	Elf_Data *data;

	/* final output section size */
	int sec_sz;
	/* final output contents of the section */
	void *raw_data;

	/* corresponding STT_SECTION symbol index in SYMTAB */
	int sec_sym_idx;

	/* section's DATASEC variable info, emitted on BTF finalization */
	bool has_btf;
	int sec_var_cnt;
	// struct btf_var_secinfo *sec_vars;

	// /* section's .BTF.ext data */
	// struct btf_ext_sec_data func_info;
	// struct btf_ext_sec_data line_info;
	// struct btf_ext_sec_data core_relo_info;
};

static int init_output_elf(struct bpf_linker *linker, const char *file);

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

	linker = calloc(1, sizeof(*linker));
	if (!linker)
		return errno = ENOMEM, NULL;
	
	linker->fd = -1;

	// err = init_output_elf(linker, filename);
}

static int init_output_elf(struct bpf_linker *linker, const char *file)
{
	int err, str_off;
	Elf64_Sym *init_sym;

	linker->filename = strdup(file);
	if (!linker->filename)
		return -ENOMEM;

	linker->fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (linker->fd < 0) {
		err = -errno;
		printf("failed to create '%s': %d\n", file, err);
		return err;
	}

	linker->elf = elf_begin(linker->fd, ELF_C_WRITE, NULL);
	if (!linker->elf) {
		printf("failed to create ELF object");
		return -EINVAL;
	}

	linker->elf_hdr = elf64_newehdr(linker->elf);
	if (!linker->elf_hdr) {
		printf("failed to create ELF header");
		return -EINVAL;
	}

	linker->elf_hdr->e_machine = EM_BPF;
	linker->elf_hdr->e_type = ET_REL;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	linker->elf_hdr->e_ident[EI_DATA] = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	linker->elf_hdr->e_ident[EI_DATA] = ELFDATA2MSB;
#else
#error "Unknown __BYTE_ORDER__"
#endif

	/* STRTAB */
	/* 使用空字符串初始化strset以符合ELF */
	// linker->strtab_strs = strset__new(INT_MAX, "", sizeof(""));
}
