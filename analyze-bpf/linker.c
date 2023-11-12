#include <libelf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include "libbpf.h"
#include "btf.h"
#include "strset.h"
#include "libbpf_internal.h"
#include "libbpf_legacy.h"

#define OPTS_VALID(opts, type)		(!(opts))

struct src_sec {
	const char *sec_name;
	/* positional (not necessarily ELF) index in an array of sections */
	int id;
	/* positional (not necessarily ELF) index of a matching section in a final object file */
	int dst_id;
	/* section data offset in a matching output section */
	int dst_off;
	/* whether section is omitted from the final ELF file */
	bool skipped;
	/* whether section is an ephemeral section, not mapped to an ELF section */
	bool ephemeral;

	/* ELF info */
	size_t sec_idx;
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	Elf_Data *data;

	/* corresponding BTF DATASEC type ID */
	int sec_type_id;
};

struct src_obj {
	const char *filename;
	int fd;
	Elf *elf;
	/* Section header strings section index */
	size_t shstrs_sec_idx;
	/* SYMTAB section index */
	size_t symtab_sec_idx;

	struct btf *btf;
	struct btf_ext *btf_ext;

	/* List of sections (including ephemeral). Slot zero is unused. */
	struct src_sec *secs;
	int sec_cnt;

	/* mapping of symbol indices from src to dst ELF */
	int *sym_map;
	/* mapping from the src BTF type IDs to dst ones */
	int *btf_type_map;
};

struct btf_ext_sec_data {
	size_t rec_cnt;
	__u32 rec_sz;
	void *recs;
};

struct glob_sym {
	/* ELF symbol index */
	int sym_idx;
	/* associated section id for .ksyms, .kconfig, etc, but not .extern */
	int sec_id;
	/* extern name offset in STRTAB */
	int name_off;
	/* optional associated BTF type ID */
	int btf_id;
	/* BTF type ID to which VAR/FUNC type is pointing to; used for
	 * rewriting types when extern VAR/FUNC is resolved to a concrete
	 * definition
	 */
	int underlying_btf_id;
	/* sec_var index in the corresponding dst_sec, if exists */
	int var_idx;

	/* extern or resolved/global symbol */
	bool is_extern;
	/* weak or strong symbol, never goes back from strong to weak */
	bool is_weak;
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
	struct btf_var_secinfo *sec_vars;

	/* section's .BTF.ext data */
	struct btf_ext_sec_data func_info;
	struct btf_ext_sec_data line_info;
	struct btf_ext_sec_data core_relo_info;
};

struct bpf_linker {
	char *filename;
	int fd;
	Elf *elf;
	Elf64_Ehdr *elf_hdr;

	/* Output sections metadata */
	struct dst_sec *secs;
	int sec_cnt;

	struct strset *strtab_strs; /* STRTAB unique strings */
	size_t strtab_sec_idx; /* STRTAB section index */
	size_t symtab_sec_idx; /* SYMTAB section index */

	struct btf *btf;
	struct btf_ext *btf_ext;

	/* global (including extern) ELF symbols */
	int glob_sym_cnt;
	struct glob_sym *glob_syms;
};

static int init_output_elf(struct bpf_linker *linker, const char *file);

static int linker_load_obj_file(struct bpf_linker *linker, const char *filename,
				const struct bpf_linker_file_opts *opts,
				struct src_obj *obj);

void bpf_linker__free(struct bpf_linker *linker)
{
	int i;

	if (!linker)
		return;

	free(linker->filename);

	if (linker->elf)
		elf_end(linker->elf);

	if (linker->fd >= 0)
		close(linker->fd);

	strset__free(linker->strtab_strs);

	// btf__free(linker->btf);
	// btf_ext__free(linker->btf_ext);

	for (i = 1; i < linker->sec_cnt; i++) {
		struct dst_sec *sec = &linker->secs[i];

		free(sec->sec_name);
		free(sec->raw_data);
		free(sec->sec_vars);

		free(sec->func_info.recs);
		free(sec->line_info.recs);
		free(sec->core_relo_info.recs);
	}
	free(linker->secs);

	free(linker->glob_syms);
	free(linker);
}

/**
 * bpf_linker__new - 创建一个linker对象
 * 创建一个新的linker对象
 * 创建一个新的elf目标文件与linker对应，elf目标文件名为filename
 * 初始化linker成员
 * 
 * @filename: 新建elf目标文件名
 * @opts: linker选项，暂时不支持选项，需传入NULL
 */
struct bpf_linker *bpf_linker__new(const char *filename, struct bpf_linker_opts *opts)
{
	struct bpf_linker *linker;
	int err;

	if (!OPTS_VALID(opts, bpf_linker_opts))
		return errno = EINVAL, NULL;
	
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("libelf initialization failed");
		return errno = EINVAL, NULL;
	}

	/**
	 * 申请一个linker对象的内存空间，calloc会将内存空间清零
	 */
	linker = calloc(1, sizeof(*linker));
	if (!linker)
		return errno = ENOMEM, NULL;
	
	linker->fd = -1;

	/**
	 * 初始化linker
	 */
	err = init_output_elf(linker, filename);
	if (err)
		goto err_out;

	return linker;

err_out:
	bpf_linker__free(linker);
	return errno = -err, NULL;
}

static struct dst_sec *add_dst_sec(struct bpf_linker *linker, const char *sec_name)
{
	struct dst_sec *secs = linker->secs, *sec;
	size_t new_cnt = linker->sec_cnt ? linker->sec_cnt + 1 : 2;

	secs = libbpf_reallocarray(secs, new_cnt, sizeof(*secs));
	if (!secs)
		return NULL;

	/* zero out newly allocated memory */
	memset(secs + linker->sec_cnt, 0, (new_cnt - linker->sec_cnt) * sizeof(*secs));

	linker->secs = secs;
	linker->sec_cnt = new_cnt;

	sec = &linker->secs[new_cnt - 1];
	sec->id = new_cnt - 1;
	sec->sec_name = strdup(sec_name);
	if (!sec->sec_name)
		return NULL;

	return sec;
}

static Elf64_Sym *add_new_sym(struct bpf_linker *linker, size_t *sym_idx)
{
	struct dst_sec *symtab = &linker->secs[linker->symtab_sec_idx];
	Elf64_Sym *syms, *sym;
	size_t sym_cnt = symtab->sec_sz / sizeof(*sym);

	syms = libbpf_reallocarray(symtab->raw_data, sym_cnt + 1, sizeof(*sym));
	if (!syms)
		return NULL;

	sym = &syms[sym_cnt];
	memset(sym, 0, sizeof(*sym));

	symtab->raw_data = syms;
	symtab->sec_sz += sizeof(*sym);
	symtab->shdr->sh_size += sizeof(*sym);
	symtab->data->d_size += sizeof(*sym);

	if (sym_idx)
		*sym_idx = sym_cnt;

	return sym;
}

static int init_output_elf(struct bpf_linker *linker, const char *file)
{
	int err, str_off;
	Elf64_Sym *init_sym;
	struct dst_sec *sec;

	/**
	 * 复制文件名(file)到linker->filename
	 */
	linker->filename = strdup(file);
	if (!linker->filename)
		return -ENOMEM;

	/**
	 * 创建新文件，文件描述符记录在linker->fd
	 */
	linker->fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (linker->fd < 0) {
		err = -errno;
		printf("failed to create '%s': %d\n", file, err);
		return err;
	}

	/**
	 * 调用elf_begin函数创建一个elf目标文件描述符
	 */
	linker->elf = elf_begin(linker->fd, ELF_C_WRITE, NULL);
	if (!linker->elf) {
		printf("failed to create ELF object");
		return -EINVAL;
	}

	/**
	 * 调用elf64_newehdr函数创建一个elf header
	 */
	linker->elf_hdr = elf64_newehdr(linker->elf);
	if (!linker->elf_hdr) {
		printf("failed to create ELF header");
		return -EINVAL;
	}

	/**
	 * 设置elf header信息，其中e_machine为EM_BPF
	 */
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
	/**
	 * 使用空字符串初始化strset以符合ELF，strset是一个字符串集合
	 */
	linker->strtab_strs = strset__new(INT_MAX, "", sizeof(""));
	if (libbpf_get_error(linker->strtab_strs))
		return libbpf_get_error(linker->strtab_strs);

	/**
	 * 在linker中添加一个名为".strtab"的dst_sec（未写入文件，未创建section对象）
	 */
	sec = add_dst_sec(linker, ".strtab");
	if (!sec)
		return -ENOMEM;

	/**
	 * 调用elf_newscn()创建一个新的section对象
	 */
	sec->scn = elf_newscn(linker->elf);
	if (!sec->scn) {
		printf("failed to create STRTAB section");
		return -EINVAL;
	}

	/**
	 * 在sec中记录新section对象的section header
	 */
	sec->shdr = elf64_getshdr(sec->scn);
	if (!sec->shdr)
		return -EINVAL;

	/**
	 * 为新创建的section对象创建elf data，并将section data地址记录在sec->data
	 */
	sec->data = elf_newdata(sec->scn);
	if (!sec->data) {
		printf("failed to create STRTAB data");
		return -EINVAL;
	}

	/**
	 * 在strset中添加section name字符串
	 */
	str_off = strset__add_str(linker->strtab_strs, sec->sec_name);
	if (str_off < 0)
		return str_off;

	/**
	 * sec中记录section索引
	 */
	sec->sec_idx = elf_ndxscn(sec->scn);
	/**
	 * elf header中记录string section的索引
	 */
	linker->elf_hdr->e_shstrndx = sec->sec_idx;
	/**
	 * linker中记录string section的索引
	 */
	linker->strtab_sec_idx = sec->sec_idx;

	/**
	 * 初始化section head
	 */
	sec->shdr->sh_name = str_off;
	sec->shdr->sh_type = SHT_STRTAB;
	sec->shdr->sh_flags = SHF_STRINGS;
	sec->shdr->sh_offset = 0;
	sec->shdr->sh_link = 0;
	sec->shdr->sh_info = 0;
	sec->shdr->sh_addralign = 1;
	sec->shdr->sh_size = sec->sec_sz = 0;
	sec->shdr->sh_entsize = 0;

	/* SYMTAB */
	sec = add_dst_sec(linker, ".symtab");
	if (!sec)
		return -ENOMEM;

	sec->scn = elf_newscn(linker->elf);
	if (!sec->scn) {
		printf("failed to create SYMTAB section");
		return -EINVAL;
	}

	sec->shdr = elf64_getshdr(sec->scn);
	if (!sec->shdr)
		return -EINVAL;

	sec->data = elf_newdata(sec->scn);
	if (!sec->data) {
		printf("failed to create SYMTAB data");
		return -EINVAL;
	}

	str_off = strset__add_str(linker->strtab_strs, sec->sec_name);
	if (str_off < 0)
		return str_off;

	sec->sec_idx = elf_ndxscn(sec->scn);
	linker->symtab_sec_idx = sec->sec_idx;

	sec->shdr->sh_name = str_off;
	sec->shdr->sh_type = SHT_SYMTAB;
	sec->shdr->sh_flags = 0;
	sec->shdr->sh_offset = 0;
	sec->shdr->sh_link = linker->strtab_sec_idx;
	/* sh_info should be one greater than the index of the last local
	 * symbol (i.e., binding is STB_LOCAL). But why and who cares?
	 */
	sec->shdr->sh_info = 0;
	sec->shdr->sh_addralign = 8;
	sec->shdr->sh_entsize = sizeof(Elf64_Sym);

	/* .BTF */
	/**
	 * 创建一个空btf对象
	 */
	linker->btf = btf__new_empty();
	err = libbpf_get_error(linker->btf);
	if (err)
		return err;

	/* add the special all-zero symbol */
	init_sym = add_new_sym(linker, NULL);
	if (!init_sym)
		return -EINVAL;

	init_sym->st_name = 0;
	init_sym->st_info = 0;
	init_sym->st_other = 0;
	init_sym->st_shndx = SHN_UNDEF;
	init_sym->st_value = 0;
	init_sym->st_size = 0;

	return 0;
}

int bpf_linker__add_file(struct bpf_linker *linker, const char *filename,
			 const struct bpf_linker_file_opts *opts)
{
	struct src_obj obj = {};
	int err = 0;

	if (!OPTS_VALID(opts, bpf_linker_file_opts))
		return libbpf_err(-EINVAL);

	if (!linker->elf)
		return libbpf_err(-EINVAL);

	/**
	 * 在linker中加载filename中的信息
	 */
	err = err ?: linker_load_obj_file(linker, filename, opts, &obj);
	// err = err ?: linker_append_sec_data(linker, &obj);
	// err = err ?: linker_append_elf_syms(linker, &obj);
	// err = err ?: linker_append_elf_relos(linker, &obj);
	// err = err ?: linker_append_btf(linker, &obj);
	// err = err ?: linker_append_btf_ext(linker, &obj);

	return err;
}

static bool is_dwarf_sec_name(const char *name)
{
	/* approximation, but the actual list is too long */
	return strncmp(name, ".debug_", sizeof(".debug_") - 1) == 0;
}

static bool is_ignored_sec(struct src_sec *sec)
{
	Elf64_Shdr *shdr = sec->shdr;
	const char *name = sec->sec_name;

	/* no special handling of .strtab */
	if (shdr->sh_type == SHT_STRTAB)
		return true;

	/* ignore .llvm_addrsig section as well */
	if (shdr->sh_type == SHT_LLVM_ADDRSIG)
		return true;

	/* no subprograms will lead to an empty .text section, ignore it */
	if (shdr->sh_type == SHT_PROGBITS && shdr->sh_size == 0 &&
	    strcmp(sec->sec_name, ".text") == 0)
		return true;

	/* DWARF sections */
	if (is_dwarf_sec_name(sec->sec_name))
		return true;

	if (strncmp(name, ".rel", sizeof(".rel") - 1) == 0) {
		name += sizeof(".rel") - 1;
		/* DWARF section relocations */
		if (is_dwarf_sec_name(name))
			return true;

		/* .BTF and .BTF.ext don't need relocations */
		if (strcmp(name, BTF_ELF_SEC) == 0 ||
		    strcmp(name, BTF_EXT_ELF_SEC) == 0)
			return true;
	}

	return false;
}

static struct src_sec *add_src_sec(struct src_obj *obj, const char *sec_name)
{
	struct src_sec *secs = obj->secs, *sec;
	size_t new_cnt = obj->sec_cnt ? obj->sec_cnt + 1 : 2;

	secs = libbpf_reallocarray(secs, new_cnt, sizeof(*secs));
	if (!secs)
		return NULL;

	/* zero out newly allocated memory */
	memset(secs + obj->sec_cnt, 0, (new_cnt - obj->sec_cnt) * sizeof(*secs));

	obj->secs = secs;
	obj->sec_cnt = new_cnt;

	sec = &obj->secs[new_cnt - 1];
	sec->id = new_cnt - 1;
	sec->sec_name = sec_name;

	return sec;
}

static int linker_load_obj_file(struct bpf_linker *linker, const char *filename,
				const struct bpf_linker_file_opts *opts,
				struct src_obj *obj)
{
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const int host_endianness = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	const int host_endianness = ELFDATA2MSB;
#else
#error "Unknown __BYTE_ORDER__"
#endif
	int err = 0;
	Elf_Scn *scn;
	Elf_Data *data;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	struct src_sec *sec;

	printf("linker: adding object file '%s'...\n", filename);

	obj->filename = filename;

	/**
	 * 打开filename目标文件
	 */
	obj->fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (obj->fd < 0) {
		err = -errno;
		printf("failed to open file '%s': %d\n", filename, err);
		return err;
	}
	/**
	 * 获得目标文件的elf信息
	 */
	obj->elf = elf_begin(obj->fd, ELF_C_READ_MMAP, NULL);
	if (!obj->elf) {
		err = -errno;
		printf("failed to parse ELF file '%s'", filename);
		return err;
	}

	/**
	 * 获得目标文件的elf header，并做检查（小端、可重定位文件、BPF、64位）
	 */
	/* Sanity check ELF file high-level properties */
	ehdr = elf64_getehdr(obj->elf);
	if (!ehdr) {
		err = -errno;
		printf("failed to get ELF header for %s", filename);
		return err;
	}
	if (ehdr->e_ident[EI_DATA] != host_endianness) {
		err = -EOPNOTSUPP;
		printf("unsupported byte order of ELF file %s", filename);
		return err;
	}
	if (ehdr->e_type != ET_REL
	    || ehdr->e_machine != EM_BPF
	    || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		err = -EOPNOTSUPP;
		printf("unsupported kind of ELF file %s", filename);
		return err;
	}

	/**
	 * 获得elf文件中section header的section header string section index
	 */
	if (elf_getshdrstrndx(obj->elf, &obj->shstrs_sec_idx)) {
		err = -errno;
		printf("failed to get SHSTRTAB section index for %s", filename);
		return err;
	}

	/**
	 * 遍历目标文件的每一个section
	 */
	scn = NULL;
	while ((scn = elf_nextscn(obj->elf, scn)) != NULL) {
		/**
		 * 获得section对应的section index
		 */
		size_t sec_idx = elf_ndxscn(scn);
		const char *sec_name;

		/**
		 * 获得section的section header
		 */
		shdr = elf64_getshdr(scn);
		if (!shdr) {
			err = -errno;
			printf("failed to get section #%zu header for %s",
				    sec_idx, filename);
			return err;
		}

		/**
		 * 获得section的section name
		 * elf + section header string section index + sh_name(string index)
		 * notes: sh_name是一个索引
		 */
		sec_name = elf_strptr(obj->elf, obj->shstrs_sec_idx, shdr->sh_name);
		if (!sec_name) {
			err = -errno;
			printf("failed to get section #%zu name for %s",
				    sec_idx, filename);
			return err;
		}

		/**
		 * 获得elf data的内存映像
		 */
		data = elf_getdata(scn, 0);
		if (!data) {
			err = -errno;
			printf("failed to get section #%zu (%s) data from %s",
				    sec_idx, sec_name, filename);
			return err;
		}

		/**
		 * 在sec_obj中添加一个src_sec，section名为sec_name
		 */
		sec = add_src_sec(obj, sec_name);
		if (!sec)
			return -ENOMEM;

		/**
		 * 记录section信息
		 */
		sec->scn = scn;
		sec->shdr = shdr;
		sec->data = data;
		sec->sec_idx = elf_ndxscn(scn);

		/**
		 * 判断是否是要忽略的section，若是，则遍历下一个section
		 * .strtab .llvm_addrsig
		 * SHT_PROGBITS + (sh_size == 0) + .text
		 * DWARF
		 * .rel + DWARF
		 * .rel + .BTF
		 * .rel + .BTF.ext
		 */
		if (is_ignored_sec(sec)) {
			sec->skipped = true;
			continue;
		}

		/**
		 * 根据不同的section类型进行不同的处理
		 */
		switch (shdr->sh_type) {
		case SHT_SYMTAB:
			if (obj->symtab_sec_idx) {
				err = -EOPNOTSUPP;
				printf("multiple SYMTAB sections found, not supported\n");
				return err;
			}
			/**
			 * 记录符号表section的索引
			 */
			obj->symtab_sec_idx = sec_idx;
			break;
		case SHT_STRTAB:
			/* we'll construct our own string table */
			break;
		case SHT_PROGBITS:
			if (strcmp(sec_name, BTF_ELF_SEC) == 0) {
				/**
				 * 创建一个btf对象，obj->btf中记录BTF信息
				 */
				obj->btf = btf__new(data->d_buf, shdr->sh_size);
				err = libbpf_get_error(obj->btf);
				if (err) {
					printf("failed to parse .BTF from %s: %d\n", filename, err);
					return err;
				}
				sec->skipped = true;
				continue;
			}
			if (strcmp(sec_name, BTF_EXT_ELF_SEC) == 0) {
				// obj->btf_ext = btf_ext__new(data->d_buf, shdr->sh_size);
				err = libbpf_get_error(obj->btf_ext);
				if (err) {
					printf("failed to parse .BTF.ext from '%s': %d\n", filename, err);
					return err;
				}
				sec->skipped = true;
				continue;
			}
			break;
		}
	}
}
