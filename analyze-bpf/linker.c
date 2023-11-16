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

#include "include/uapi/linux/bpf.h"

#define OPTS_VALID(opts, type)		(!(opts))

#define BTF_EXTERN_SEC ".extern"

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
static int linker_sanity_check_elf(struct src_obj *obj);
static int linker_sanity_check_elf_symtab(struct src_obj *obj, struct src_sec *sec);
static int linker_sanity_check_elf_relos(struct src_obj *obj, struct src_sec *sec);
static int linker_sanity_check_btf(struct src_obj *obj);
static int linker_sanity_check_btf_ext(struct src_obj *obj);
static int linker_fixup_btf(struct src_obj *obj);
static int linker_append_sec_data(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_elf_syms(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_elf_sym(struct bpf_linker *linker, struct src_obj *obj,
				 Elf64_Sym *sym, const char *sym_name, int src_sym_idx);

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
	err = err ?: linker_append_sec_data(linker, &obj);
	err = err ?: linker_append_elf_syms(linker, &obj);
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
				obj->btf_ext = btf_ext__new(data->d_buf, shdr->sh_size);
				err = libbpf_get_error(obj->btf_ext);
				if (err) {
					printf("failed to parse .BTF.ext from '%s': %d\n", filename, err);
					return err;
				}
				sec->skipped = true;
				continue;
			}

			/* data & code */
			break;
		case SHT_NOBITS:
			/* BSS */
			break;
		case SHT_REL:
			/* relocations */
			break;
		default:
			printf("unrecognized section #%zu (%s) in %s\n",
				sec_idx, sec_name, filename);
			err = -EINVAL;
			return err;
		}
	}

	err = err ?: linker_sanity_check_elf(obj);
	err = err ?: linker_sanity_check_btf(obj);
	err = err ?: linker_sanity_check_btf_ext(obj);
	err = err ?: linker_fixup_btf(obj);

	return err;
}

static int linker_sanity_check_elf(struct src_obj *obj)
{
	struct src_sec *sec;
	int i, err;

	if (!obj->symtab_sec_idx) {
		printf("ELF is missing SYMTAB section in %s\n", obj->filename);
		return -EINVAL;
	}
	if (!obj->shstrs_sec_idx) {
		printf("ELF is missing section headers STRTAB section in %s\n", obj->filename);
		return -EINVAL;
	}

	for (i = 1; i < obj->sec_cnt; i++) {
		sec = &obj->secs[i];

		if (sec->sec_name[0] == '\0') {
			printf("ELF section #%zu has empty name in %s\n", sec->sec_idx, obj->filename);
			return -EINVAL;
		}

		if (sec->shdr->sh_addralign && !is_pow_of_2(sec->shdr->sh_addralign))
			return -EINVAL;
		if (sec->shdr->sh_addralign != sec->data->d_align)
			return -EINVAL;

		if (sec->shdr->sh_size != sec->data->d_size)
			return -EINVAL;

		switch (sec->shdr->sh_type) {
		case SHT_SYMTAB:
			err = linker_sanity_check_elf_symtab(obj, sec);
			if (err)
				return err;
			break;
		case SHT_STRTAB:
			break;
		case SHT_PROGBITS:
			if (sec->shdr->sh_flags & SHF_EXECINSTR) {
				if (sec->shdr->sh_size % sizeof(struct bpf_insn) != 0)
					return -EINVAL;
			}
			break;
		case SHT_NOBITS:
			break;
		case SHT_REL:
			err = linker_sanity_check_elf_relos(obj, sec);
			if (err)
				return err;
			break;
		case SHT_LLVM_ADDRSIG:
			break;
		default:
		printf("ELF section #%zu (%s) has unrecognized type %zu in %s\n",
				sec->sec_idx, sec->sec_name, (size_t)sec->shdr->sh_type, obj->filename);
			return -EINVAL;
		}
	}

	return 0;
}

static int linker_sanity_check_elf_symtab(struct src_obj *obj, struct src_sec *sec)
{
	struct src_sec *link_sec;
	Elf64_Sym *sym;
	int i, n;

	if (sec->shdr->sh_entsize != sizeof(Elf64_Sym))
		return -EINVAL;
	if (sec->shdr->sh_size % sec->shdr->sh_entsize != 0)
		return -EINVAL;

	if (!sec->shdr->sh_link || sec->shdr->sh_link >= obj->sec_cnt) {
		printf("ELF SYMTAB section #%zu points to missing STRTAB section #%zu in %s\n",
			sec->sec_idx, (size_t)sec->shdr->sh_link, obj->filename);
		return -EINVAL;
	}
	link_sec = &obj->secs[sec->shdr->sh_link];
	if (link_sec->shdr->sh_type != SHT_STRTAB) {
		printf("ELF SYMTAB section #%zu points to invalid STRTAB section #%zu in %s\n",
			sec->sec_idx, (size_t)sec->shdr->sh_link, obj->filename);
		return -EINVAL;
	}

	n = sec->shdr->sh_size / sec->shdr->sh_entsize;
	sym = sec->data->d_buf;
	for (i = 0; i < n; i++, sym++) {
		int sym_type = ELF64_ST_TYPE(sym->st_info);
		int sym_bind = ELF64_ST_BIND(sym->st_info);
		int sym_vis = ELF64_ST_VISIBILITY(sym->st_other);

		if (i == 0) {
			if (sym->st_name != 0 || sym->st_info != 0
			    || sym->st_other != 0 || sym->st_shndx != 0
			    || sym->st_value != 0 || sym->st_size != 0) {
				printf("ELF sym #0 is invalid in %s\n", obj->filename);
				return -EINVAL;
			}
			continue;
		}
		if (sym_bind != STB_LOCAL && sym_bind != STB_GLOBAL && sym_bind != STB_WEAK) {
			printf("ELF sym #%d in section #%zu has unsupported symbol binding %d\n",
				i, sec->sec_idx, sym_bind);
			return -EINVAL;
		}
		if (sym_vis != STV_DEFAULT && sym_vis != STV_HIDDEN) {
			printf("ELF sym #%d in section #%zu has unsupported symbol visibility %d\n",
				i, sec->sec_idx, sym_vis);
			return -EINVAL;
		}
		if (sym->st_shndx == 0) {
			if (sym_type != STT_NOTYPE || sym_bind == STB_LOCAL
			    || sym->st_value != 0 || sym->st_size != 0) {
				printf("ELF sym #%d is invalid extern symbol in %s\n",
					i, obj->filename);

				return -EINVAL;
			}
			continue;
		}
		if (sym->st_shndx < SHN_LORESERVE && sym->st_shndx >= obj->sec_cnt) {
			printf("ELF sym #%d in section #%zu points to missing section #%zu in %s\n",
				i, sec->sec_idx, (size_t)sym->st_shndx, obj->filename);
			return -EINVAL;
		}
		if (sym_type == STT_SECTION) {
			if (sym->st_value != 0)
				return -EINVAL;
			continue;
		}
	}

	return 0;
}

static int linker_sanity_check_elf_relos(struct src_obj *obj, struct src_sec *sec)
{
	struct src_sec *link_sec, *sym_sec;
	Elf64_Rel *relo;
	int i, n;

	if (sec->shdr->sh_entsize != sizeof(Elf64_Rel))
		return -EINVAL;
	if (sec->shdr->sh_size % sec->shdr->sh_entsize != 0)
		return -EINVAL;

	/* SHT_REL's sh_link should point to SYMTAB */
	if (sec->shdr->sh_link != obj->symtab_sec_idx) {
		printf("ELF relo section #%zu points to invalid SYMTAB section #%zu in %s\n",
			sec->sec_idx, (size_t)sec->shdr->sh_link, obj->filename);
		return -EINVAL;
	}

	/* SHT_REL's sh_info points to relocated section */
	if (!sec->shdr->sh_info || sec->shdr->sh_info >= obj->sec_cnt) {
		printf("ELF relo section #%zu points to missing section #%zu in %s\n",
			sec->sec_idx, (size_t)sec->shdr->sh_info, obj->filename);
		return -EINVAL;
	}
	link_sec = &obj->secs[sec->shdr->sh_info];

	/* .rel<secname> -> <secname> pattern is followed */
	if (strncmp(sec->sec_name, ".rel", sizeof(".rel") - 1) != 0
	    || strcmp(sec->sec_name + sizeof(".rel") - 1, link_sec->sec_name) != 0) {
		printf("ELF relo section #%zu name has invalid name in %s\n",
			sec->sec_idx, obj->filename);
		return -EINVAL;
	}

	/* don't further validate relocations for ignored sections */
	if (link_sec->skipped)
		return 0;

	/* relocatable section is data or instructions */
	if (link_sec->shdr->sh_type != SHT_PROGBITS && link_sec->shdr->sh_type != SHT_NOBITS) {
		printf("ELF relo section #%zu points to invalid section #%zu in %s\n",
			sec->sec_idx, (size_t)sec->shdr->sh_info, obj->filename);
		return -EINVAL;
	}

	/* check sanity of each relocation */
	n = sec->shdr->sh_size / sec->shdr->sh_entsize;
	relo = sec->data->d_buf;
	sym_sec = &obj->secs[obj->symtab_sec_idx];
	for (i = 0; i < n; i++, relo++) {
		size_t sym_idx = ELF64_R_SYM(relo->r_info);
		size_t sym_type = ELF64_R_TYPE(relo->r_info);

		if (sym_type != R_BPF_64_64 && sym_type != R_BPF_64_32 &&
		    sym_type != R_BPF_64_ABS64 && sym_type != R_BPF_64_ABS32) {
			printf("ELF relo #%d in section #%zu has unexpected type %zu in %s\n",
				i, sec->sec_idx, sym_type, obj->filename);
			return -EINVAL;
		}

		if (!sym_idx || sym_idx * sizeof(Elf64_Sym) >= sym_sec->shdr->sh_size) {
			printf("ELF relo #%d in section #%zu points to invalid symbol #%zu in %s\n",
				i, sec->sec_idx, sym_idx, obj->filename);
			return -EINVAL;
		}

		if (link_sec->shdr->sh_flags & SHF_EXECINSTR) {
			if (relo->r_offset % sizeof(struct bpf_insn) != 0) {
				printf("ELF relo #%d in section #%zu points to missing symbol #%zu in %s\n",
					i, sec->sec_idx, sym_idx, obj->filename);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int check_btf_type_id(__u32 *type_id, void *ctx)
{
	struct btf *btf = ctx;

	if (*type_id >= btf__type_cnt(btf))
		return -EINVAL;

	return 0;
}

static int check_btf_str_off(__u32 *str_off, void *ctx)
{
	struct btf *btf = ctx;
	const char *s;

	s = btf__str_by_offset(btf, *str_off);

	if (!s)
		return -EINVAL;

	return 0;
}

static int linker_sanity_check_btf(struct src_obj *obj)
{
	struct btf_type *t;
	int i, n, err = 0;

	if (!obj->btf)
		return 0;

	n = btf__type_cnt(obj->btf);
	for (i = 1; i < n; i++) {
		t = btf_type_by_id(obj->btf, i);

		err = err ?: btf_type_visit_type_ids(t, check_btf_type_id, obj->btf);
		err = err ?: btf_type_visit_str_offs(t, check_btf_str_off, obj->btf);
		if (err)
			return err;
	}

	return 0;
}

static int linker_sanity_check_btf_ext(struct src_obj *obj)
{
	int err = 0;

	if (!obj->btf_ext)
		return 0;

	/* can't use .BTF.ext without .BTF */
	if (!obj->btf)
		return -EINVAL;

	err = err ?: btf_ext_visit_type_ids(obj->btf_ext, check_btf_type_id, obj->btf);
	err = err ?: btf_ext_visit_str_offs(obj->btf_ext, check_btf_str_off, obj->btf);
	if (err)
		return err;

	return 0;
}

static int init_sec(struct bpf_linker *linker, struct dst_sec *dst_sec, struct src_sec *src_sec)
{
	Elf_Scn *scn;
	Elf_Data *data;
	Elf64_Shdr *shdr;
	int name_off;

	dst_sec->sec_sz = 0;
	dst_sec->sec_idx = 0;
	dst_sec->ephemeral = src_sec->ephemeral;

	/* ephemeral sections are just thin section shells lacking most parts */
	if (src_sec->ephemeral)
		return 0;

	scn = elf_newscn(linker->elf);
	if (!scn)
		return -ENOMEM;
	data = elf_newdata(scn);
	if (!data)
		return -ENOMEM;
	shdr = elf64_getshdr(scn);
	if (!shdr)
		return -ENOMEM;

	dst_sec->scn = scn;
	dst_sec->shdr = shdr;
	dst_sec->data = data;
	dst_sec->sec_idx = elf_ndxscn(scn);

	name_off = strset__add_str(linker->strtab_strs, src_sec->sec_name);
	if (name_off < 0)
		return name_off;

	shdr->sh_name = name_off;
	shdr->sh_type = src_sec->shdr->sh_type;
	shdr->sh_flags = src_sec->shdr->sh_flags;
	shdr->sh_size = 0;
	/* sh_link and sh_info have different meaning for different types of
	 * sections, so we leave it up to the caller code to fill them in, if
	 * necessary
	 */
	shdr->sh_link = 0;
	shdr->sh_info = 0;
	shdr->sh_addralign = src_sec->shdr->sh_addralign;
	shdr->sh_entsize = src_sec->shdr->sh_entsize;

	data->d_type = src_sec->data->d_type;
	data->d_size = 0;
	data->d_buf = NULL;
	data->d_align = src_sec->data->d_align;
	data->d_off = 0;

	return 0;
}

static struct dst_sec *find_dst_sec_by_name(struct bpf_linker *linker, const char *sec_name)
{
	struct dst_sec *sec;
	int i;

	for (i = 1; i < linker->sec_cnt; i++) {
		sec = &linker->secs[i];

		if (strcmp(sec->sec_name, sec_name) == 0)
			return sec;
	}

	return NULL;
}

static bool secs_match(struct dst_sec *dst, struct src_sec *src)
{
	if (dst->ephemeral || src->ephemeral)
		return true;

	if (dst->shdr->sh_type != src->shdr->sh_type) {
		printf("sec %s types mismatch\n", dst->sec_name);
		return false;
	}
	if (dst->shdr->sh_flags != src->shdr->sh_flags) {
		printf("sec %s flags mismatch\n", dst->sec_name);
		return false;
	}
	if (dst->shdr->sh_entsize != src->shdr->sh_entsize) {
		printf("sec %s entsize mismatch\n", dst->sec_name);
		return false;
	}

	return true;
}

static bool sec_content_is_same(struct dst_sec *dst_sec, struct src_sec *src_sec)
{
	if (dst_sec->sec_sz != src_sec->shdr->sh_size)
		return false;
	if (memcmp(dst_sec->raw_data, src_sec->data->d_buf, dst_sec->sec_sz) != 0)
		return false;
	return true;
}

static int extend_sec(struct bpf_linker *linker, struct dst_sec *dst, struct src_sec *src)
{
	void *tmp;
	size_t dst_align, src_align;
	size_t dst_align_sz, dst_final_sz;
	int err;

	/* Ephemeral source section doesn't contribute anything to ELF
	 * section data.
	 */
	if (src->ephemeral)
		return 0;

	/* Some sections (like .maps) can contain both externs (and thus be
	 * ephemeral) and non-externs (map definitions). So it's possible that
	 * it has to be "upgraded" from ephemeral to non-ephemeral when the
	 * first non-ephemeral entity appears. In such case, we add ELF
	 * section, data, etc.
	 */
	if (dst->ephemeral) {
		err = init_sec(linker, dst, src);
		if (err)
			return err;
	}

	dst_align = dst->shdr->sh_addralign;
	src_align = src->shdr->sh_addralign;
	if (dst_align == 0)
		dst_align = 1;
	if (dst_align < src_align)
		dst_align = src_align;

	dst_align_sz = (dst->sec_sz + dst_align - 1) / dst_align * dst_align;

	/* no need to re-align final size */
	dst_final_sz = dst_align_sz + src->shdr->sh_size;

	if (src->shdr->sh_type != SHT_NOBITS) {
		tmp = realloc(dst->raw_data, dst_final_sz);
		/* If dst_align_sz == 0, realloc() behaves in a special way:
		 * 1. When dst->raw_data is NULL it returns:
		 *    "either NULL or a pointer suitable to be passed to free()" [1].
		 * 2. When dst->raw_data is not-NULL it frees dst->raw_data and returns NULL,
		 *    thus invalidating any "pointer suitable to be passed to free()" obtained
		 *    at step (1).
		 *
		 * The dst_align_sz > 0 check avoids error exit after (2), otherwise
		 * dst->raw_data would be freed again in bpf_linker__free().
		 *
		 * [1] man 3 realloc
		 */
		if (!tmp && dst_align_sz > 0)
			return -ENOMEM;
		dst->raw_data = tmp;

		/* pad dst section, if it's alignment forced size increase */
		memset(dst->raw_data + dst->sec_sz, 0, dst_align_sz - dst->sec_sz);
		/* now copy src data at a properly aligned offset */
		memcpy(dst->raw_data + dst_align_sz, src->data->d_buf, src->shdr->sh_size);
	}

	dst->sec_sz = dst_final_sz;
	dst->shdr->sh_size = dst_final_sz;
	dst->data->d_size = dst_final_sz;

	dst->shdr->sh_addralign = dst_align;
	dst->data->d_align = dst_align;

	src->dst_off = dst_align_sz;

	return 0;
}

static bool is_data_sec(struct src_sec *sec)
{
	if (!sec || sec->skipped)
		return false;
	/* ephemeral sections are data sections, e.g., .kconfig, .ksyms */
	if (sec->ephemeral)
		return true;
	return sec->shdr->sh_type == SHT_PROGBITS || sec->shdr->sh_type == SHT_NOBITS;
}

static bool is_relo_sec(struct src_sec *sec)
{
	if (!sec || sec->skipped || sec->ephemeral)
		return false;
	return sec->shdr->sh_type == SHT_REL;
}

static int linker_append_sec_data(struct bpf_linker *linker, struct src_obj *obj)
{
	int i, err;

	for (i = 1; i < obj->sec_cnt; i++) {
		struct src_sec *src_sec;
		struct dst_sec *dst_sec;

		src_sec = &obj->secs[i];
		if (!is_data_sec(src_sec))
			continue;

		dst_sec = find_dst_sec_by_name(linker, src_sec->sec_name);
		if (!dst_sec) {
			dst_sec = add_dst_sec(linker, src_sec->sec_name);
			if (!dst_sec)
				return -ENOMEM;
			err = init_sec(linker, dst_sec, src_sec);
			if (err) {
				printf("failed to init section '%s'\n", src_sec->sec_name);
				return err;
			}
		} else {
			if (!secs_match(dst_sec, src_sec)) {
				printf("ELF sections %s are incompatible\n", src_sec->sec_name);
				return -1;
			}

			/* "license" and "version" sections are deduped */
			if (strcmp(src_sec->sec_name, "license") == 0
			    || strcmp(src_sec->sec_name, "version") == 0) {
				if (!sec_content_is_same(dst_sec, src_sec)) {
					printf("non-identical contents of section '%s' are not supported\n", src_sec->sec_name);
					return -EINVAL;
				}
				src_sec->skipped = true;
				src_sec->dst_id = dst_sec->id;
				continue;
			}
		}

		/* record mapped section index */
		src_sec->dst_id = dst_sec->id;

		err = extend_sec(linker, dst_sec, src_sec);
		if (err)
			return err;
	}

	return 0;
}

static void sym_update_bind(Elf64_Sym *sym, int sym_bind)
{
	sym->st_info = ELF64_ST_INFO(sym_bind, ELF64_ST_TYPE(sym->st_info));
}

static void sym_update_type(Elf64_Sym *sym, int sym_type)
{
	sym->st_info = ELF64_ST_INFO(ELF64_ST_BIND(sym->st_info), sym_type);
}

static void sym_update_visibility(Elf64_Sym *sym, int sym_vis)
{
	/* libelf doesn't provide setters for ST_VISIBILITY,
	 * but it is stored in the lower 2 bits of st_other
	 */
	sym->st_other &= ~0x03;
	sym->st_other |= sym_vis;
}

static int linker_append_elf_syms(struct bpf_linker *linker, struct src_obj *obj)
{
	struct src_sec *symtab = &obj->secs[obj->symtab_sec_idx];
	Elf64_Sym *sym = symtab->data->d_buf;
	int i, n = symtab->shdr->sh_size / symtab->shdr->sh_entsize, err;
	int str_sec_idx = symtab->shdr->sh_link;
	const char *sym_name;

	obj->sym_map = calloc(n + 1, sizeof(*obj->sym_map));
	if (!obj->sym_map)
		return -ENOMEM;

	for (i = 0; i < n; i++, sym++) {
		/* We already validated all-zero symbol #0 and we already
		 * appended it preventively to the final SYMTAB, so skip it.
		 */
		if (i == 0)
			continue;

		sym_name = elf_strptr(obj->elf, str_sec_idx, sym->st_name);
		if (!sym_name) {
			printf("can't fetch symbol name for symbol #%d in '%s'\n", i, obj->filename);
			return -EINVAL;
		}

		err = linker_append_elf_sym(linker, obj, sym, sym_name, i);
		if (err)
			return err;
	}

	return 0;
}

static Elf64_Sym *get_sym_by_idx(struct bpf_linker *linker, size_t sym_idx)
{
	struct dst_sec *symtab = &linker->secs[linker->symtab_sec_idx];
	Elf64_Sym *syms = symtab->raw_data;

	return &syms[sym_idx];
}

static struct glob_sym *find_glob_sym(struct bpf_linker *linker, const char *sym_name)
{
	struct glob_sym *glob_sym;
	const char *name;
	int i;

	for (i = 0; i < linker->glob_sym_cnt; i++) {
		glob_sym = &linker->glob_syms[i];
		name = strset__data(linker->strtab_strs) + glob_sym->name_off;

		if (strcmp(name, sym_name) == 0)
			return glob_sym;
	}

	return NULL;
}

static struct glob_sym *add_glob_sym(struct bpf_linker *linker)
{
	struct glob_sym *syms, *sym;

	syms = libbpf_reallocarray(linker->glob_syms, linker->glob_sym_cnt + 1,
				   sizeof(*linker->glob_syms));
	if (!syms)
		return NULL;

	sym = &syms[linker->glob_sym_cnt];
	memset(sym, 0, sizeof(*sym));
	sym->var_idx = -1;

	linker->glob_syms = syms;
	linker->glob_sym_cnt++;

	return sym;
}

static bool glob_sym_btf_matches(const char *sym_name, bool exact,
				 const struct btf *btf1, __u32 id1,
				 const struct btf *btf2, __u32 id2)
{
	const struct btf_type *t1, *t2;
	bool is_static1, is_static2;
	const char *n1, *n2;
	int i, n;

recur:
	n1 = n2 = NULL;
	t1 = skip_mods_and_typedefs(btf1, id1, &id1);
	t2 = skip_mods_and_typedefs(btf2, id2, &id2);

	/* check if only one side is FWD, otherwise handle with common logic */
	if (!exact && btf_is_fwd(t1) != btf_is_fwd(t2)) {
		n1 = btf__str_by_offset(btf1, t1->name_off);
		n2 = btf__str_by_offset(btf2, t2->name_off);
		if (strcmp(n1, n2) != 0) {
			printf("global '%s': incompatible forward declaration names '%s' and '%s'\n",
				sym_name, n1, n2);
			return false;
		}
		/* validate if FWD kind matches concrete kind */
		if (btf_is_fwd(t1)) {
			if (btf_kflag(t1) && btf_is_union(t2))
				return true;
			if (!btf_kflag(t1) && btf_is_struct(t2))
				return true;
			printf("global '%s': incompatible %s forward declaration and concrete kind %s\n",
				sym_name, btf_kflag(t1) ? "union" : "struct", btf_kind_str(t2));
		} else {
			if (btf_kflag(t2) && btf_is_union(t1))
				return true;
			if (!btf_kflag(t2) && btf_is_struct(t1))
				return true;
			printf("global '%s': incompatible %s forward declaration and concrete kind %s\n",
				sym_name, btf_kflag(t2) ? "union" : "struct", btf_kind_str(t1));
		}
		return false;
	}

	if (btf_kind(t1) != btf_kind(t2)) {
		printf("global '%s': incompatible BTF kinds %s and %s\n",
			sym_name, btf_kind_str(t1), btf_kind_str(t2));
		return false;
	}

	switch (btf_kind(t1)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
	case BTF_KIND_FWD:
	case BTF_KIND_FUNC:
	case BTF_KIND_VAR:
		n1 = btf__str_by_offset(btf1, t1->name_off);
		n2 = btf__str_by_offset(btf2, t2->name_off);
		if (strcmp(n1, n2) != 0) {
			printf("global '%s': incompatible %s names '%s' and '%s'\n",
				sym_name, btf_kind_str(t1), n1, n2);
			return false;
		}
		break;
	default:
		break;
	}

	switch (btf_kind(t1)) {
	case BTF_KIND_UNKN: /* void */
	case BTF_KIND_FWD:
		return true;
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		/* ignore encoding for int and enum values for enum */
		if (t1->size != t2->size) {
			printf("global '%s': incompatible %s '%s' size %u and %u\n",
				sym_name, btf_kind_str(t1), n1, t1->size, t2->size);
			return false;
		}
		return true;
	case BTF_KIND_PTR:
		/* just validate overall shape of the referenced type, so no
		 * contents comparison for struct/union, and allowd fwd vs
		 * struct/union
		 */
		exact = false;
		id1 = t1->type;
		id2 = t2->type;
		goto recur;
	case BTF_KIND_ARRAY:
		/* ignore index type and array size */
		id1 = btf_array(t1)->type;
		id2 = btf_array(t2)->type;
		goto recur;
	case BTF_KIND_FUNC:
		/* extern and global linkages are compatible */
		is_static1 = btf_func_linkage(t1) == BTF_FUNC_STATIC;
		is_static2 = btf_func_linkage(t2) == BTF_FUNC_STATIC;
		if (is_static1 != is_static2) {
			printf("global '%s': incompatible func '%s' linkage\n", sym_name, n1);
			return false;
		}

		id1 = t1->type;
		id2 = t2->type;
		goto recur;
	case BTF_KIND_VAR:
		/* extern and global linkages are compatible */
		is_static1 = btf_var(t1)->linkage == BTF_VAR_STATIC;
		is_static2 = btf_var(t2)->linkage == BTF_VAR_STATIC;
		if (is_static1 != is_static2) {
			printf("global '%s': incompatible var '%s' linkage\n", sym_name, n1);
			return false;
		}

		id1 = t1->type;
		id2 = t2->type;
		goto recur;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m1, *m2;

		if (!exact)
			return true;

		if (btf_vlen(t1) != btf_vlen(t2)) {
			printf("global '%s': incompatible number of %s fields %u and %u\n",
				sym_name, btf_kind_str(t1), btf_vlen(t1), btf_vlen(t2));
			return false;
		}

		n = btf_vlen(t1);
		m1 = btf_members(t1);
		m2 = btf_members(t2);
		for (i = 0; i < n; i++, m1++, m2++) {
			n1 = btf__str_by_offset(btf1, m1->name_off);
			n2 = btf__str_by_offset(btf2, m2->name_off);
			if (strcmp(n1, n2) != 0) {
				printf("global '%s': incompatible field #%d names '%s' and '%s'\n",
					sym_name, i, n1, n2);
				return false;
			}
			if (m1->offset != m2->offset) {
				printf("global '%s': incompatible field #%d ('%s') offsets\n",
					sym_name, i, n1);
				return false;
			}
			if (!glob_sym_btf_matches(sym_name, exact, btf1, m1->type, btf2, m2->type))
				return false;
		}

		return true;
	}
	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *m1, *m2;

		if (btf_vlen(t1) != btf_vlen(t2)) {
			printf("global '%s': incompatible number of %s params %u and %u\n",
				sym_name, btf_kind_str(t1), btf_vlen(t1), btf_vlen(t2));
			return false;
		}

		n = btf_vlen(t1);
		m1 = btf_params(t1);
		m2 = btf_params(t2);
		for (i = 0; i < n; i++, m1++, m2++) {
			/* ignore func arg names */
			if (!glob_sym_btf_matches(sym_name, exact, btf1, m1->type, btf2, m2->type))
				return false;
		}

		/* now check return type as well */
		id1 = t1->type;
		id2 = t2->type;
		goto recur;
	}

	/* skip_mods_and_typedefs() make this impossible */
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	/* DATASECs are never compared with each other */
	case BTF_KIND_DATASEC:
	default:
		printf("global '%s': unsupported BTF kind %s\n",
			sym_name, btf_kind_str(t1));
		return false;
	}
}

static bool map_defs_match(const char *sym_name,
			   const struct btf *main_btf,
			   const struct btf_map_def *main_def,
			   const struct btf_map_def *main_inner_def,
			   const struct btf *extra_btf,
			   const struct btf_map_def *extra_def,
			   const struct btf_map_def *extra_inner_def)
{
	const char *reason;

	if (main_def->map_type != extra_def->map_type) {
		reason = "type";
		goto mismatch;
	}

	/* check key type/size match */
	if (main_def->key_size != extra_def->key_size) {
		reason = "key_size";
		goto mismatch;
	}
	if (!!main_def->key_type_id != !!extra_def->key_type_id) {
		reason = "key type";
		goto mismatch;
	}
	if ((main_def->parts & MAP_DEF_KEY_TYPE)
	     && !glob_sym_btf_matches(sym_name, true /*exact*/,
				      main_btf, main_def->key_type_id,
				      extra_btf, extra_def->key_type_id)) {
		reason = "key type";
		goto mismatch;
	}

	/* validate value type/size match */
	if (main_def->value_size != extra_def->value_size) {
		reason = "value_size";
		goto mismatch;
	}
	if (!!main_def->value_type_id != !!extra_def->value_type_id) {
		reason = "value type";
		goto mismatch;
	}
	if ((main_def->parts & MAP_DEF_VALUE_TYPE)
	     && !glob_sym_btf_matches(sym_name, true /*exact*/,
				      main_btf, main_def->value_type_id,
				      extra_btf, extra_def->value_type_id)) {
		reason = "key type";
		goto mismatch;
	}

	if (main_def->max_entries != extra_def->max_entries) {
		reason = "max_entries";
		goto mismatch;
	}
	if (main_def->map_flags != extra_def->map_flags) {
		reason = "map_flags";
		goto mismatch;
	}
	if (main_def->numa_node != extra_def->numa_node) {
		reason = "numa_node";
		goto mismatch;
	}
	if (main_def->pinning != extra_def->pinning) {
		reason = "pinning";
		goto mismatch;
	}

	if ((main_def->parts & MAP_DEF_INNER_MAP) != (extra_def->parts & MAP_DEF_INNER_MAP)) {
		reason = "inner map";
		goto mismatch;
	}

	if (main_def->parts & MAP_DEF_INNER_MAP) {
		char inner_map_name[128];

		snprintf(inner_map_name, sizeof(inner_map_name), "%s.inner", sym_name);

		return map_defs_match(inner_map_name,
				      main_btf, main_inner_def, NULL,
				      extra_btf, extra_inner_def, NULL);
	}

	return true;

mismatch:
	printf("global '%s': map %s mismatch\n", sym_name, reason);
	return false;
}

static bool glob_map_defs_match(const char *sym_name,
				struct bpf_linker *linker, struct glob_sym *glob_sym,
				struct src_obj *obj, Elf64_Sym *sym, int btf_id)
{
	struct btf_map_def dst_def = {}, dst_inner_def = {};
	struct btf_map_def src_def = {}, src_inner_def = {};
	const struct btf_type *t;
	int err;

	t = btf__type_by_id(obj->btf, btf_id);
	if (!btf_is_var(t)) {
		printf("global '%s': invalid map definition type [%d]\n", sym_name, btf_id);
		return false;
	}
	t = skip_mods_and_typedefs(obj->btf, t->type, NULL);

	err = parse_btf_map_def(sym_name, obj->btf, t, true /*strict*/, &src_def, &src_inner_def);
	if (err) {
		printf("global '%s': invalid map definition\n", sym_name);
		return false;
	}

	/* re-parse existing map definition */
	t = btf__type_by_id(linker->btf, glob_sym->btf_id);
	t = skip_mods_and_typedefs(linker->btf, t->type, NULL);
	err = parse_btf_map_def(sym_name, linker->btf, t, true /*strict*/, &dst_def, &dst_inner_def);
	if (err) {
		/* this should not happen, because we already validated it */
		printf("global '%s': invalid dst map definition\n", sym_name);
		return false;
	}

	/* Currently extern map definition has to be complete and match
	 * concrete map definition exactly. This restriction might be lifted
	 * in the future.
	 */
	return map_defs_match(sym_name, linker->btf, &dst_def, &dst_inner_def,
			      obj->btf, &src_def, &src_inner_def);
}

static bool glob_syms_match(const char *sym_name,
			    struct bpf_linker *linker, struct glob_sym *glob_sym,
			    struct src_obj *obj, Elf64_Sym *sym, size_t sym_idx, int btf_id)
{
	const struct btf_type *src_t;

	/* if we are dealing with externs, BTF types describing both global
	 * and extern VARs/FUNCs should be completely present in all files
	 */
	if (!glob_sym->btf_id || !btf_id) {
		printf("BTF info is missing for global symbol '%s'\n", sym_name);
		return false;
	}

	src_t = btf__type_by_id(obj->btf, btf_id);
	if (!btf_is_var(src_t) && !btf_is_func(src_t)) {
		printf("only extern variables and functions are supported, but got '%s' for '%s'\n",
			btf_kind_str(src_t), sym_name);
		return false;
	}

	/* deal with .maps definitions specially */
	if (glob_sym->sec_id && strcmp(linker->secs[glob_sym->sec_id].sec_name, MAPS_ELF_SEC) == 0)
		return glob_map_defs_match(sym_name, linker, glob_sym, obj, sym, btf_id);

	if (!glob_sym_btf_matches(sym_name, true /*exact*/,
				  linker->btf, glob_sym->btf_id, obj->btf, btf_id))
		return false;

	return true;
}

static struct src_sec *find_src_sec_by_name(struct src_obj *obj, const char *sec_name)
{
	struct src_sec *sec;
	int i;

	for (i = 1; i < obj->sec_cnt; i++) {
		sec = &obj->secs[i];

		if (strcmp(sec->sec_name, sec_name) == 0)
			return sec;
	}

	return NULL;
}

static int complete_extern_btf_info(struct btf *dst_btf, int dst_id,
				    struct btf *src_btf, int src_id)
{
	struct btf_type *dst_t = btf_type_by_id(dst_btf, dst_id);
	struct btf_type *src_t = btf_type_by_id(src_btf, src_id);
	struct btf_param *src_p, *dst_p;
	const char *s;
	int i, n, off;

	/* We already made sure that source and destination types (FUNC or
	 * VAR) match in terms of types and argument names.
	 */
	if (btf_is_var(dst_t)) {
		btf_var(dst_t)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
		return 0;
	}

	dst_t->info = btf_type_info(BTF_KIND_FUNC, BTF_FUNC_GLOBAL, 0);

	/* now onto FUNC_PROTO types */
	src_t = btf_type_by_id(src_btf, src_t->type);
	dst_t = btf_type_by_id(dst_btf, dst_t->type);

	/* Fill in all the argument names, which for extern FUNCs are missing.
	 * We'll end up with two copies of FUNCs/VARs for externs, but that
	 * will be taken care of by BTF dedup at the very end.
	 * It might be that BTF types for extern in one file has less/more BTF
	 * information (e.g., FWD instead of full STRUCT/UNION information),
	 * but that should be (in most cases, subject to BTF dedup rules)
	 * handled and resolved by BTF dedup algorithm as well, so we won't
	 * worry about it. Our only job is to make sure that argument names
	 * are populated on both sides, otherwise BTF dedup will pedantically
	 * consider them different.
	 */
	src_p = btf_params(src_t);
	dst_p = btf_params(dst_t);
	for (i = 0, n = btf_vlen(dst_t); i < n; i++, src_p++, dst_p++) {
		if (!src_p->name_off)
			continue;

		/* src_btf has more complete info, so add name to dst_btf */
		s = btf__str_by_offset(src_btf, src_p->name_off);
		off = btf__add_str(dst_btf, s);
		if (off < 0)
			return off;
		dst_p->name_off = off;
	}
	return 0;
}

static Elf64_Sym *find_sym_by_name(struct src_obj *obj, size_t sec_idx,
				   int sym_type, const char *sym_name)
{
	struct src_sec *symtab = &obj->secs[obj->symtab_sec_idx];
	Elf64_Sym *sym = symtab->data->d_buf;
	int i, n = symtab->shdr->sh_size / symtab->shdr->sh_entsize;
	int str_sec_idx = symtab->shdr->sh_link;
	const char *name;

	for (i = 0; i < n; i++, sym++) {
		if (sym->st_shndx != sec_idx)
			continue;
		if (ELF64_ST_TYPE(sym->st_info) != sym_type)
			continue;

		name = elf_strptr(obj->elf, str_sec_idx, sym->st_name);
		if (!name)
			return NULL;

		if (strcmp(sym_name, name) != 0)
			continue;

		return sym;
	}

	return NULL;
}

static int linker_fixup_btf(struct src_obj *obj)
{
	const char *sec_name;
	struct src_sec *sec;
	int i, j, n, m;

	if (!obj->btf)
		return 0;

	n = btf__type_cnt(obj->btf);
	for (i = 1; i < n; i++) {
		struct btf_var_secinfo *vi;
		struct btf_type *t;

		t = btf_type_by_id(obj->btf, i);
		if (btf_kind(t) != BTF_KIND_DATASEC)
			continue;

		sec_name = btf__str_by_offset(obj->btf, t->name_off);
		sec = find_src_sec_by_name(obj, sec_name);
		if (sec) {
			/* record actual section size, unless ephemeral */
			if (sec->shdr)
				t->size = sec->shdr->sh_size;
		} else {
			/* BTF can have some sections that are not represented
			 * in ELF, e.g., .kconfig, .ksyms, .extern, which are used
			 * for special extern variables.
			 *
			 * For all but one such special (ephemeral)
			 * sections, we pre-create "section shells" to be able
			 * to keep track of extra per-section metadata later
			 * (e.g., those BTF extern variables).
			 *
			 * .extern is even more special, though, because it
			 * contains extern variables that need to be resolved
			 * by static linker, not libbpf and kernel. When such
			 * externs are resolved, we are going to remove them
			 * from .extern BTF section and might end up not
			 * needing it at all. Each resolved extern should have
			 * matching non-extern VAR/FUNC in other sections.
			 *
			 * We do support leaving some of the externs
			 * unresolved, though, to support cases of building
			 * libraries, which will later be linked against final
			 * BPF applications. So if at finalization we still
			 * see unresolved externs, we'll create .extern
			 * section on our own.
			 */
			if (strcmp(sec_name, BTF_EXTERN_SEC) == 0)
				continue;

			sec = add_src_sec(obj, sec_name);
			if (!sec)
				return -ENOMEM;

			sec->ephemeral = true;
			sec->sec_idx = 0; /* will match UNDEF shndx in ELF */
		}

		/* remember ELF section and its BTF type ID match */
		sec->sec_type_id = i;

		/* fix up variable offsets */
		vi = btf_var_secinfos(t);
		for (j = 0, m = btf_vlen(t); j < m; j++, vi++) {
			const struct btf_type *vt = btf__type_by_id(obj->btf, vi->type);
			const char *var_name = btf__str_by_offset(obj->btf, vt->name_off);
			int var_linkage = btf_var(vt)->linkage;
			Elf64_Sym *sym;

			/* no need to patch up static or extern vars */
			if (var_linkage != BTF_VAR_GLOBAL_ALLOCATED)
				continue;

			sym = find_sym_by_name(obj, sec->sec_idx, STT_OBJECT, var_name);
			if (!sym) {
				printf("failed to find symbol for variable '%s' in section '%s'\n", var_name, sec_name);
				return -ENOENT;
			}

			vi->offset = sym->st_value;
		}
	}

	return 0;
}

static bool btf_is_non_static(const struct btf_type *t)
{
	return (btf_is_var(t) && btf_var(t)->linkage != BTF_VAR_STATIC)
	       || (btf_is_func(t) && btf_func_linkage(t) != BTF_FUNC_STATIC);
}

static int find_glob_sym_btf(struct src_obj *obj, Elf64_Sym *sym, const char *sym_name,
			     int *out_btf_sec_id, int *out_btf_id)
{
	int i, j, n, m, btf_id = 0;
	const struct btf_type *t;
	const struct btf_var_secinfo *vi;
	const char *name;

	if (!obj->btf) {
		printf("failed to find BTF info for object '%s'\n", obj->filename);
		return -EINVAL;
	}

	n = btf__type_cnt(obj->btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(obj->btf, i);

		/* some global and extern FUNCs and VARs might not be associated with any
		 * DATASEC, so try to detect them in the same pass
		 */
		if (btf_is_non_static(t)) {
			name = btf__str_by_offset(obj->btf, t->name_off);
			if (strcmp(name, sym_name) != 0)
				continue;

			/* remember and still try to find DATASEC */
			btf_id = i;
			continue;
		}

		if (!btf_is_datasec(t))
			continue;

		vi = btf_var_secinfos(t);
		for (j = 0, m = btf_vlen(t); j < m; j++, vi++) {
			t = btf__type_by_id(obj->btf, vi->type);
			name = btf__str_by_offset(obj->btf, t->name_off);

			if (strcmp(name, sym_name) != 0)
				continue;
			if (btf_is_var(t) && btf_var(t)->linkage == BTF_VAR_STATIC)
				continue;
			if (btf_is_func(t) && btf_func_linkage(t) == BTF_FUNC_STATIC)
				continue;

			if (btf_id && btf_id != vi->type) {
				printf("global/extern '%s' BTF is ambiguous: both types #%d and #%u match\n",
					sym_name, btf_id, vi->type);
				return -EINVAL;
			}

			*out_btf_sec_id = i;
			*out_btf_id = vi->type;

			return 0;
		}
	}

	/* free-floating extern or global FUNC */
	if (btf_id) {
		*out_btf_sec_id = 0;
		*out_btf_id = btf_id;
		return 0;
	}

	printf("failed to find BTF info for global/extern symbol '%s'\n", sym_name);
	return -ENOENT;
}

static int linker_append_elf_sym(struct bpf_linker *linker, struct src_obj *obj,
				 Elf64_Sym *sym, const char *sym_name, int src_sym_idx)
{
	struct src_sec *src_sec = NULL;
	struct dst_sec *dst_sec = NULL;
	struct glob_sym *glob_sym = NULL;
	int name_off, sym_type, sym_bind, sym_vis, err;
	int btf_sec_id = 0, btf_id = 0;
	size_t dst_sym_idx;
	Elf64_Sym *dst_sym;
	bool sym_is_extern;

	sym_type = ELF64_ST_TYPE(sym->st_info);
	sym_bind = ELF64_ST_BIND(sym->st_info);
	sym_vis = ELF64_ST_VISIBILITY(sym->st_other);
	sym_is_extern = sym->st_shndx == SHN_UNDEF;

	if (sym_is_extern) {
		if (!obj->btf) {
			printf("externs without BTF info are not supported\n");
			return -ENOTSUP;
		}
	} else if (sym->st_shndx < SHN_LORESERVE) {
		src_sec = &obj->secs[sym->st_shndx];
		if (src_sec->skipped)
			return 0;
		dst_sec = &linker->secs[src_sec->dst_id];

		/* allow only one STT_SECTION symbol per section */
		if (sym_type == STT_SECTION && dst_sec->sec_sym_idx) {
			obj->sym_map[src_sym_idx] = dst_sec->sec_sym_idx;
			return 0;
		}
	}

	if (sym_bind == STB_LOCAL)
		goto add_sym;

	/* find matching BTF info */
	err = find_glob_sym_btf(obj, sym, sym_name, &btf_sec_id, &btf_id);
	if (err)
		return err;

	if (sym_is_extern && btf_sec_id) {
		const char *sec_name = NULL;
		const struct btf_type *t;

		t = btf__type_by_id(obj->btf, btf_sec_id);
		sec_name = btf__str_by_offset(obj->btf, t->name_off);

		/* Clang puts unannotated extern vars into
		 * '.extern' BTF DATASEC. Treat them the same
		 * as unannotated extern funcs (which are
		 * currently not put into any DATASECs).
		 * Those don't have associated src_sec/dst_sec.
		 */
		if (strcmp(sec_name, BTF_EXTERN_SEC) != 0) {
			src_sec = find_src_sec_by_name(obj, sec_name);
			if (!src_sec) {
				printf("failed to find matching ELF sec '%s'\n", sec_name);
				return -ENOENT;
			}
			dst_sec = &linker->secs[src_sec->dst_id];
		}
	}

	glob_sym = find_glob_sym(linker, sym_name);
	if (glob_sym) {
		/* Preventively resolve to existing symbol. This is
		 * needed for further relocation symbol remapping in
		 * the next step of linking.
		 */
		obj->sym_map[src_sym_idx] = glob_sym->sym_idx;

		/* If both symbols are non-externs, at least one of
		 * them has to be STB_WEAK, otherwise they are in
		 * a conflict with each other.
		 */
		if (!sym_is_extern && !glob_sym->is_extern
		    && !glob_sym->is_weak && sym_bind != STB_WEAK) {
			printf("conflicting non-weak symbol #%d (%s) definition in '%s'\n",
				src_sym_idx, sym_name, obj->filename);
			return -EINVAL;
		}

		if (!glob_syms_match(sym_name, linker, glob_sym, obj, sym, src_sym_idx, btf_id))
			return -EINVAL;

		dst_sym = get_sym_by_idx(linker, glob_sym->sym_idx);

		/* If new symbol is strong, then force dst_sym to be strong as
		 * well; this way a mix of weak and non-weak extern
		 * definitions will end up being strong.
		 */
		if (sym_bind == STB_GLOBAL) {
			/* We still need to preserve type (NOTYPE or
			 * OBJECT/FUNC, depending on whether the symbol is
			 * extern or not)
			 */
			sym_update_bind(dst_sym, STB_GLOBAL);
			glob_sym->is_weak = false;
		}

		/* Non-default visibility is "contaminating", with stricter
		 * visibility overwriting more permissive ones, even if more
		 * permissive visibility comes from just an extern definition.
		 * Currently only STV_DEFAULT and STV_HIDDEN are allowed and
		 * ensured by ELF symbol sanity checks above.
		 */
		if (sym_vis > ELF64_ST_VISIBILITY(dst_sym->st_other))
			sym_update_visibility(dst_sym, sym_vis);

		/* If the new symbol is extern, then regardless if
		 * existing symbol is extern or resolved global, just
		 * keep the existing one untouched.
		 */
		if (sym_is_extern)
			return 0;

		/* If existing symbol is a strong resolved symbol, bail out,
		 * because we lost resolution battle have nothing to
		 * contribute. We already checked abover that there is no
		 * strong-strong conflict. We also already tightened binding
		 * and visibility, so nothing else to contribute at that point.
		 */
		if (!glob_sym->is_extern && sym_bind == STB_WEAK)
			return 0;

		/* At this point, new symbol is strong non-extern,
		 * so overwrite glob_sym with new symbol information.
		 * Preserve binding and visibility.
		 */
		sym_update_type(dst_sym, sym_type);
		dst_sym->st_shndx = dst_sec->sec_idx;
		dst_sym->st_value = src_sec->dst_off + sym->st_value;
		dst_sym->st_size = sym->st_size;

		/* see comment below about dst_sec->id vs dst_sec->sec_idx */
		glob_sym->sec_id = dst_sec->id;
		glob_sym->is_extern = false;

		if (complete_extern_btf_info(linker->btf, glob_sym->btf_id,
					     obj->btf, btf_id))
			return -EINVAL;

		/* request updating VAR's/FUNC's underlying BTF type when appending BTF type */
		glob_sym->underlying_btf_id = 0;

		obj->sym_map[src_sym_idx] = glob_sym->sym_idx;
		return 0;
	}

add_sym:
	name_off = strset__add_str(linker->strtab_strs, sym_name);
	if (name_off < 0)
		return name_off;

	dst_sym = add_new_sym(linker, &dst_sym_idx);
	if (!dst_sym)
		return -ENOMEM;

	dst_sym->st_name = name_off;
	dst_sym->st_info = sym->st_info;
	dst_sym->st_other = sym->st_other;
	dst_sym->st_shndx = dst_sec ? dst_sec->sec_idx : sym->st_shndx;
	dst_sym->st_value = (src_sec ? src_sec->dst_off : 0) + sym->st_value;
	dst_sym->st_size = sym->st_size;

	obj->sym_map[src_sym_idx] = dst_sym_idx;

	if (sym_type == STT_SECTION && dst_sym) {
		dst_sec->sec_sym_idx = dst_sym_idx;
		dst_sym->st_value = 0;
	}

	if (sym_bind != STB_LOCAL) {
		glob_sym = add_glob_sym(linker);
		if (!glob_sym)
			return -ENOMEM;

		glob_sym->sym_idx = dst_sym_idx;
		/* we use dst_sec->id (and not dst_sec->sec_idx), because
		 * ephemeral sections (.kconfig, .ksyms, etc) don't have
		 * sec_idx (as they don't have corresponding ELF section), but
		 * still have id. .extern doesn't have even ephemeral section
		 * associated with it, so dst_sec->id == dst_sec->sec_idx == 0.
		 */
		glob_sym->sec_id = dst_sec ? dst_sec->id : 0;
		glob_sym->name_off = name_off;
		/* we will fill btf_id in during BTF merging step */
		glob_sym->btf_id = 0;
		glob_sym->is_extern = sym_is_extern;
		glob_sym->is_weak = sym_bind == STB_WEAK;
	}

	return 0;
}
