#include <stdio.h>
#include <string.h>
#include <linux/err.h>
#include <errno.h>
#include <sys/resource.h>
#include "libbpf.h"
#include "btf.h"
#include "libbpf_internal.h"
#include "libbpf_legacy.h"
#include "libbpf_version.h"

#include "include/uapi/linux/bpf.h"
#include "include/uapi/linux/btf.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC		0xcafe4a11
#endif

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

#define __printf(a, b)	__attribute__((format(printf, a, b)))

static const char * const attach_type_name[] = {

};

static const char * const link_type_name[] = {

};

static const char * const map_type_name[] = {

};

static const char * const prog_type_name[] = {

};

static int __base_pr(enum libbpf_print_level level, const char *format,
		     va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

static libbpf_print_fn_t __libbpf_pr = __base_pr;

libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn)
{
	libbpf_print_fn_t old_print_fn;

	old_print_fn = __atomic_exchange_n(&__libbpf_pr, fn, __ATOMIC_RELAXED);

	return old_print_fn;
}

__printf(2, 3)
void libbpf_print(enum libbpf_print_level level, const char *format, ...)
{
	va_list args;
	int old_errno;
	libbpf_print_fn_t print_fn;

	print_fn = __atomic_load_n(&__libbpf_pr, __ATOMIC_RELAXED);
	if (!print_fn)
		return;

	old_errno = errno;

	va_start(args, format);
	__libbpf_pr(level, format, args);
	va_end(args);

	errno = old_errno;
}

static void pr_perm_msg(int err)
{
	struct rlimit limit;
	char buf[100];

	if (err != -EPERM || geteuid() != 0)
		return;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err)
		return;

	if (limit.rlim_cur == RLIM_INFINITY)
		return;

	if (limit.rlim_cur < 1024)
		snprintf(buf, sizeof(buf), "%zu bytes", (size_t)limit.rlim_cur);
	else if (limit.rlim_cur < 1024*1024)
		snprintf(buf, sizeof(buf), "%.1f KiB", (double)limit.rlim_cur / 1024);
	else
		snprintf(buf, sizeof(buf), "%.1f MiB", (double)limit.rlim_cur / (1024*1024));

	printf("permission error while running as root; try raising 'ulimit -l'? current value: %s\n",
		buf);
}

#define STRERR_BUFSIZE  128

/* Copied from tools/perf/util/util.h */
#ifndef zfree
# define zfree(ptr) ({ free(*ptr); *ptr = NULL; })
#endif

#ifndef zclose
# define zclose(fd) ({			\
	int ___err = 0;			\
	if ((fd) >= 0)			\
		___err = close((fd));	\
	fd = -1;			\
	___err; })
#endif

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int libbpf_set_strict_mode(enum libbpf_strict_mode mode)
{
	/* as of v1.0 libbpf_set_strict_mode() is a no-op */
	return 0;
}

__u32 libbpf_major_version(void)
{
	return LIBBPF_MAJOR_VERSION;
}

__u32 libbpf_minor_version(void)
{
	return LIBBPF_MINOR_VERSION;
}

const char *libbpf_version_string(void)
{
#define __S(X) #X
#define _S(X) __S(X)
	return  "v" _S(LIBBPF_MAJOR_VERSION) "." _S(LIBBPF_MINOR_VERSION);
#undef _S
#undef __S
}

/**
 * 重定位类型
 */
enum reloc_type {
	/* 64位加载指令 */
	RELO_LD64,
	/* 调用指令 */
	RELO_CALL,
	/* 数据 */
	RELO_DATA,
	/* 外部64位加载指令 */
	RELO_EXTERN_LD64,
	/* 外部调用指令 */
	RELO_EXTERN_CALL,
	/* 子程序地址 */
	RELO_SUBPROG_ADDR,
	/* 核心(内核?) */
	RELO_CORE,
};

/**
 * reloc_desc - 重定位描述符
 */
struct reloc_desc {
	/**
	 * 重定位类型
	 */
	enum reloc_type type;
	/**
	 * 指令索引，需要重定位的指定在程序的位置
	 */
	int insn_idx;
	/**
	 * 根据type的值选择不同的成员
	 */
	union {
		const struct bpf_core_relo *core_relo; /* used when type == RELO_CORE */
		struct {
			/**
			 * 映射索引，表示需要重定位的映射在程序中的位置
			 */
			int map_idx;
			/**
			 * 符号偏移量，表示需要重定位的符号相对于其定义的位置的偏移量
			 */
			int sym_off;
			/**
			 * 外部索引，表示需要重定位的外部符号在外部符号表中的位置
			 */
			int ext_idx;
		};
	};
};

/* stored as sec_def->cookie for all libbpf-supported SEC()s */
enum sec_def_flags {
	SEC_NONE = 0,
};

/**
 * bpf_sec_def - 描述一个BPF section
 * 描述BPF节属性和相关操作，可以帮助用户：
 * 1. 设置BPF程序的特性
 * 2. 准备加载
 * 3. 将BPF程序附加到指定位置
 */
struct bpf_sec_def {
	char *sec;
	/**
	 * BPF程序类型
	 */
	enum bpf_prog_type prog_type;
	/**
	 * BPF程序预期的附加类型
	 */
	enum bpf_attach_type expected_attach_type;
	long cookie;
	int handler_id;

	/**
	 * typedef int (*libbpf_prog_setup_fn_t)(struct bpf_program *prog, long cookie);
	 */
	libbpf_prog_setup_fn_t prog_setup_fn;
	/**
	 * typedef int (*libbpf_prog_prepare_load_fn_t)(struct bpf_program *prog,
	 *				     struct bpf_prog_load_opts *opts, long cookie);
	 */
	libbpf_prog_prepare_load_fn_t prog_prepare_load_fn;
	/**
	 * typedef int (*libbpf_prog_attach_fn_t)(const struct bpf_program *prog, long cookie,
	 *			       struct bpf_link **link);
	 */
	libbpf_prog_attach_fn_t prog_attach_fn;
};

/*
 * bpf_prog should be a better name but it has been used in
 * linux/filter.h.
 */
struct bpf_program {
	char *name;
	char *sec_name;
	size_t sec_idx;
	const struct bpf_sec_def *sec_def;
	/* this program's instruction offset (in number of instructions)
	 * within its containing ELF section
	 */
	size_t sec_insn_off;
	/* number of original instructions in ELF section belonging to this
	 * program, not taking into account subprogram instructions possible
	 * appended later during relocation
	 */
	size_t sec_insn_cnt;
	/* Offset (in number of instructions) of the start of instruction
	 * belonging to this BPF program  within its containing main BPF
	 * program. For the entry-point (main) BPF program, this is always
	 * zero. For a sub-program, this gets reset before each of main BPF
	 * programs are processed and relocated and is used to determined
	 * whether sub-program was already appended to the main program, and
	 * if yes, at which instruction offset.
	 */
	size_t sub_insn_off;

	/* instructions that belong to BPF program; insns[0] is located at
	 * sec_insn_off instruction within its ELF section in ELF file, so
	 * when mapping ELF file instruction index to the local instruction,
	 * one needs to subtract sec_insn_off; and vice versa.
	 */
	struct bpf_insn *insns;
	/* actual number of instruction in this BPF program's image; for
	 * entry-point BPF programs this includes the size of main program
	 * itself plus all the used sub-programs, appended at the end
	 */
	size_t insns_cnt;

	struct reloc_desc *reloc_desc;
	int nr_reloc;

	/* BPF verifier log settings */
	char *log_buf;
	size_t log_size;
	__u32 log_level;

	struct bpf_object *obj;

	int fd;
	bool autoload;
	bool autoattach;
	bool sym_global;
	bool mark_btf_static;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	int exception_cb_idx;

	int prog_ifindex;
	__u32 attach_btf_obj_fd;
	__u32 attach_btf_id;
	__u32 attach_prog_fd;

	void *func_info;
	__u32 func_info_rec_size;
	__u32 func_info_cnt;

	void *line_info;
	__u32 line_info_rec_size;
	__u32 line_info_cnt;
	__u32 prog_flags;
};

struct bpf_struct_ops {
	const char *tname;
	const struct btf_type *type;
	struct bpf_program **progs;
	__u32 *kern_func_off;
	/* e.g. struct tcp_congestion_ops in bpf_prog's btf format */
	void *data;
	/* e.g. struct bpf_struct_ops_tcp_congestion_ops in
	 *      btf_vmlinux's format.
	 * struct bpf_struct_ops_tcp_congestion_ops {
	 *	[... some other kernel fields ...]
	 *	struct tcp_congestion_ops data;
	 * }
	 * kern_vdata-size == sizeof(struct bpf_struct_ops_tcp_congestion_ops)
	 * bpf_map__init_kern_struct_ops() will populate the "kern_vdata"
	 * from "data".
	 */
	void *kern_vdata;
	__u32 type_id;
};

#define DATA_SEC ".data"
#define BSS_SEC ".bss"
#define RODATA_SEC ".rodata"
#define KCONFIG_SEC ".kconfig"
#define KSYMS_SEC ".ksyms"
#define STRUCT_OPS_SEC ".struct_ops"
#define STRUCT_OPS_LINK_SEC ".struct_ops.link"

enum libbpf_map_type {
	LIBBPF_MAP_UNSPEC,
	LIBBPF_MAP_DATA,
	LIBBPF_MAP_BSS,
	LIBBPF_MAP_RODATA,
	LIBBPF_MAP_KCONFIG,
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map {
	struct bpf_object *obj;
	char *name;
	/* real_name is defined for special internal maps (.rodata*,
	 * .data*, .bss, .kconfig) and preserves their original ELF section
	 * name. This is important to be able to find corresponding BTF
	 * DATASEC information.
	 */
	char *real_name;
	int fd;
	int sec_idx;
	size_t sec_offset;
	int map_ifindex;
	int inner_map_fd;
	struct bpf_map_def def;
	__u32 numa_node;
	__u32 btf_var_idx;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_value_type_id;
	enum libbpf_map_type libbpf_type;
	void *mmaped;
	struct bpf_struct_ops *st_ops;
	struct bpf_map *inner_map;
	void **init_slots;
	int init_slots_sz;
	char *pin_path;
	bool pinned;
	bool reused;
	bool autocreate;
	__u64 map_extra;
};

enum extern_type {
	EXT_UNKNOWN,
	EXT_KCFG,
	EXT_KSYM,
};

enum kcfg_type {
	KCFG_UNKNOWN,
	KCFG_CHAR,
	KCFG_BOOL,
	KCFG_INT,
	KCFG_TRISTATE,
	KCFG_CHAR_ARR,
};

struct extern_desc {
	enum extern_type type;
	int sym_idx;
	int btf_id;
	int sec_btf_id;
	const char *name;
	char *essent_name;
	bool is_set;
	bool is_weak;
	union {
		struct {
			enum kcfg_type type;
			int sz;
			int align;
			int data_off;
			bool is_signed;
		} kcfg;
		struct {
			unsigned long long addr;

			/* target btf_id of the corresponding kernel var. */
			int kernel_btf_obj_fd;
			int kernel_btf_id;

			/* local btf_id of the ksym extern's type. */
			__u32 type_id;
			/* BTF fd index to be patched in for insn->off, this is
			 * 0 for vmlinux BTF, index in obj->fd_array for module
			 * BTF
			 */
			__s16 btf_fd_idx;
		} ksym;
	};
};

struct module_btf {
	struct btf *btf;
	char *name;
	__u32 id;
	int fd;
	int fd_array_idx;
};

enum sec_type {
	SEC_UNUSED = 0,
	SEC_RELO,
	SEC_BSS,
	SEC_DATA,
	SEC_RODATA,
};

struct elf_sec_desc {
	enum sec_type sec_type;
	Elf64_Shdr *shdr;
	Elf_Data *data;
};

struct elf_state {
	int fd;
	const void *obj_buf;
	size_t obj_buf_sz;
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf_Data *symbols;
	Elf_Data *st_ops_data;
	Elf_Data *st_ops_link_data;
	size_t shstrndx; /* section index for section name strings */
	size_t strtabidx;
	struct elf_sec_desc *secs;
	size_t sec_cnt;
	int btf_maps_shndx;
	__u32 btf_maps_sec_btf_id;
	int text_shndx;
	int symbols_shndx;
	int st_ops_shndx;
	int st_ops_link_shndx;
};

struct usdt_manager;

struct bpf_object {
	char name[BPF_OBJ_NAME_LEN];
	char license[64];
	__u32 kern_version;

	struct bpf_program *programs;
	size_t nr_programs;
	struct bpf_map *maps;
	size_t nr_maps;
	size_t maps_cap;

	char *kconfig;
	struct extern_desc *externs;
	int nr_extern;
	int kconfig_map_idx;

	bool loaded;
	bool has_subcalls;
	bool has_rodata;

	struct bpf_gen *gen_loader;

	/* Information when doing ELF related work. Only valid if efile.elf is not NULL */
	struct elf_state efile;

	struct btf *btf;
	struct btf_ext *btf_ext;

	/* Parse and load BTF vmlinux if any of the programs in the object need
	 * it at load time.
	 */
	struct btf *btf_vmlinux;
	/* Path to the custom BTF to be used for BPF CO-RE relocations as an
	 * override for vmlinux BTF.
	 */
	char *btf_custom_path;
	/* vmlinux BTF override for CO-RE relocations */
	struct btf *btf_vmlinux_override;
	/* Lazily initialized kernel module BTFs */
	struct module_btf *btf_modules;
	bool btf_modules_loaded;
	size_t btf_module_cnt;
	size_t btf_module_cap;

	/* optional log settings passed to BPF_BTF_LOAD and BPF_PROG_LOAD commands */
	char *log_buf;
	size_t log_size;
	__u32 log_level;

	int *fd_array;
	size_t fd_array_cap;
	size_t fd_array_cnt;

	struct usdt_manager *usdt_man;

	char path[];
};

static bool bpf_map_type__is_map_in_map(enum bpf_map_type type)
{
	if (type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	    type == BPF_MAP_TYPE_HASH_OF_MAPS)
		return true;
	return false;
}

long libbpf_get_error(const void *ptr)
{
	if (!IS_ERR_OR_NULL(ptr))
		return 0;

	if (IS_ERR(ptr))
		errno = -PTR_ERR(ptr);

	/* If ptr == NULL, then errno should be already set by the failing
	 * API, because libbpf never returns NULL on success and it now always
	 * sets errno on error. So no extra errno handling for ptr == NULL
	 * case.
	 */
	return -errno;
}

const struct btf_type *
skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);

	if (res_id)
		*res_id = id;

	while (btf_is_mod(t) || btf_is_typedef(t)) {
		if (res_id)
			*res_id = t->type;
		t = btf__type_by_id(btf, t->type);
	}

	return t;
}

static const char *__btf_kind_str(__u16 kind)
{
	switch (kind) {
	case BTF_KIND_UNKN: return "void";
	case BTF_KIND_INT: return "int";
	case BTF_KIND_PTR: return "ptr";
	case BTF_KIND_ARRAY: return "array";
	case BTF_KIND_STRUCT: return "struct";
	case BTF_KIND_UNION: return "union";
	case BTF_KIND_ENUM: return "enum";
	case BTF_KIND_FWD: return "fwd";
	case BTF_KIND_TYPEDEF: return "typedef";
	case BTF_KIND_VOLATILE: return "volatile";
	case BTF_KIND_CONST: return "const";
	case BTF_KIND_RESTRICT: return "restrict";
	case BTF_KIND_FUNC: return "func";
	case BTF_KIND_FUNC_PROTO: return "func_proto";
	case BTF_KIND_VAR: return "var";
	case BTF_KIND_DATASEC: return "datasec";
	case BTF_KIND_FLOAT: return "float";
	case BTF_KIND_DECL_TAG: return "decl_tag";
	case BTF_KIND_TYPE_TAG: return "type_tag";
	case BTF_KIND_ENUM64: return "enum64";
	default: return "unknown";
	}
}

const char *btf_kind_str(const struct btf_type *t)
{
	return __btf_kind_str(btf_kind(t));
}

/*
 * Fetch integer attribute of BTF map definition. Such attributes are
 * represented using a pointer to an array, in which dimensionality of array
 * encodes specified integer value. E.g., int (*type)[BPF_MAP_TYPE_ARRAY];
 * encodes `type => BPF_MAP_TYPE_ARRAY` key/value pair completely using BTF
 * type definition, while using only sizeof(void *) space in ELF data section.
 */
static bool get_map_field_int(const char *map_name, const struct btf *btf,
			      const struct btf_member *m, __u32 *res)
{
	const struct btf_type *t = skip_mods_and_typedefs(btf, m->type, NULL);
	const char *name = btf__name_by_offset(btf, m->name_off);
	const struct btf_array *arr_info;
	const struct btf_type *arr_t;

	if (!btf_is_ptr(t)) {
		printf("map '%s': attr '%s': expected PTR, got %s.\n",
			map_name, name, btf_kind_str(t));
		return false;
	}

	arr_t = btf__type_by_id(btf, t->type);
	if (!arr_t) {
		printf("map '%s': attr '%s': type [%u] not found.\n",
			map_name, name, t->type);
		return false;
	}
	if (!btf_is_array(arr_t)) {
		printf("map '%s': attr '%s': expected ARRAY, got %s.\n",
			map_name, name, btf_kind_str(arr_t));
		return false;
	}
	arr_info = btf_array(arr_t);
	*res = arr_info->nelems;
	return true;
}

/* should match definition in bpf_helpers.h */
enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	/* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
	LIBBPF_PIN_BY_NAME,
};

int parse_btf_map_def(const char *map_name, struct btf *btf,
		      const struct btf_type *def_t, bool strict,
		      struct btf_map_def *map_def, struct btf_map_def *inner_def)
{
	const struct btf_type *t;
	const struct btf_member *m;
	bool is_inner = inner_def == NULL;
	int vlen, i;

	vlen = btf_vlen(def_t);
	m = btf_members(def_t);
	for (i = 0; i < vlen; i++, m++) {
		const char *name = btf__name_by_offset(btf, m->name_off);

		if (!name) {
			printf("map '%s': invalid field #%d.\n", map_name, i);
			return -EINVAL;
		}
		if (strcmp(name, "type") == 0) {
			if (!get_map_field_int(map_name, btf, m, &map_def->map_type))
				return -EINVAL;
			map_def->parts |= MAP_DEF_MAP_TYPE;
		} else if (strcmp(name, "max_entries") == 0) {
			if (!get_map_field_int(map_name, btf, m, &map_def->max_entries))
				return -EINVAL;
			map_def->parts |= MAP_DEF_MAX_ENTRIES;
		} else if (strcmp(name, "map_flags") == 0) {
			if (!get_map_field_int(map_name, btf, m, &map_def->map_flags))
				return -EINVAL;
			map_def->parts |= MAP_DEF_MAP_FLAGS;
		} else if (strcmp(name, "numa_node") == 0) {
			if (!get_map_field_int(map_name, btf, m, &map_def->numa_node))
				return -EINVAL;
			map_def->parts |= MAP_DEF_NUMA_NODE;
		} else if (strcmp(name, "key_size") == 0) {
			__u32 sz;

			if (!get_map_field_int(map_name, btf, m, &sz))
				return -EINVAL;
			if (map_def->key_size && map_def->key_size != sz) {
				printf("map '%s': conflicting key size %u != %u.\n",
					map_name, map_def->key_size, sz);
				return -EINVAL;
			}
			map_def->key_size = sz;
			map_def->parts |= MAP_DEF_KEY_SIZE;
		} else if (strcmp(name, "key") == 0) {
			__s64 sz;

			t = btf__type_by_id(btf, m->type);
			if (!t) {
				printf("map '%s': key type [%d] not found.\n",
					map_name, m->type);
				return -EINVAL;
			}
			if (!btf_is_ptr(t)) {
				printf("map '%s': key spec is not PTR: %s.\n",
					map_name, btf_kind_str(t));
				return -EINVAL;
			}
			sz = btf__resolve_size(btf, t->type);
			if (sz < 0) {
				printf("map '%s': can't determine key size for type [%u]: %zd.\n",
					map_name, t->type, (ssize_t)sz);
				return sz;
			}
			if (map_def->key_size && map_def->key_size != sz) {
				printf("map '%s': conflicting key size %u != %zd.\n",
					map_name, map_def->key_size, (ssize_t)sz);
				return -EINVAL;
			}
			map_def->key_size = sz;
			map_def->key_type_id = t->type;
			map_def->parts |= MAP_DEF_KEY_SIZE | MAP_DEF_KEY_TYPE;
		} else if (strcmp(name, "value_size") == 0) {
			__u32 sz;

			if (!get_map_field_int(map_name, btf, m, &sz))
				return -EINVAL;
			if (map_def->value_size && map_def->value_size != sz) {
				printf("map '%s': conflicting value size %u != %u.\n",
					map_name, map_def->value_size, sz);
				return -EINVAL;
			}
			map_def->value_size = sz;
			map_def->parts |= MAP_DEF_VALUE_SIZE;
		} else if (strcmp(name, "value") == 0) {
			__s64 sz;

			t = btf__type_by_id(btf, m->type);
			if (!t) {
				printf("map '%s': value type [%d] not found.\n",
					map_name, m->type);
				return -EINVAL;
			}
			if (!btf_is_ptr(t)) {
				printf("map '%s': value spec is not PTR: %s.\n",
					map_name, btf_kind_str(t));
				return -EINVAL;
			}
			sz = btf__resolve_size(btf, t->type);
			if (sz < 0) {
				printf("map '%s': can't determine value size for type [%u]: %zd.\n",
					map_name, t->type, (ssize_t)sz);
				return sz;
			}
			if (map_def->value_size && map_def->value_size != sz) {
				printf("map '%s': conflicting value size %u != %zd.\n",
					map_name, map_def->value_size, (ssize_t)sz);
				return -EINVAL;
			}
			map_def->value_size = sz;
			map_def->value_type_id = t->type;
			map_def->parts |= MAP_DEF_VALUE_SIZE | MAP_DEF_VALUE_TYPE;
		}
		else if (strcmp(name, "values") == 0) {
			bool is_map_in_map = bpf_map_type__is_map_in_map(map_def->map_type);
			bool is_prog_array = map_def->map_type == BPF_MAP_TYPE_PROG_ARRAY;
			const char *desc = is_map_in_map ? "map-in-map inner" : "prog-array value";
			char inner_map_name[128];
			int err;

			if (is_inner) {
				printf("map '%s': multi-level inner maps not supported.\n",
					map_name);
				return -ENOTSUP;
			}
			if (i != vlen - 1) {
				printf("map '%s': '%s' member should be last.\n",
					map_name, name);
				return -EINVAL;
			}
			if (!is_map_in_map && !is_prog_array) {
				printf("map '%s': should be map-in-map or prog-array.\n",
					map_name);
				return -ENOTSUP;
			}
			if (map_def->value_size && map_def->value_size != 4) {
				printf("map '%s': conflicting value size %u != 4.\n",
					map_name, map_def->value_size);
				return -EINVAL;
			}
			map_def->value_size = 4;
			t = btf__type_by_id(btf, m->type);
			if (!t) {
				printf("map '%s': %s type [%d] not found.\n",
					map_name, desc, m->type);
				return -EINVAL;
			}
			if (!btf_is_array(t) || btf_array(t)->nelems) {
				printf("map '%s': %s spec is not a zero-sized array.\n",
					map_name, desc);
				return -EINVAL;
			}
			t = skip_mods_and_typedefs(btf, btf_array(t)->type, NULL);
			if (!btf_is_ptr(t)) {
				printf("map '%s': %s def is of unexpected kind %s.\n",
					map_name, desc, btf_kind_str(t));
				return -EINVAL;
			}
			t = skip_mods_and_typedefs(btf, t->type, NULL);
			if (is_prog_array) {
				if (!btf_is_func_proto(t)) {
					printf("map '%s': prog-array value def is of unexpected kind %s.\n",
						map_name, btf_kind_str(t));
					return -EINVAL;
				}
				continue;
			}
			if (!btf_is_struct(t)) {
				printf("map '%s': map-in-map inner def is of unexpected kind %s.\n",
					map_name, btf_kind_str(t));
				return -EINVAL;
			}

			snprintf(inner_map_name, sizeof(inner_map_name), "%s.inner", map_name);
			err = parse_btf_map_def(inner_map_name, btf, t, strict, inner_def, NULL);
			if (err)
				return err;

			map_def->parts |= MAP_DEF_INNER_MAP;
		} else if (strcmp(name, "pinning") == 0) {
			__u32 val;

			if (is_inner) {
				printf("map '%s': inner def can't be pinned.\n", map_name);
				return -EINVAL;
			}
			if (!get_map_field_int(map_name, btf, m, &val))
				return -EINVAL;
			if (val != LIBBPF_PIN_NONE && val != LIBBPF_PIN_BY_NAME) {
				printf("map '%s': invalid pinning value %u.\n",
					map_name, val);
				return -EINVAL;
			}
			map_def->pinning = val;
			map_def->parts |= MAP_DEF_PINNING;
		} else if (strcmp(name, "map_extra") == 0) {
			__u32 map_extra;

			if (!get_map_field_int(map_name, btf, m, &map_extra))
				return -EINVAL;
			map_def->map_extra = map_extra;
			map_def->parts |= MAP_DEF_MAP_EXTRA;
		} else {
			if (strict) {
				printf("map '%s': unknown field '%s'.\n", map_name, name);
				return -ENOTSUP;
			}
			printf("map '%s': ignoring unknown field '%s'.\n", map_name, name);
		}
	}

	if (map_def->map_type == BPF_MAP_TYPE_UNSPEC) {
		printf("map '%s': map type isn't specified.\n", map_name);
		return -EINVAL;
	}

	return 0;
}
