#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <gelf.h>
#include <ctype.h>
#include <zlib.h>
#include <linux/err.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "str_error.h"
#include "libbpf.h"
#include "btf.h"
#include "libbpf_internal.h"
#include "libbpf_legacy.h"
#include "libbpf_version.h"
#include "relo_core.h"
#include "bpf_gen_internal.h"

#include "include/linux/kernel.h"
#include "include/uapi/linux/bpf.h"
#include "include/uapi/linux/btf.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC		0xcafe4a11
#endif

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

#define __printf(a, b)	__attribute__((format(printf, a, b)))

static struct bpf_map *bpf_object__add_map(struct bpf_object *obj);

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

static const char *elf_sym_str(const struct bpf_object *obj, size_t off);
static const char *elf_sec_str(const struct bpf_object *obj, size_t off);
static Elf_Scn *elf_sec_by_idx(const struct bpf_object *obj, size_t idx);
static Elf_Scn *elf_sec_by_name(const struct bpf_object *obj, const char *name);
static Elf64_Shdr *elf_sec_hdr(const struct bpf_object *obj, Elf_Scn *scn);
static const char *elf_sec_name(const struct bpf_object *obj, Elf_Scn *scn);
static Elf_Data *elf_sec_data(const struct bpf_object *obj, Elf_Scn *scn);
static Elf64_Sym *elf_sym_by_idx(const struct bpf_object *obj, size_t idx);
static Elf64_Rel *elf_rel_by_idx(Elf_Data *data, size_t idx);

void bpf_program__unload(struct bpf_program *prog)
{
	if (!prog)
		return;

	zclose(prog->fd);

	zfree(&prog->func_info);
	zfree(&prog->line_info);
}

static void bpf_program__exit(struct bpf_program *prog)
{
	if (!prog)
		return;

	bpf_program__unload(prog);
	zfree(&prog->name);
	zfree(&prog->sec_name);
	zfree(&prog->insns);
	zfree(&prog->reloc_desc);

	prog->nr_reloc = 0;
	prog->insns_cnt = 0;
	prog->sec_idx = -1;
}

static bool is_call_insn(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL);
}

/**
 * bpf_object__init_prog - 初始化bpf_program
 * @obj: 指向需要进行初始化的bpf_program所属bpf_object
 * @prog: 需要进行初始化的bpf_program
 * @name: program名字
 * @sec_idx: program section索引
 * @sec_name: program所属section的name
 * @sec_off: program的偏移
 * @insn_data: program指令起始地址
 * @insn_data_sz: program指令大小，以字节为单位
 */
static int
bpf_object__init_prog(struct bpf_object *obj, struct bpf_program *prog,
		      const char *name, size_t sec_idx, const char *sec_name,
		      size_t sec_off, void *insn_data, size_t insn_data_sz)
{
	/**
	 * 进行必要的参数检:
	 * 1. 指令大小为0，返回-EINVAL
	 * 2. 指令大小不是bpf_insn整数倍，返回-EINVAL
	 * 3. program在seciton中的偏移不是bpf_insn的整数倍，返回-EINVAL
	 */
	if (insn_data_sz == 0 || insn_data_sz % BPF_INSN_SZ || sec_off % BPF_INSN_SZ) {
		printf("sec '%s': corrupted program '%s', offset %zu, size %zu\n",
			sec_name, name, sec_off, insn_data_sz);
		return -EINVAL;
	}

	memset(prog, 0, sizeof(*prog));
	prog->obj = obj;

	prog->sec_idx = sec_idx;
	prog->sec_insn_off = sec_off / BPF_INSN_SZ;
	prog->sec_insn_cnt = insn_data_sz / BPF_INSN_SZ;
	/* insns_cnt can later be increased by appending used subprograms */
	prog->insns_cnt = prog->sec_insn_cnt;

	/**
	 * 初始化BPF程序类型
	 */
	prog->type = BPF_PROG_TYPE_UNSPEC;
	prog->fd = -1;
	prog->exception_cb_idx = -1;

	/* libbpf's convention for SEC("?abc...") is that it's just like
	 * SEC("abc...") but the corresponding bpf_program starts out with
	 * autoload set to false.
	 */
	/**
	 * libbpf对SEC("?abc...")的约定是:
	 * 它与SEC("abc...")相同，但对应的bpf_program的autoload属性设置为false
	 */
	if (sec_name[0] == '?') {
		prog->autoload = false;
		/* from now on forget there was ? in section name */
		sec_name++;
	} else {
		prog->autoload = true;
	}

	prog->autoattach = true;

	/* inherit object's log_level */
	prog->log_level = obj->log_level;

	prog->sec_name = strdup(sec_name);
	if (!prog->sec_name)
		goto errout;

	prog->name = strdup(name);
	if (!prog->name)
		goto errout;

	prog->insns = malloc(insn_data_sz);
	if (!prog->insns)
		goto errout;
	memcpy(prog->insns, insn_data, insn_data_sz);

	return 0;
errout:
	printf("sec '%s': failed to allocate memory for prog '%s'\n", sec_name, name);
	bpf_program__exit(prog);
	return -ENOMEM;
}

/**
 * bpf_object__add_programs - bpf_object中添加代码section
 * @obj: 指向bpf_object
 * @sec_data: program section的数据部分
 * @sec_name: program section的名字
 * @sec_idx: program section的索引
 */
static int
bpf_object__add_programs(struct bpf_object *obj, Elf_Data *sec_data,
			 const char *sec_name, int sec_idx)
{
	Elf_Data *symbols = obj->efile.symbols;
	struct bpf_program *prog, *progs;
	void *data = sec_data->d_buf;
	size_t sec_sz = sec_data->d_size, sec_off, prog_sz, nr_syms;
	int nr_progs, err, i;
	const char *name;
	Elf64_Sym *sym;

	progs = obj->programs;
	nr_progs = obj->nr_programs;
	nr_syms = symbols->d_size / sizeof(Elf64_Sym);

	/**
	 * 遍历每一个符号
	 */
	for (i = 0; i < nr_syms; i++) {
		/**
		 * 通过符号索引找到符号表项
		 */
		sym = elf_sym_by_idx(obj, i);
		/**
		 * 符号若不属于该section，跳过
		 */
		if (sym->st_shndx != sec_idx)
			continue;
		/**
		 * 符号若不是code object，跳过
		 */
		if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;
		
		prog_sz = sym->st_size;
		sec_off = sym->st_value;

		/**
		 * 获取string name
		 */
		name = elf_sym_str(obj, sym->st_name);
		if (!name) {
			printf("sec '%s': failed to get symbol name for offset %zu\n",
				sec_name, sec_off);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (sec_off + prog_sz > sec_sz) {
			printf("sec '%s': program at offset %zu crosses section boundary\n",
				sec_name, sec_off);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (sec_idx != obj->efile.text_shndx && ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
			printf("sec '%s': program '%s' is static and not supported\n", sec_name, name);
			return -ENOTSUP;
		}

		pr_debug("sec '%s': found program '%s' at insn offset %zu (%zu bytes), code size %zu insns (%zu bytes)\n",
			 sec_name, name, sec_off / BPF_INSN_SZ, sec_off, prog_sz / BPF_INSN_SZ, prog_sz);
		
		/**
		 * 分配bpf_program结构体
		 */
		progs = libbpf_reallocarray(progs, nr_progs + 1, sizeof(*progs));
		if (!progs) {
			/*
			 * In this case the original obj->programs
			 * is still valid, so don't need special treat for
			 * bpf_close_object().
			 */
			printf("sec '%s': failed to alloc memory for new program '%s'\n",
				sec_name, name);
			return -ENOMEM;
		}
		obj->programs = progs;

		/**
		 * 指向新增的bpf_program
		 */
		prog = &progs[nr_progs];

		/**
		 * 初始化新增的bpf_program
		 */
		err = bpf_object__init_prog(obj, prog, name, sec_idx, sec_name,
					    sec_off, data + sec_off, prog_sz);
		if (err)
			return err;
		
		if (ELF64_ST_BIND(sym->st_info) != STB_LOCAL)
			prog->sym_global = true;
		
		/* if function is a global/weak symbol, but has restricted
		 * (STV_HIDDEN or STV_INTERNAL) visibility, mark its BTF FUNC
		 * as static to enable more permissive BPF verification mode
		 * with more outside context available to BPF verifier
		 */
		/**
		 * 如果函数是全局/弱符号，但具有受限的可见性（STV_HIDDEN或STV_INTERNAL），
		 * 将其BTF FUNC标记为static，以启用更宽松的BPF验证模式，
		 * 并使BPF验证器具备更多外部上下文可用性。
		 */
		if (prog->sym_global && (ELF64_ST_VISIBILITY(sym->st_other) == STV_HIDDEN
		    || ELF64_ST_VISIBILITY(sym->st_other) == STV_INTERNAL))
			prog->mark_btf_static = true;

		nr_progs++;
		obj->nr_programs = nr_progs;
	}

	return 0;
}

static const struct btf_member *
find_member_by_offset(const struct btf_type *t, __u32 bit_offset)
{
	struct btf_member *m;
	int i;

	for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
		if (btf_member_bit_offset(t, i) == bit_offset)
			return m;
	}

	return NULL;
}

static const struct btf_member *
find_member_by_name(const struct btf *btf, const struct btf_type *t,
		    const char *name)
{
	struct btf_member *m;
	int i;

	for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
		if (!strcmp(btf__name_by_offset(btf, m->name_off), name))
			return m;
	}

	return NULL;
}

#define STRUCT_OPS_VALUE_PREFIX "bpf_struct_ops_"
static int find_btf_by_prefix_kind(const struct btf *btf, const char *prefix,
				   const char *name, __u32 kind);

static int
find_struct_ops_kern_types(const struct btf *btf, const char *tname,
			   const struct btf_type **type, __u32 *type_id,
			   const struct btf_type **vtype, __u32 *vtype_id,
			   const struct btf_member **data_member)
{
	const struct btf_type *kern_type, *kern_vtype;
	const struct btf_member *kern_data_member;
	__s32 kern_vtype_id, kern_type_id;
	__u32 i;

	kern_type_id = btf__find_by_name_kind(btf, tname, BTF_KIND_STRUCT);
	if (kern_type_id < 0) {
		printf("struct_ops init_kern: struct %s is not found in kernel BTF\n",
			tname);
		return kern_type_id;
	}
	kern_type = btf__type_by_id(btf, kern_type_id);

	/* Find the corresponding "map_value" type that will be used
	 * in map_update(BPF_MAP_TYPE_STRUCT_OPS).  For example,
	 * find "struct bpf_struct_ops_tcp_congestion_ops" from the
	 * btf_vmlinux.
	 */
	kern_vtype_id = find_btf_by_prefix_kind(btf, STRUCT_OPS_VALUE_PREFIX,
						tname, BTF_KIND_STRUCT);
	if (kern_vtype_id < 0) {
		printf("struct_ops init_kern: struct %s%s is not found in kernel BTF\n",
			STRUCT_OPS_VALUE_PREFIX, tname);
		return kern_vtype_id;
	}
	kern_vtype = btf__type_by_id(btf, kern_vtype_id);

	/* Find "struct tcp_congestion_ops" from
	 * struct bpf_struct_ops_tcp_congestion_ops {
	 *	[ ... ]
	 *	struct tcp_congestion_ops data;
	 * }
	 */
	kern_data_member = btf_members(kern_vtype);
	for (i = 0; i < btf_vlen(kern_vtype); i++, kern_data_member++) {
		if (kern_data_member->type == kern_type_id)
			break;
	}
	if (i == btf_vlen(kern_vtype)) {
		printf("struct_ops init_kern: struct %s data is not found in struct %s%s\n",
			tname, STRUCT_OPS_VALUE_PREFIX, tname);
		return -EINVAL;
	}

	*type = kern_type;
	*type_id = kern_type_id;
	*vtype = kern_vtype;
	*vtype_id = kern_vtype_id;
	*data_member = kern_data_member;

	return 0;
}

static bool bpf_map__is_struct_ops(const struct bpf_map *map)
{
	return map->def.type == BPF_MAP_TYPE_STRUCT_OPS;
}

/* Init the map's fields that depend on kern_btf */
static int bpf_map__init_kern_struct_ops(struct bpf_map *map,
					 const struct btf *btf,
					 const struct btf *kern_btf)
{
	const struct btf_member *member, *kern_member, *kern_data_member;
	const struct btf_type *type, *kern_type, *kern_vtype;
	__u32 i, kern_type_id, kern_vtype_id, kern_data_off;
	struct bpf_struct_ops *st_ops;
	void *data, *kern_data;
	const char *tname;
	int err;

	st_ops = map->st_ops;
	type = st_ops->type;
	tname = st_ops->tname;
	err = find_struct_ops_kern_types(kern_btf, tname,
					 &kern_type, &kern_type_id,
					 &kern_vtype, &kern_vtype_id,
					 &kern_data_member);
	if (err)
		return err;

	printf("struct_ops init_kern %s: type_id:%u kern_type_id:%u kern_vtype_id:%u\n",
		 map->name, st_ops->type_id, kern_type_id, kern_vtype_id);

	map->def.value_size = kern_vtype->size;
	map->btf_vmlinux_value_type_id = kern_vtype_id;

	st_ops->kern_vdata = calloc(1, kern_vtype->size);
	if (!st_ops->kern_vdata)
		return -ENOMEM;

	data = st_ops->data;
	kern_data_off = kern_data_member->offset / 8;
	kern_data = st_ops->kern_vdata + kern_data_off;

	member = btf_members(type);
	for (i = 0; i < btf_vlen(type); i++, member++) {
		const struct btf_type *mtype, *kern_mtype;
		__u32 mtype_id, kern_mtype_id;
		void *mdata, *kern_mdata;
		__s64 msize, kern_msize;
		__u32 moff, kern_moff;
		__u32 kern_member_idx;
		const char *mname;

		mname = btf__name_by_offset(btf, member->name_off);
		kern_member = find_member_by_name(kern_btf, kern_type, mname);
		if (!kern_member) {
			printf("struct_ops init_kern %s: Cannot find member %s in kernel BTF\n",
				map->name, mname);
			return -ENOTSUP;
		}

		kern_member_idx = kern_member - btf_members(kern_type);
		if (btf_member_bitfield_size(type, i) ||
		    btf_member_bitfield_size(kern_type, kern_member_idx)) {
			printf("struct_ops init_kern %s: bitfield %s is not supported\n",
				map->name, mname);
			return -ENOTSUP;
		}

		moff = member->offset / 8;
		kern_moff = kern_member->offset / 8;

		mdata = data + moff;
		kern_mdata = kern_data + kern_moff;

		mtype = skip_mods_and_typedefs(btf, member->type, &mtype_id);
		kern_mtype = skip_mods_and_typedefs(kern_btf, kern_member->type,
						    &kern_mtype_id);
		if (BTF_INFO_KIND(mtype->info) !=
		    BTF_INFO_KIND(kern_mtype->info)) {
			printf("struct_ops init_kern %s: Unmatched member type %s %u != %u(kernel)\n",
				map->name, mname, BTF_INFO_KIND(mtype->info),
				BTF_INFO_KIND(kern_mtype->info));
			return -ENOTSUP;
		}

		if (btf_is_ptr(mtype)) {
			struct bpf_program *prog;

			prog = st_ops->progs[i];
			if (!prog)
				continue;

			kern_mtype = skip_mods_and_typedefs(kern_btf,
							    kern_mtype->type,
							    &kern_mtype_id);

			/* mtype->type must be a func_proto which was
			 * guaranteed in bpf_object__collect_st_ops_relos(),
			 * so only check kern_mtype for func_proto here.
			 */
			if (!btf_is_func_proto(kern_mtype)) {
				printf("struct_ops init_kern %s: kernel member %s is not a func ptr\n",
					map->name, mname);
				return -ENOTSUP;
			}

			prog->attach_btf_id = kern_type_id;
			prog->expected_attach_type = kern_member_idx;

			st_ops->kern_func_off[i] = kern_data_off + kern_moff;

			printf("struct_ops init_kern %s: func ptr %s is set to prog %s from data(+%u) to kern_data(+%u)\n",
				 map->name, mname, prog->name, moff,
				 kern_moff);

			continue;
		}

		msize = btf__resolve_size(btf, mtype_id);
		kern_msize = btf__resolve_size(kern_btf, kern_mtype_id);
		if (msize < 0 || kern_msize < 0 || msize != kern_msize) {
			printf("struct_ops init_kern %s: Error in size of member %s: %zd != %zd(kernel)\n",
				map->name, mname, (ssize_t)msize,
				(ssize_t)kern_msize);
			return -ENOTSUP;
		}

		printf("struct_ops init_kern %s: copy %s %u bytes from data(+%u) to kern_data(+%u)\n",
			 map->name, mname, (unsigned int)msize,
			 moff, kern_moff);
		memcpy(kern_mdata, mdata, msize);
	}

	return 0;
}

static int bpf_object__init_kern_struct_ops_maps(struct bpf_object *obj)
{
	struct bpf_map *map;
	size_t i;
	int err;

	for (i = 0; i < obj->nr_maps; i++) {
		map = &obj->maps[i];

		if (!bpf_map__is_struct_ops(map))
			continue;

		err = bpf_map__init_kern_struct_ops(map, obj->btf,
						    obj->btf_vmlinux);
		if (err)
			return err;
	}

	return 0;
}

static int init_struct_ops_maps(struct bpf_object *obj, const char *sec_name,
				int shndx, Elf_Data *data, __u32 map_flags)
{
	const struct btf_type *type, *datasec;
	const struct btf_var_secinfo *vsi;
	struct bpf_struct_ops *st_ops;
	const char *tname, *var_name;
	__s32 type_id, datasec_id;
	const struct btf *btf;
	struct bpf_map *map;
	__u32 i;

	if (shndx == -1)
		return 0;

	btf = obj->btf;
	datasec_id = btf__find_by_name_kind(btf, sec_name,
					    BTF_KIND_DATASEC);
	if (datasec_id < 0) {
		printf("struct_ops init: DATASEC %s not found\n",
			sec_name);
		return -EINVAL;
	}

	datasec = btf__type_by_id(btf, datasec_id);
	vsi = btf_var_secinfos(datasec);
	for (i = 0; i < btf_vlen(datasec); i++, vsi++) {
		type = btf__type_by_id(obj->btf, vsi->type);
		var_name = btf__name_by_offset(obj->btf, type->name_off);

		type_id = btf__resolve_type(obj->btf, vsi->type);
		if (type_id < 0) {
			printf("struct_ops init: Cannot resolve var type_id %u in DATASEC %s\n",
				vsi->type, sec_name);
			return -EINVAL;
		}

		type = btf__type_by_id(obj->btf, type_id);
		tname = btf__name_by_offset(obj->btf, type->name_off);
		if (!tname[0]) {
			printf("struct_ops init: anonymous type is not supported\n");
			return -ENOTSUP;
		}
		if (!btf_is_struct(type)) {
			printf("struct_ops init: %s is not a struct\n", tname);
			return -EINVAL;
		}

		map = bpf_object__add_map(obj);
		if (IS_ERR(map))
			return PTR_ERR(map);

		map->sec_idx = shndx;
		map->sec_offset = vsi->offset;
		map->name = strdup(var_name);
		if (!map->name)
			return -ENOMEM;

		map->def.type = BPF_MAP_TYPE_STRUCT_OPS;
		map->def.key_size = sizeof(int);
		map->def.value_size = type->size;
		map->def.max_entries = 1;
		map->def.map_flags = map_flags;

		map->st_ops = calloc(1, sizeof(*map->st_ops));
		if (!map->st_ops)
			return -ENOMEM;
		st_ops = map->st_ops;
		st_ops->data = malloc(type->size);
		st_ops->progs = calloc(btf_vlen(type), sizeof(*st_ops->progs));
		st_ops->kern_func_off = malloc(btf_vlen(type) *
					       sizeof(*st_ops->kern_func_off));
		if (!st_ops->data || !st_ops->progs || !st_ops->kern_func_off)
			return -ENOMEM;

		if (vsi->offset + type->size > data->d_size) {
			printf("struct_ops init: var %s is beyond the end of DATASEC %s\n",
				var_name, sec_name);
			return -EINVAL;
		}

		memcpy(st_ops->data,
		       data->d_buf + vsi->offset,
		       type->size);
		st_ops->tname = tname;
		st_ops->type = type;
		st_ops->type_id = type_id;

		printf("struct_ops init: struct %s(type_id=%u) %s found at offset %u\n",
			 tname, type_id, var_name, vsi->offset);
	}

	return 0;
}

static int bpf_object_init_struct_ops(struct bpf_object *obj)
{
	int err;

	err = init_struct_ops_maps(obj, STRUCT_OPS_SEC, obj->efile.st_ops_shndx,
				   obj->efile.st_ops_data, 0);
	err = err ?: init_struct_ops_maps(obj, STRUCT_OPS_LINK_SEC,
					  obj->efile.st_ops_link_shndx,
					  obj->efile.st_ops_link_data,
					  BPF_F_LINK);
	return err;
}

/**
 * bpf_object__new - 创建一个bpf_object
 * @path: bpf程序路径
 * @obj_buf: 保存有bpf程序的内存缓冲区
 * @obj_buf_sz: obj_buf的大小
 * @obj_name: obj_object的名字
 */
static struct bpf_object *bpf_object__new(const char *path,
					  const void *obj_buf,
					  size_t obj_buf_sz,
					  const char *obj_name)
{
	struct bpf_object *obj;
	char *end;

	/**
	 * 申请一个bpf_object对象，bpf_objdect对象尾部保存有该bpf程序的路径，该路径可以为空
	 */
	obj = calloc(1, sizeof(struct bpf_object) + strlen(path) + 1);
	if (!obj) {
		printf("alloc memory failed for %s\n", path);
		return ERR_PTR(-ENOMEM);
	}

	/**
	 * 拷贝路径名，bpf_object对象名
	 * 若bpf_object对象名为空，则根据path生成一个名字
	 */
	strcpy(obj->path, path);
	if (obj_name) {
		libbpf_strlcpy(obj->name, obj_name, sizeof(obj->name));
	} else {
		/* Using basename() GNU version which doesn't modify arg. */
		libbpf_strlcpy(obj->name, basename((void *)path), sizeof(obj->name));
		end = strchr(obj->name, '.');
		if (end)
			*end = 0;
	}

	/**
	 * 初始化elf文件相关信息
	 */
	obj->efile.fd = -1;
	/**
	 * Caller of this function should also call
	 * bpf_object__elf_finish() after data collection to return
	 * obj_buf to user. if not, we should duplicate the buffer to
	 * avoid user freeing them before elf finish.
	 */
	obj->efile.obj_buf = obj_buf;   // 记录elf文件在内存中的二进制内容
	obj->efile.obj_buf_sz = obj_buf_sz;   // 记录obj_buf的大小
	obj->efile.btf_maps_shndx = -1;   // 初始化btf maps所在的section
	obj->efile.st_ops_shndx = -1;
	obj->efile.st_ops_link_shndx = -1;
	obj->kconfig_map_idx = -1;

	obj->kern_version = get_kernel_version();   // 记录内核版本
	obj->loaded = false;   // 初始化加载状态

	return obj;
}

static void bpf_object__elf_finish(struct bpf_object *obj)
{
	if (!obj->efile.elf)
		return;

	elf_end(obj->efile.elf);
	obj->efile.elf = NULL;
	obj->efile.symbols = NULL;
	obj->efile.st_ops_data = NULL;
	obj->efile.st_ops_link_data = NULL;

	zfree(&obj->efile.secs);
	obj->efile.sec_cnt = 0;
	zclose(obj->efile.fd);
	obj->efile.obj_buf = NULL;
	obj->efile.obj_buf_sz = 0;
}

/**
 * bpf_object__elf_init - 初始化obj->efile结构中与ELF相关的内容并进行检查
 * 1. 根据obj_buf创建ELF对象
 * 2. obj->efile.elf中记录创建的ELF对象
 * 3. obj->efile.ehdr记录ELF header
 * 4. obj->efile.shstrndx记录section header string table的section索引
 * 5. 做一些必要的检查
 */
static int bpf_object__elf_init(struct bpf_object *obj)
{
	Elf64_Ehdr *ehdr;
	int err = 0;
	Elf *elf;
	
	if (obj->efile.elf) {
		printf("elf: init internal error\n");
		return -LIBBPF_ERRNO__LIBELF;
	}
	
	/**
	 * 创建一个ELF对象
	 */
	if (obj->efile.obj_buf_sz > 0) {
		/* obj_buf should have been validated by bpf_object__open_mem(). */
		elf = elf_memory((char *)obj->efile.obj_buf, obj->efile.obj_buf_sz);
	} else {
		obj->efile.fd = open(obj->path, O_RDONLY | O_CLOEXEC);
		if (obj->efile.fd < 0) {
			char errmsg[STRERR_BUFSIZE], *cp;

			err = -errno;
			cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
			printf("elf: failed to open %s: %s\n", obj->path, cp);
			return err;
		}

		elf = elf_begin(obj->efile.fd, ELF_C_READ_MMAP, NULL);
	}

	if (!elf) {
		printf("elf: failed to open %s as ELF file: %s\n", obj->path, elf_errmsg(-1));
		err = -LIBBPF_ERRNO__LIBELF;
		goto errout;
	}

	/**
	 * obj中记录创建的ELF对象
	 */
	obj->efile.elf = elf;

	if (elf_kind(elf) != ELF_K_ELF) {
		err = -LIBBPF_ERRNO__FORMAT;
		printf("elf: '%s' is not a proper ELF object\n", obj->path);
		goto errout;
	}
	
	if (gelf_getclass(elf) != ELFCLASS64) {
		err = -LIBBPF_ERRNO__FORMAT;
		printf("elf: '%s' is not a 64-bit ELF object\n", obj->path);
		goto errout;
	}

	/**
	 * 记录ELF header
	 */
	obj->efile.ehdr = ehdr = elf64_getehdr(elf);
	if (!obj->efile.ehdr) {
		printf("elf: failed to get ELF header from %s: %s\n", obj->path, elf_errmsg(-1));
		err = -LIBBPF_ERRNO__FORMAT;
		goto errout;
	}

	/**
	 * 获取并记录section header string table的section索引
	 */
	if (elf_getshdrstrndx(elf, &obj->efile.shstrndx)) {
		printf("elf: failed to get section names section index for %s: %s\n",
			obj->path, elf_errmsg(-1));
		err = -LIBBPF_ERRNO__FORMAT;
		goto errout;
	}

	/* ELF is corrupted/truncated, avoid calling elf_strptr. */
	/**
	 * 检查section header string table是否为空，为空返回错误
	 */
	if (!elf_rawdata(elf_getscn(elf, obj->efile.shstrndx), NULL)) {
		printf("elf: failed to get section names strings from %s: %s\n",
			obj->path, elf_errmsg(-1));
		err = -LIBBPF_ERRNO__FORMAT;
		goto errout;
	}

	/* Old LLVM set e_machine to EM_NONE */
	/**
	 * 检查ELF文件类型是否为可重定位文件，并且e_machine是否为EM_BPF
	 */
	if (ehdr->e_type != ET_REL || (ehdr->e_machine && ehdr->e_machine != EM_BPF)) {
		printf("elf: %s is not a valid eBPF object file\n", obj->path);
		err = -LIBBPF_ERRNO__FORMAT;
		goto errout;
	}

	return 0;
errout:
	bpf_object__elf_finish(obj);
	return err;
}

/**
 * bpf_object__check_endianness - 检查字节顺序
 * 检查通过返回0
 * 检查不通过返回-LIBBPF_ERRNO__ENDIAN
 */
static int bpf_object__check_endianness(struct bpf_object *obj)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (obj->efile.ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		return 0;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	if (obj->efile.ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		return 0;
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
	printf("elf: endianness mismatch in %s.\n", obj->path);
	return -LIBBPF_ERRNO__ENDIAN;
}

static int
bpf_object__init_license(struct bpf_object *obj, void *data, size_t size)
{
	if (!data) {
		printf("invalid license section in %s\n", obj->path);
		return -LIBBPF_ERRNO__FORMAT;
	}
	/* libbpf_strlcpy() only copies first N - 1 bytes, so size + 1 won't
	 * go over allowed ELF data section buffer
	 */
	libbpf_strlcpy(obj->license, data, min(size + 1, sizeof(obj->license)));
	pr_debug("license of %s is %s\n", obj->path, obj->license);
	return 0;
}

static int
bpf_object__init_kversion(struct bpf_object *obj, void *data, size_t size)
{
	__u32 kver;

	if (!data || size != sizeof(kver)) {
		printf("invalid kver section in %s\n", obj->path);
		return -LIBBPF_ERRNO__FORMAT;
	}
	memcpy(&kver, data, sizeof(kver));
	obj->kern_version = kver;
	printf("kernel version of %s is %x\n", obj->path, obj->kern_version);
	return 0;
}

static bool bpf_map_type__is_map_in_map(enum bpf_map_type type)
{
	if (type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	    type == BPF_MAP_TYPE_HASH_OF_MAPS)
		return true;
	return false;
}

static int find_elf_sec_sz(const struct bpf_object *obj, const char *name, __u32 *size)
{
	Elf_Data *data;
	Elf_Scn *scn;

	if (!name)
		return -EINVAL;

	scn = elf_sec_by_name(obj, name);
	data = elf_sec_data(obj, scn);
	if (data) {
		*size = data->d_size;
		return 0; /* found it */
	}

	return -ENOENT;
}

static Elf64_Sym *find_elf_var_sym(const struct bpf_object *obj, const char *name)
{
	Elf_Data *symbols = obj->efile.symbols;
	const char *sname;
	size_t si;

	for (si = 0; si < symbols->d_size / sizeof(Elf64_Sym); si++) {
		Elf64_Sym *sym = elf_sym_by_idx(obj, si);

		if (ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
			continue;

		if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL &&
		    ELF64_ST_BIND(sym->st_info) != STB_WEAK)
			continue;

		sname = elf_sym_str(obj, sym->st_name);
		if (!sname) {
			printf("failed to get sym name string for var %s\n", name);
			return ERR_PTR(-EIO);
		}
		if (strcmp(name, sname) == 0)
			return sym;
	}

	return ERR_PTR(-ENOENT);
}

static struct bpf_map *bpf_object__add_map(struct bpf_object *obj)
{
	struct bpf_map *map;
	int err;

	err = libbpf_ensure_mem((void **)&obj->maps, &obj->maps_cap,
				sizeof(*obj->maps), obj->nr_maps + 1);
	if (err)
		return ERR_PTR(err);

	map = &obj->maps[obj->nr_maps++];
	map->obj = obj;
	map->fd = -1;
	map->inner_map_fd = -1;
	map->autocreate = true;

	return map;
}

static size_t bpf_map_mmap_sz(unsigned int value_sz, unsigned int max_entries)
{
	const long page_sz = sysconf(_SC_PAGE_SIZE);
	size_t map_sz;

	map_sz = (size_t)roundup(value_sz, 8) * max_entries;
	map_sz = roundup(map_sz, page_sz);
	return map_sz;
}

static int bpf_map_mmap_resize(struct bpf_map *map, size_t old_sz, size_t new_sz)
{
	void *mmaped;

	if (!map->mmaped)
		return -EINVAL;

	if (old_sz == new_sz)
		return 0;

	mmaped = mmap(NULL, new_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mmaped == MAP_FAILED)
		return -errno;

	memcpy(mmaped, map->mmaped, min(old_sz, new_sz));
	munmap(map->mmaped, old_sz);
	map->mmaped = mmaped;
	return 0;
}

static char *internal_map_name(struct bpf_object *obj, const char *real_name)
{
	char map_name[BPF_OBJ_NAME_LEN], *p;
	int pfx_len, sfx_len = max((size_t)7, strlen(real_name));

	/* This is one of the more confusing parts of libbpf for various
	 * reasons, some of which are historical. The original idea for naming
	 * internal names was to include as much of BPF object name prefix as
	 * possible, so that it can be distinguished from similar internal
	 * maps of a different BPF object.
	 * As an example, let's say we have bpf_object named 'my_object_name'
	 * and internal map corresponding to '.rodata' ELF section. The final
	 * map name advertised to user and to the kernel will be
	 * 'my_objec.rodata', taking first 8 characters of object name and
	 * entire 7 characters of '.rodata'.
	 * Somewhat confusingly, if internal map ELF section name is shorter
	 * than 7 characters, e.g., '.bss', we still reserve 7 characters
	 * for the suffix, even though we only have 4 actual characters, and
	 * resulting map will be called 'my_objec.bss', not even using all 15
	 * characters allowed by the kernel. Oh well, at least the truncated
	 * object name is somewhat consistent in this case. But if the map
	 * name is '.kconfig', we'll still have entirety of '.kconfig' added
	 * (8 chars) and thus will be left with only first 7 characters of the
	 * object name ('my_obje'). Happy guessing, user, that the final map
	 * name will be "my_obje.kconfig".
	 * Now, with libbpf starting to support arbitrarily named .rodata.*
	 * and .data.* data sections, it's possible that ELF section name is
	 * longer than allowed 15 chars, so we now need to be careful to take
	 * only up to 15 first characters of ELF name, taking no BPF object
	 * name characters at all. So '.rodata.abracadabra' will result in
	 * '.rodata.abracad' kernel and user-visible name.
	 * We need to keep this convoluted logic intact for .data, .bss and
	 * .rodata maps, but for new custom .data.custom and .rodata.custom
	 * maps we use their ELF names as is, not prepending bpf_object name
	 * in front. We still need to truncate them to 15 characters for the
	 * kernel. Full name can be recovered for such maps by using DATASEC
	 * BTF type associated with such map's value type, though.
	 */
	if (sfx_len >= BPF_OBJ_NAME_LEN)
		sfx_len = BPF_OBJ_NAME_LEN - 1;

	/* if there are two or more dots in map name, it's a custom dot map */
	if (strchr(real_name + 1, '.') != NULL)
		pfx_len = 0;
	else
		pfx_len = min((size_t)BPF_OBJ_NAME_LEN - sfx_len - 1, strlen(obj->name));

	snprintf(map_name, sizeof(map_name), "%.*s%.*s", pfx_len, obj->name,
		 sfx_len, real_name);

	/* sanitise map name to characters allowed by kernel */
	for (p = map_name; *p && p < map_name + sizeof(map_name); p++)
		if (!isalnum(*p) && *p != '_' && *p != '.')
			*p = '_';

	return strdup(map_name);
}

static int
map_fill_btf_type_info(struct bpf_object *obj, struct bpf_map *map);

/* Internal BPF map is mmap()'able only if at least one of corresponding
 * DATASEC's VARs are to be exposed through BPF skeleton. I.e., it's a GLOBAL
 * variable and it's not marked as __hidden (which turns it into, effectively,
 * a STATIC variable).
 */
static bool map_is_mmapable(struct bpf_object *obj, struct bpf_map *map)
{
	const struct btf_type *t, *vt;
	struct btf_var_secinfo *vsi;
	int i, n;

	if (!map->btf_value_type_id)
		return false;

	t = btf__type_by_id(obj->btf, map->btf_value_type_id);
	if (!btf_is_datasec(t))
		return false;

	vsi = btf_var_secinfos(t);
	for (i = 0, n = btf_vlen(t); i < n; i++, vsi++) {
		vt = btf__type_by_id(obj->btf, vsi->type);
		if (!btf_is_var(vt))
			continue;

		if (btf_var(vt)->linkage != BTF_VAR_STATIC)
			return true;
	}

	return false;
}

static int
bpf_object__init_internal_map(struct bpf_object *obj, enum libbpf_map_type type,
			      const char *real_name, int sec_idx, void *data, size_t data_sz)
{
	struct bpf_map_def *def;
	struct bpf_map *map;
	size_t mmap_sz;
	int err;

	map = bpf_object__add_map(obj);
	if (IS_ERR(map))
		return PTR_ERR(map);

	map->libbpf_type = type;
	map->sec_idx = sec_idx;
	map->sec_offset = 0;
	map->real_name = strdup(real_name);
	map->name = internal_map_name(obj, real_name);
	if (!map->real_name || !map->name) {
		zfree(&map->real_name);
		zfree(&map->name);
		return -ENOMEM;
	}

	def = &map->def;
	def->type = BPF_MAP_TYPE_ARRAY;
	def->key_size = sizeof(int);
	def->value_size = data_sz;
	def->max_entries = 1;
	def->map_flags = type == LIBBPF_MAP_RODATA || type == LIBBPF_MAP_KCONFIG
			 ? BPF_F_RDONLY_PROG : 0;

	/* failures are fine because of maps like .rodata.str1.1 */
	(void) map_fill_btf_type_info(obj, map);

	if (map_is_mmapable(obj, map))
		def->map_flags |= BPF_F_MMAPABLE;

	pr_debug("map '%s' (global data): at sec_idx %d, offset %zu, flags %x.\n",
		 map->name, map->sec_idx, map->sec_offset, def->map_flags);

	mmap_sz = bpf_map_mmap_sz(map->def.value_size, map->def.max_entries);
	map->mmaped = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map->mmaped == MAP_FAILED) {
		err = -errno;
		map->mmaped = NULL;
		pr_warn("failed to alloc map '%s' content buffer: %d\n",
			map->name, err);
		zfree(&map->real_name);
		zfree(&map->name);
		return err;
	}

	if (data)
		memcpy(map->mmaped, data, data_sz);

	pr_debug("map %td is \"%s\"\n", map - obj->maps, map->name);
	return 0;
}

static int bpf_object__init_global_data_maps(struct bpf_object *obj)
{
	struct elf_sec_desc *sec_desc;
	const char *sec_name;
	int err = 0, sec_idx;

	/*
	 * Populate obj->maps with libbpf internal maps.
	 */
	for (sec_idx = 1; sec_idx < obj->efile.sec_cnt; sec_idx++) {
		sec_desc = &obj->efile.secs[sec_idx];

		/* Skip recognized sections with size 0. */
		if (!sec_desc->data || sec_desc->data->d_size == 0)
			continue;

		switch (sec_desc->sec_type) {
		case SEC_DATA:
			sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
			err = bpf_object__init_internal_map(obj, LIBBPF_MAP_DATA,
							    sec_name, sec_idx,
							    sec_desc->data->d_buf,
							    sec_desc->data->d_size);
			break;
		case SEC_RODATA:
			obj->has_rodata = true;
			sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
			err = bpf_object__init_internal_map(obj, LIBBPF_MAP_RODATA,
							    sec_name, sec_idx,
							    sec_desc->data->d_buf,
							    sec_desc->data->d_size);
			break;
		case SEC_BSS:
			sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
			err = bpf_object__init_internal_map(obj, LIBBPF_MAP_BSS,
							    sec_name, sec_idx,
							    NULL,
							    sec_desc->data->d_size);
			break;
		default:
			/* skip */
			break;
		}
		if (err)
			return err;
	}
	return 0;
}

static struct extern_desc *find_extern_by_name(const struct bpf_object *obj,
					       const void *name)
{
	int i;

	for (i = 0; i < obj->nr_extern; i++) {
		if (strcmp(obj->externs[i].name, name) == 0)
			return &obj->externs[i];
	}
	return NULL;
}

// static int set_kcfg_value_tri(struct extern_desc *ext, void *ext_val,
// 			      char value)
// {
// 	switch (ext->kcfg.type) {
// 	case KCFG_BOOL:
// 		if (value == 'm') {
// 			printf("extern (kcfg) '%s': value '%c' implies tristate or char type\n",
// 				ext->name, value);
// 			return -EINVAL;
// 		}
// 		*(bool *)ext_val = value == 'y' ? true : false;
// 		break;
// 	case KCFG_TRISTATE:
// 		if (value == 'y')
// 			*(enum libbpf_tristate *)ext_val = TRI_YES;
// 		else if (value == 'm')
// 			*(enum libbpf_tristate *)ext_val = TRI_MODULE;
// 		else /* value == 'n' */
// 			*(enum libbpf_tristate *)ext_val = TRI_NO;
// 		break;
// 	case KCFG_CHAR:
// 		*(char *)ext_val = value;
// 		break;
// 	case KCFG_UNKNOWN:
// 	case KCFG_INT:
// 	case KCFG_CHAR_ARR:
// 	default:
// 		printf("extern (kcfg) '%s': value '%c' implies bool, tristate, or char type\n",
// 			ext->name, value);
// 		return -EINVAL;
// 	}
// 	ext->is_set = true;
// 	return 0;
// }

// static int set_kcfg_value_str(struct extern_desc *ext, char *ext_val,
// 			      const char *value)
// {
// 	size_t len;

// 	if (ext->kcfg.type != KCFG_CHAR_ARR) {
// 		printf("extern (kcfg) '%s': value '%s' implies char array type\n",
// 			ext->name, value);
// 		return -EINVAL;
// 	}

// 	len = strlen(value);
// 	if (value[len - 1] != '"') {
// 		printf("extern (kcfg) '%s': invalid string config '%s'\n",
// 			ext->name, value);
// 		return -EINVAL;
// 	}

// 	/* strip quotes */
// 	len -= 2;
// 	if (len >= ext->kcfg.sz) {
// 		printf("extern (kcfg) '%s': long string '%s' of (%zu bytes) truncated to %d bytes\n",
// 			ext->name, value, len, ext->kcfg.sz - 1);
// 		len = ext->kcfg.sz - 1;
// 	}
// 	memcpy(ext_val, value + 1, len);
// 	ext_val[len] = '\0';
// 	ext->is_set = true;
// 	return 0;
// }

// static int parse_u64(const char *value, __u64 *res)
// {
// 	char *value_end;
// 	int err;

// 	errno = 0;
// 	*res = strtoull(value, &value_end, 0);
// 	if (errno) {
// 		err = -errno;
// 		printf("failed to parse '%s' as integer: %d\n", value, err);
// 		return err;
// 	}
// 	if (*value_end) {
// 		printf("failed to parse '%s' as integer completely\n", value);
// 		return -EINVAL;
// 	}
// 	return 0;
// }

// static bool is_kcfg_value_in_range(const struct extern_desc *ext, __u64 v)
// {
// 	int bit_sz = ext->kcfg.sz * 8;

// 	if (ext->kcfg.sz == 8)
// 		return true;

// 	/* Validate that value stored in u64 fits in integer of `ext->sz`
// 	 * bytes size without any loss of information. If the target integer
// 	 * is signed, we rely on the following limits of integer type of
// 	 * Y bits and subsequent transformation:
// 	 *
// 	 *     -2^(Y-1) <= X           <= 2^(Y-1) - 1
// 	 *            0 <= X + 2^(Y-1) <= 2^Y - 1
// 	 *            0 <= X + 2^(Y-1) <  2^Y
// 	 *
// 	 *  For unsigned target integer, check that all the (64 - Y) bits are
// 	 *  zero.
// 	 */
// 	if (ext->kcfg.is_signed)
// 		return v + (1ULL << (bit_sz - 1)) < (1ULL << bit_sz);
// 	else
// 		return (v >> bit_sz) == 0;
// }

// static int set_kcfg_value_num(struct extern_desc *ext, void *ext_val,
// 			      __u64 value)
// {
// 	if (ext->kcfg.type != KCFG_INT && ext->kcfg.type != KCFG_CHAR &&
// 	    ext->kcfg.type != KCFG_BOOL) {
// 		printf("extern (kcfg) '%s': value '%llu' implies integer, char, or boolean type\n",
// 			ext->name, (unsigned long long)value);
// 		return -EINVAL;
// 	}
// 	if (ext->kcfg.type == KCFG_BOOL && value > 1) {
// 		printf("extern (kcfg) '%s': value '%llu' isn't boolean compatible\n",
// 			ext->name, (unsigned long long)value);
// 		return -EINVAL;

// 	}
// 	if (!is_kcfg_value_in_range(ext, value)) {
// 		printf("extern (kcfg) '%s': value '%llu' doesn't fit in %d bytes\n",
// 			ext->name, (unsigned long long)value, ext->kcfg.sz);
// 		return -ERANGE;
// 	}
// 	switch (ext->kcfg.sz) {
// 	case 1:
// 		*(__u8 *)ext_val = value;
// 		break;
// 	case 2:
// 		*(__u16 *)ext_val = value;
// 		break;
// 	case 4:
// 		*(__u32 *)ext_val = value;
// 		break;
// 	case 8:
// 		*(__u64 *)ext_val = value;
// 		break;
// 	default:
// 		return -EINVAL;
// 	}
// 	ext->is_set = true;
// 	return 0;
// }

// static int bpf_object__process_kconfig_line(struct bpf_object *obj,
// 					    char *buf, void *data)
// {
// 	struct extern_desc *ext;
// 	char *sep, *value;
// 	int len, err = 0;
// 	void *ext_val;
// 	__u64 num;

// 	if (!str_has_pfx(buf, "CONFIG_"))
// 		return 0;

// 	sep = strchr(buf, '=');
// 	if (!sep) {
// 		printf("failed to parse '%s': no separator\n", buf);
// 		return -EINVAL;
// 	}

// 	/* Trim ending '\n' */
// 	len = strlen(buf);
// 	if (buf[len - 1] == '\n')
// 		buf[len - 1] = '\0';
// 	/* Split on '=' and ensure that a value is present. */
// 	*sep = '\0';
// 	if (!sep[1]) {
// 		*sep = '=';
// 		printf("failed to parse '%s': no value\n", buf);
// 		return -EINVAL;
// 	}

// 	ext = find_extern_by_name(obj, buf);
// 	if (!ext || ext->is_set)
// 		return 0;

// 	ext_val = data + ext->kcfg.data_off;
// 	value = sep + 1;

// 	switch (*value) {
// 	case 'y': case 'n': case 'm':
// 		err = set_kcfg_value_tri(ext, ext_val, *value);
// 		break;
// 	case '"':
// 		err = set_kcfg_value_str(ext, ext_val, value);
// 		break;
// 	default:
// 		/* assume integer */
// 		err = parse_u64(value, &num);
// 		if (err) {
// 			printf("extern (kcfg) '%s': value '%s' isn't a valid integer\n", ext->name, value);
// 			return err;
// 		}
// 		if (ext->kcfg.type != KCFG_INT && ext->kcfg.type != KCFG_CHAR) {
// 			printf("extern (kcfg) '%s': value '%s' implies integer type\n", ext->name, value);
// 			return -EINVAL;
// 		}
// 		err = set_kcfg_value_num(ext, ext_val, num);
// 		break;
// 	}
// 	if (err)
// 		return err;
// 	printf("extern (kcfg) '%s': set to %s\n", ext->name, value);
// 	return 0;
// }

// static int bpf_object__read_kconfig_file(struct bpf_object *obj, void *data)
// {
// 	char buf[PATH_MAX];
// 	struct utsname uts;
// 	int len, err = 0;
// 	gzFile file;

// 	uname(&uts);
// 	len = snprintf(buf, PATH_MAX, "/boot/config-%s", uts.release);
// 	if (len < 0)
// 		return -EINVAL;
// 	else if (len >= PATH_MAX)
// 		return -ENAMETOOLONG;

// 	/* gzopen also accepts uncompressed files. */
// 	file = gzopen(buf, "re");
// 	if (!file)
// 		file = gzopen("/proc/config.gz", "re");

// 	if (!file) {
// 		printf("failed to open system Kconfig\n");
// 		return -ENOENT;
// 	}

// 	while (gzgets(file, buf, sizeof(buf))) {
// 		err = bpf_object__process_kconfig_line(obj, buf, data);
// 		if (err) {
// 			printf("error parsing system Kconfig line '%s': %d\n",
// 				buf, err);
// 			goto out;
// 		}
// 	}

// out:
// 	gzclose(file);
// 	return err;
// }

static int bpf_object__init_kconfig_map(struct bpf_object *obj)
{
	struct extern_desc *last_ext = NULL, *ext;
	size_t map_sz;
	int i, err;

	for (i = 0; i < obj->nr_extern; i++) {
		ext = &obj->externs[i];
		if (ext->type == EXT_KCFG)
			last_ext = ext;
	}

	if (!last_ext)
		return 0;

	map_sz = last_ext->kcfg.data_off + last_ext->kcfg.sz;
	err = bpf_object__init_internal_map(obj, LIBBPF_MAP_KCONFIG,
					    ".kconfig", obj->efile.symbols_shndx,
					    NULL, map_sz);
	if (err)
		return err;

	obj->kconfig_map_idx = obj->nr_maps - 1;

	return 0;
}

static bool libbpf_needs_btf(const struct bpf_object *obj)
{
	return obj->efile.btf_maps_shndx >= 0 ||
	       obj->efile.st_ops_shndx >= 0 ||
	       obj->efile.st_ops_link_shndx >= 0 ||
	       obj->nr_extern > 0;
}

static bool kernel_needs_btf(const struct bpf_object *obj)
{
	return obj->efile.st_ops_shndx >= 0 || obj->efile.st_ops_link_shndx >= 0;
}

/**
 * bpf_object__init_btf - 初始化bpf_object中的btf_object
 * @obj: 指向bpf_object
 * @btf_data: 指向btf_data
 * @btf_ext_data: 指向btf_ext_data
 */
static int bpf_object__init_btf(struct bpf_object *obj,
				Elf_Data *btf_data,
				Elf_Data *btf_ext_data)
{
	int err = -ENOENT;

	if (btf_data) {
		obj->btf = btf__new(btf_data->d_buf, btf_data->d_size);
		err = libbpf_get_error(obj->btf);
		if (err) {
			obj->btf = NULL;
			printf("Error loading ELF section %s: %d.\n", BTF_ELF_SEC, err);
			goto out;
		}
		/* enforce 8-byte pointers for BPF-targeted BTFs */
		btf__set_pointer_size(obj->btf, 8);
	}
	if (btf_ext_data) {
		struct btf_ext_info *ext_segs[3];
		int seg_num, sec_num;

		if (!obj->btf) {
			printf("Ignore ELF section %s because its depending ELF section %s is not found.\n",
				 BTF_EXT_ELF_SEC, BTF_ELF_SEC);
			goto out;
		}
		obj->btf_ext = btf_ext__new(btf_ext_data->d_buf, btf_ext_data->d_size);
		err = libbpf_get_error(obj->btf_ext);
		if (err) {
			printf("Error loading ELF section %s: %d. Ignored and continue.\n",
				BTF_EXT_ELF_SEC, err);
			obj->btf_ext = NULL;
			goto out;
		}

		/* setup .BTF.ext to ELF section mapping */
		ext_segs[0] = &obj->btf_ext->func_info;
		ext_segs[1] = &obj->btf_ext->line_info;
		ext_segs[2] = &obj->btf_ext->core_relo_info;
		for (seg_num = 0; seg_num < ARRAY_SIZE(ext_segs); seg_num++) {
			struct btf_ext_info *seg = ext_segs[seg_num];
			const struct btf_ext_info_sec *sec;
			const char *sec_name;
			Elf_Scn *scn;

			if (seg->sec_cnt == 0)
				continue;

			seg->sec_idxs = calloc(seg->sec_cnt, sizeof(*seg->sec_idxs));
			if (!seg->sec_idxs) {
				err = -ENOMEM;
				goto out;
			}

			sec_num = 0;
			for_each_btf_ext_sec(seg, sec) {
				/* preventively increment index to avoid doing
				 * this before every continue below
				 */
				sec_num++;

				sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
				if (str_is_empty(sec_name))
					continue;
				scn = elf_sec_by_name(obj, sec_name);
				if (!scn)
					continue;

				seg->sec_idxs[sec_num - 1] = elf_ndxscn(scn);
			}
		}
	}
out:
	if (err && libbpf_needs_btf(obj)) {
		printf("BTF is required, but is missing or corrupted.\n");
		return err;
	}
	return 0;
}

static int compare_vsi_off(const void *_a, const void *_b)
{
	const struct btf_var_secinfo *a = _a;
	const struct btf_var_secinfo *b = _b;

	return a->offset - b->offset;
}

static int btf_fixup_datasec(struct bpf_object *obj, struct btf *btf,
			     struct btf_type *t)
{
	__u32 size = 0, i, vars = btf_vlen(t);
	const char *sec_name = btf__name_by_offset(btf, t->name_off);
	struct btf_var_secinfo *vsi;
	bool fixup_offsets = false;
	int err;

	if (!sec_name) {
		printf("No name found in string section for DATASEC kind.\n");
		return -ENOENT;
	}

	/* Extern-backing datasecs (.ksyms, .kconfig) have their size and
	 * variable offsets set at the previous step. Further, not every
	 * extern BTF VAR has corresponding ELF symbol preserved, so we skip
	 * all fixups altogether for such sections and go straight to sorting
	 * VARs within their DATASEC.
	 */
	if (strcmp(sec_name, KCONFIG_SEC) == 0 || strcmp(sec_name, KSYMS_SEC) == 0)
		goto sort_vars;

	/* Clang leaves DATASEC size and VAR offsets as zeroes, so we need to
	 * fix this up. But BPF static linker already fixes this up and fills
	 * all the sizes and offsets during static linking. So this step has
	 * to be optional. But the STV_HIDDEN handling is non-optional for any
	 * non-extern DATASEC, so the variable fixup loop below handles both
	 * functions at the same time, paying the cost of BTF VAR <-> ELF
	 * symbol matching just once.
	 */
	if (t->size == 0) {
		err = find_elf_sec_sz(obj, sec_name, &size);
		if (err || !size) {
			printf("sec '%s': failed to determine size from ELF: size %u, err %d\n",
				 sec_name, size, err);
			return -ENOENT;
		}

		t->size = size;
		fixup_offsets = true;
	}

	for (i = 0, vsi = btf_var_secinfos(t); i < vars; i++, vsi++) {
		const struct btf_type *t_var;
		struct btf_var *var;
		const char *var_name;
		Elf64_Sym *sym;

		t_var = btf__type_by_id(btf, vsi->type);
		if (!t_var || !btf_is_var(t_var)) {
			printf("sec '%s': unexpected non-VAR type found\n", sec_name);
			return -EINVAL;
		}

		var = btf_var(t_var);
		if (var->linkage == BTF_VAR_STATIC || var->linkage == BTF_VAR_GLOBAL_EXTERN)
			continue;

		var_name = btf__name_by_offset(btf, t_var->name_off);
		if (!var_name) {
			printf("sec '%s': failed to find name of DATASEC's member #%d\n",
				 sec_name, i);
			return -ENOENT;
		}

		sym = find_elf_var_sym(obj, var_name);
		if (IS_ERR(sym)) {
			printf("sec '%s': failed to find ELF symbol for VAR '%s'\n",
				 sec_name, var_name);
			return -ENOENT;
		}

		if (fixup_offsets)
			vsi->offset = sym->st_value;

		/* if variable is a global/weak symbol, but has restricted
		 * (STV_HIDDEN or STV_INTERNAL) visibility, mark its BTF VAR
		 * as static. This follows similar logic for functions (BPF
		 * subprogs) and influences libbpf's further decisions about
		 * whether to make global data BPF array maps as
		 * BPF_F_MMAPABLE.
		 */
		if (ELF64_ST_VISIBILITY(sym->st_other) == STV_HIDDEN
		    || ELF64_ST_VISIBILITY(sym->st_other) == STV_INTERNAL)
			var->linkage = BTF_VAR_STATIC;
	}

sort_vars:
	qsort(btf_var_secinfos(t), vars, sizeof(*vsi), compare_vsi_off);
	return 0;
}

static int bpf_object_fixup_btf(struct bpf_object *obj)
{
	int i, n, err = 0;

	if (!obj->btf)
		return 0;

	n = btf__type_cnt(obj->btf);
	for (i = 1; i < n; i++) {
		struct btf_type *t = btf_type_by_id(obj->btf, i);

		/* Loader needs to fix up some of the things compiler
		 * couldn't get its hands on while emitting BTF. This
		 * is section size and global variable offset. We use
		 * the info from the ELF itself for this purpose.
		 */
		if (btf_is_datasec(t)) {
			err = btf_fixup_datasec(obj, obj->btf, t);
			if (err)
				return err;
		}
	}

	return 0;
}

static const char *elf_sym_str(const struct bpf_object *obj, size_t off)
{
	const char *name;

	name = elf_strptr(obj->efile.elf, obj->efile.strtabidx, off);
	if (!name) {
		printf("elf: failed to get section name string at offset %zu from %s: %s\n",
			off, obj->path, elf_errmsg(-1));
		return NULL;
	}

	return name;
}

static const char *elf_sec_str(const struct bpf_object *obj, size_t off)
{
	const char *name;

	name = elf_strptr(obj->efile.elf, obj->efile.shstrndx, off);
	if (!name) {
		printf("elf: failed to get section name string at offset %zu from %s: %s\n",
			off, obj->path, elf_errmsg(-1));
		return NULL;
	}

	return name;
}

static Elf_Scn *elf_sec_by_idx(const struct bpf_object *obj, size_t idx)
{
	Elf_Scn *scn;

	scn = elf_getscn(obj->efile.elf, idx);
	if (!scn) {
		printf("elf: failed to get section(%zu) from %s: %s\n",
			idx, obj->path, elf_errmsg(-1));
		return NULL;
	}
	return scn;
}

static Elf_Scn *elf_sec_by_name(const struct bpf_object *obj, const char *name)
{
	Elf_Scn *scn = NULL;
	Elf *elf = obj->efile.elf;
	const char *sec_name;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		sec_name = elf_sec_name(obj, scn);
		if (!sec_name)
			return NULL;

		if (strcmp(sec_name, name) != 0)
			continue;

		return scn;
	}
	return NULL;
}

/**
 * elf_sec_hdr - get elf section's header
 * @scn: 要获取section header的section
 */
static Elf64_Shdr *elf_sec_hdr(const struct bpf_object *obj, Elf_Scn *scn)
{
	Elf64_Shdr *shdr;

	if (!scn)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr) {
		printf("elf: failed to get section(%zu) header from %s: %s\n",
			elf_ndxscn(scn), obj->path, elf_errmsg(-1));
		return NULL;
	}

	return shdr;
}

static const char *elf_sec_name(const struct bpf_object *obj, Elf_Scn *scn)
{
	const char *name;
	Elf64_Shdr *sh;

	if (!scn)
		return NULL;

	sh = elf_sec_hdr(obj, scn);
	if (!sh)
		return NULL;

	name = elf_sec_str(obj, sh->sh_name);
	if (!name) {
		printf("elf: failed to get section(%zu) name from %s: %s\n",
			elf_ndxscn(scn), obj->path, elf_errmsg(-1));
		return NULL;
	}

	return name;
}

static Elf_Data *elf_sec_data(const struct bpf_object *obj, Elf_Scn *scn)
{
	Elf_Data *data;

	if (!scn)
		return NULL;

	data = elf_getdata(scn, 0);
	if (!data) {
		printf("elf: failed to get section(%zu) %s data from %s: %s\n",
			elf_ndxscn(scn), elf_sec_name(obj, scn) ?: "<?>",
			obj->path, elf_errmsg(-1));
		return NULL;
	}

	return data;
}

static Elf64_Sym *elf_sym_by_idx(const struct bpf_object *obj, size_t idx)
{
	if (idx >= obj->efile.symbols->d_size / sizeof(Elf64_Sym))
		return NULL;

	return (Elf64_Sym *)obj->efile.symbols->d_buf + idx;
}

static Elf64_Rel *elf_rel_by_idx(Elf_Data *data, size_t idx)
{
	if (idx >= data->d_size / sizeof(Elf64_Rel))
		return NULL;

	return (Elf64_Rel *)data->d_buf + idx;
}

static bool is_sec_name_dwarf(const char *name)
{
	/* approximation, but the actual list is too long */
	return str_has_pfx(name, ".debug_");
}

static bool ignore_elf_section(Elf64_Shdr *hdr, const char *name)
{
	/* no special handling of .strtab */
	if (hdr->sh_type == SHT_STRTAB)
		return true;

	/* ignore .llvm_addrsig section as well */
	if (hdr->sh_type == SHT_LLVM_ADDRSIG)
		return true;

	/* no subprograms will lead to an empty .text section, ignore it */
	if (hdr->sh_type == SHT_PROGBITS && hdr->sh_size == 0 &&
	    strcmp(name, ".text") == 0)
		return true;

	/* DWARF sections */
	if (is_sec_name_dwarf(name))
		return true;

	if (str_has_pfx(name, ".rel")) {
		name += sizeof(".rel") - 1;
		/* DWARF section relocations */
		if (is_sec_name_dwarf(name))
			return true;

		/* .BTF and .BTF.ext don't need relocations */
		if (strcmp(name, BTF_ELF_SEC) == 0 ||
		    strcmp(name, BTF_EXT_ELF_SEC) == 0)
			return true;
	}

	return false;
}

static bool section_have_execinstr(struct bpf_object *obj, int idx)
{
	Elf64_Shdr *sh;

	sh = elf_sec_hdr(obj, elf_sec_by_idx(obj, idx));
	if (!sh)
		return false;

	return sh->sh_flags & SHF_EXECINSTR;
}

static int cmp_progs(const void *_a, const void *_b)
{
	const struct bpf_program *a = _a;
	const struct bpf_program *b = _b;

	if (a->sec_idx != b->sec_idx)
		return a->sec_idx < b->sec_idx ? -1 : 1;

	/* sec_insn_off can't be the same within the section */
	return a->sec_insn_off < b->sec_insn_off ? -1 : 1;
}

static int bpf_object__elf_collect(struct bpf_object *obj)
{
	struct elf_sec_desc *sec_desc;
	Elf *elf = obj->efile.elf;
	Elf_Data *btf_ext_data = NULL;
	Elf_Data *btf_data = NULL;
	int idx = 0, err = 0;
	const char *name;
	Elf_Data *data;
	Elf_Scn *scn;
	Elf64_Shdr *sh;

	/* ELF section indices are 0-based, but sec #0 is special "invalid"
	 * section. Since section count retrieved by elf_getshdrnum() does
	 * include sec #0, it is already the necessary size of an array to keep
	 * all the sections.
	 */
	/**
	 * ELF section的索引从0开始，但节#0是特殊的“无效”节。
	 * 由于elf_getshdrnum()返回的节计数包括了节#0，
	 * 因此，它已经是一个足够大的数组来保存所有的节。
	 */
	if (elf_getshdrnum(obj->efile.elf, &obj->efile.sec_cnt)) {
		printf("elf: failed to get the number of sections for %s: %s\n",
			obj->path, elf_errmsg(-1));
		return -LIBBPF_ERRNO__FORMAT;
	}
	/**
	 * 分配obj->efile.sec_cnt个struct elf_sec_desc结构
	 */
	obj->efile.secs = calloc(obj->efile.sec_cnt, sizeof(*obj->efile.secs));
	if (!obj->efile.secs)
		return -ENOMEM;

	/**
	 * a bunch of elf parsing functionality depends on processing symbols,
	 * so do the first pass and find the symbol table
	 * 许多ELF解析功能依赖于处理符号，因此进行第一次遍历，找到符号表。
	 * 遍历每一个seciton，找到符号表(symbol table)
	 */
	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		/**
		 * 获取section的header
		 */
		sh = elf_sec_hdr(obj, scn);
		if (!sh)
			return -LIBBPF_ERRNO__FORMAT;

		if (sh->sh_type == SHT_SYMTAB) {
			if (obj->efile.symbols) {
				printf("elf: multiple symbol tables in %s\n", obj->path);
				return -LIBBPF_ERRNO__FORMAT;
			}

			data = elf_sec_data(obj, scn);
			if (!data)
				return -LIBBPF_ERRNO__FORMAT;

			idx = elf_ndxscn(scn);

			obj->efile.symbols = data;   // 符号表数据
			obj->efile.symbols_shndx = idx;   // 符号表索引
			obj->efile.strtabidx = sh->sh_link;   // 符号表使用的字符串表索引
		}
	}

	/**
	 * 检查是否获得了符号表数据
	 */
	if (!obj->efile.symbols) {
		printf("elf: couldn't find symbol table in %s, stripped object file?\n",
			obj->path);
		return -ENOENT;
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		idx = elf_ndxscn(scn);
		sec_desc = &obj->efile.secs[idx];

		sh = elf_sec_hdr(obj, scn);
		if (!sh)
			return -LIBBPF_ERRNO__FORMAT;

		name = elf_sec_str(obj, sh->sh_name);
		if (!name)
			return -LIBBPF_ERRNO__FORMAT;

		if (ignore_elf_section(sh, name))
			continue;
		
		data = elf_sec_data(obj, scn);
		if (!data)
			return -LIBBPF_ERRNO__FORMAT;

		pr_debug("elf: section(%d) %s, size %ld, link %d, flags %lx, type=%d\n",
			 idx, name, (unsigned long)data->d_size,
			 (int)sh->sh_link, (unsigned long)sh->sh_flags,
			 (int)sh->sh_type);

		if (strcmp(name, "license") == 0) {
			/**
			 * 初始化bpf_object的license成员
			 */
			err = bpf_object__init_license(obj, data->d_buf, data->d_size);
			if (err)
				return err;
		} else if (strcmp(name, "maps") == 0) {
			printf("elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+\n");
			return -ENOTSUP;
		} else if (strcmp(name, MAPS_ELF_SEC) == 0) {
			/**
			 * 记录btf_maps段的索引
			 */
			obj->efile.btf_maps_shndx = idx;
		} else if (strcmp(name, BTF_ELF_SEC) == 0) {
			if (sh->sh_type != SHT_PROGBITS)
				return -LIBBPF_ERRNO__FORMAT;
			/**
			 * 记录btf section的数据
			 */
			btf_data = data;
		} else if (sh->sh_type == SHT_PROGBITS && data->d_size > 0) {
			if (sh->sh_flags & SHF_EXECINSTR) {
				/**
				 * 记录.text section的索引
				 */
				if (strcmp(name, ".text") == 0)
					obj->efile.text_shndx = idx;
				err = bpf_object__add_programs(obj, data, name, idx);
				if (err)
					return err;
			} else if (strcmp(name, DATA_SEC) == 0 ||
				   str_has_pfx(name, DATA_SEC ".")) {
				sec_desc->sec_type = SEC_DATA;
				sec_desc->shdr = sh;
				sec_desc->data = data;
			} else if (strcmp(name, RODATA_SEC) == 0 ||
				   str_has_pfx(name, RODATA_SEC ".")) {
				sec_desc->sec_type = SEC_RODATA;
				sec_desc->shdr = sh;
				sec_desc->data = data;
			} else if (strcmp(name, STRUCT_OPS_SEC) == 0) {
				obj->efile.st_ops_data = data;
				obj->efile.st_ops_shndx = idx;
			} else if (strcmp(name, STRUCT_OPS_LINK_SEC) == 0) {
				obj->efile.st_ops_link_data = data;
				obj->efile.st_ops_link_shndx = idx;
			} else {
				pr_debug("elf: skipping unrecognized data section(%d) %s\n",
					idx, name);
			}
		} else if (sh->sh_type == SHT_REL) {
			int targ_sec_idx = sh->sh_info; /* points to other section */

			if (sh->sh_entsize != sizeof(Elf64_Rel) ||
			    targ_sec_idx >= obj->efile.sec_cnt)
				return -LIBBPF_ERRNO__FORMAT;

			/* Only do relo for section with exec instructions */
			if (!section_have_execinstr(obj, targ_sec_idx) &&
			    strcmp(name, ".rel" STRUCT_OPS_SEC) &&
			    strcmp(name, ".rel" STRUCT_OPS_LINK_SEC) &&
			    strcmp(name, ".rel" MAPS_ELF_SEC)) {
				printf("elf: skipping relo section(%d) %s for section(%d) %s\n",
					idx, name, targ_sec_idx,
					elf_sec_name(obj, elf_sec_by_idx(obj, targ_sec_idx)) ?: "<?>");
				continue;
			}

			sec_desc->sec_type = SEC_RELO;
			sec_desc->shdr = sh;
			sec_desc->data = data;
		} else if (sh->sh_type == SHT_NOBITS && (strcmp(name, BSS_SEC) == 0 ||
							 str_has_pfx(name, BSS_SEC "."))) {
			sec_desc->sec_type = SEC_BSS;
			sec_desc->shdr = sh;
			sec_desc->data = data;
		} else {
			pr_debug("elf: skipping section(%d) %s (size %zu)\n", idx, name,
				(size_t)sh->sh_size);
		}
	}

	if (!obj->efile.strtabidx || obj->efile.strtabidx > idx) {
		printf("elf: symbol strings section missing or invalid in %s\n", obj->path);
		return -LIBBPF_ERRNO__FORMAT;
	}

	/* sort BPF programs by section name and in-section instruction offset
	 * for faster search
	 */
	if (obj->nr_programs)
		qsort(obj->programs, obj->nr_programs, sizeof(*obj->programs), cmp_progs);

	return bpf_object__init_btf(obj, btf_data, btf_ext_data);
}

static bool sym_is_extern(const Elf64_Sym *sym)
{
	int bind = ELF64_ST_BIND(sym->st_info);
	/* externs are symbols w/ type=NOTYPE, bind=GLOBAL|WEAK, section=UND */
	return sym->st_shndx == SHN_UNDEF &&
	       (bind == STB_GLOBAL || bind == STB_WEAK) &&
	       ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE;
}

static bool sym_is_subprog(const Elf64_Sym *sym, int text_shndx)
{
	int bind = ELF64_ST_BIND(sym->st_info);
	int type = ELF64_ST_TYPE(sym->st_info);

	/* in .text section */
	if (sym->st_shndx != text_shndx)
		return false;

	/* local function */
	if (bind == STB_LOCAL && type == STT_SECTION)
		return true;

	/* global function */
	return bind == STB_GLOBAL && type == STT_FUNC;
}

static int find_extern_btf_id(const struct btf *btf, const char *ext_name)
{
	const struct btf_type *t;
	const char *tname;
	int i, n;

	if (!btf)
		return -ESRCH;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(btf, i);

		if (!btf_is_var(t) && !btf_is_func(t))
			continue;

		tname = btf__name_by_offset(btf, t->name_off);
		if (strcmp(tname, ext_name))
			continue;

		if (btf_is_var(t) &&
		    btf_var(t)->linkage != BTF_VAR_GLOBAL_EXTERN)
			return -EINVAL;

		if (btf_is_func(t) && btf_func_linkage(t) != BTF_FUNC_EXTERN)
			return -EINVAL;

		return i;
	}

	return -ENOENT;
}

static int find_extern_sec_btf_id(struct btf *btf, int ext_btf_id)
{
	const struct btf_var_secinfo *vs;
	const struct btf_type *t;
	int i, j, n;

	if (!btf)
		return -ESRCH;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(btf, i);

		if (!btf_is_datasec(t))
			continue;

		vs = btf_var_secinfos(t);
		for (j = 0; j < btf_vlen(t); j++, vs++) {
			if (vs->type == ext_btf_id)
				return i;
		}
	}

	return -ENOENT;
}

static enum kcfg_type find_kcfg_type(const struct btf *btf, int id,
				     bool *is_signed)
{
	const struct btf_type *t;
	const char *name;

	t = skip_mods_and_typedefs(btf, id, NULL);
	name = btf__name_by_offset(btf, t->name_off);

	if (is_signed)
		*is_signed = false;
	switch (btf_kind(t)) {
	case BTF_KIND_INT: {
		int enc = btf_int_encoding(t);

		if (enc & BTF_INT_BOOL)
			return t->size == 1 ? KCFG_BOOL : KCFG_UNKNOWN;
		if (is_signed)
			*is_signed = enc & BTF_INT_SIGNED;
		if (t->size == 1)
			return KCFG_CHAR;
		if (t->size < 1 || t->size > 8 || (t->size & (t->size - 1)))
			return KCFG_UNKNOWN;
		return KCFG_INT;
	}
	case BTF_KIND_ENUM:
		if (t->size != 4)
			return KCFG_UNKNOWN;
		if (strcmp(name, "libbpf_tristate"))
			return KCFG_UNKNOWN;
		return KCFG_TRISTATE;
	case BTF_KIND_ENUM64:
		if (strcmp(name, "libbpf_tristate"))
			return KCFG_UNKNOWN;
		return KCFG_TRISTATE;
	case BTF_KIND_ARRAY:
		if (btf_array(t)->nelems == 0)
			return KCFG_UNKNOWN;
		if (find_kcfg_type(btf, btf_array(t)->type, NULL) != KCFG_CHAR)
			return KCFG_UNKNOWN;
		return KCFG_CHAR_ARR;
	default:
		return KCFG_UNKNOWN;
	}
}

static int cmp_externs(const void *_a, const void *_b)
{
	const struct extern_desc *a = _a;
	const struct extern_desc *b = _b;

	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;

	if (a->type == EXT_KCFG) {
		/* descending order by alignment requirements */
		if (a->kcfg.align != b->kcfg.align)
			return a->kcfg.align > b->kcfg.align ? -1 : 1;
		/* ascending order by size, within same alignment class */
		if (a->kcfg.sz != b->kcfg.sz)
			return a->kcfg.sz < b->kcfg.sz ? -1 : 1;
	}

	/* resolve ties by name */
	return strcmp(a->name, b->name);
}

static int find_int_btf_id(const struct btf *btf)
{
	const struct btf_type *t;
	int i, n;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(btf, i);

		if (btf_is_int(t) && btf_int_bits(t) == 32)
			return i;
	}

	return 0;
}

static int add_dummy_ksym_var(struct btf *btf)
{
	int i, int_btf_id, sec_btf_id, dummy_var_btf_id;
	const struct btf_var_secinfo *vs;
	const struct btf_type *sec;

	if (!btf)
		return 0;
	
	sec_btf_id = btf__find_by_name_kind(btf, KSYMS_SEC,
					    BTF_KIND_DATASEC);
	if (sec_btf_id < 0)
		return 0;

	sec = btf__type_by_id(btf, sec_btf_id);
	vs = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++, vs++) {
		const struct btf_type *vt;

		vt = btf__type_by_id(btf, vs->type);
		if (btf_is_func(vt))
			break;
	}

	/* No func in ksyms sec.  No need to add dummy var. */
	if (i == btf_vlen(sec))
		return 0;

	int_btf_id = find_int_btf_id(btf);
	dummy_var_btf_id = btf__add_var(btf,
					"dummy_ksym",
					BTF_VAR_GLOBAL_ALLOCATED,
					int_btf_id);
	if (dummy_var_btf_id < 0)
		printf("cannot create a dummy_ksym var\n");

	return dummy_var_btf_id;
}

static int bpf_object__collect_externs(struct bpf_object *obj)
{
	struct btf_type *sec, *kcfg_sec = NULL, *ksym_sec = NULL;
	const struct btf_type *t;
	struct extern_desc *ext;
	int i, n, off, dummy_var_btf_id;
	const char *ext_name, *sec_name;
	size_t ext_essent_len;
	Elf_Scn *scn;
	Elf64_Shdr *sh;

	if (!obj->efile.symbols)
		return 0;
	
	scn = elf_sec_by_idx(obj, obj->efile.symbols_shndx);
	sh = elf_sec_hdr(obj, scn);
	if (!sh || sh->sh_entsize != sizeof(Elf64_Sym))
		return -LIBBPF_ERRNO__FORMAT;
	
	dummy_var_btf_id = add_dummy_ksym_var(obj->btf);
	if (dummy_var_btf_id < 0)
		return dummy_var_btf_id;
	
	n = sh->sh_size / sh->sh_entsize;
	pr_debug("looking for externs among %d symbols...\n", n);

	for (i = 0; i < n; i++) {
		Elf64_Sym *sym = elf_sym_by_idx(obj, i);

		if (!sym)
			return -LIBBPF_ERRNO__FORMAT;
		if (!sym_is_extern(sym))
			continue;
		ext_name = elf_sym_str(obj, sym->st_name);
		if (!ext_name || !ext_name[0])
			continue;

		ext = obj->externs;
		ext = libbpf_reallocarray(ext, obj->nr_extern + 1, sizeof(*ext));
		if (!ext)
			return -ENOMEM;
		obj->externs = ext;
		ext = &ext[obj->nr_extern];
		memset(ext, 0, sizeof(*ext));
		obj->nr_extern++;

		ext->btf_id = find_extern_btf_id(obj->btf, ext_name);
		if (ext->btf_id <= 0) {
			printf("failed to find BTF for extern '%s': %d\n",
				ext_name, ext->btf_id);
			return ext->btf_id;
		}
		t = btf__type_by_id(obj->btf, ext->btf_id);
		ext->name = btf__name_by_offset(obj->btf, t->name_off);
		ext->sym_idx = i;
		ext->is_weak = ELF64_ST_BIND(sym->st_info) == STB_WEAK;

		ext_essent_len = bpf_core_essential_name_len(ext->name);
		ext->essent_name = NULL;
		if (ext_essent_len != strlen(ext->name)) {
			ext->essent_name = strndup(ext->name, ext_essent_len);
			if (!ext->essent_name)
				return -ENOMEM;
		}

		ext->sec_btf_id = find_extern_sec_btf_id(obj->btf, ext->btf_id);
		if (ext->sec_btf_id <= 0) {
			printf("failed to find BTF for extern '%s' [%d] section: %d\n",
				ext_name, ext->btf_id, ext->sec_btf_id);
			return ext->sec_btf_id;
		}
		sec = (void *)btf__type_by_id(obj->btf, ext->sec_btf_id);
		sec_name = btf__name_by_offset(obj->btf, sec->name_off);

		if (strcmp(sec_name, KCONFIG_SEC) == 0) {
			if (btf_is_func(t)) {
				printf("extern function %s is unsupported under %s section\n",
					ext->name, KCONFIG_SEC);
				return -ENOTSUP;
			}
			kcfg_sec = sec;
			ext->type = EXT_KCFG;
			ext->kcfg.sz = btf__resolve_size(obj->btf, t->type);
			if (ext->kcfg.sz <= 0) {
				printf("failed to resolve size of extern (kcfg) '%s': %d\n",
					ext_name, ext->kcfg.sz);
				return ext->kcfg.sz;
			}
			ext->kcfg.align = btf__align_of(obj->btf, t->type);
			if (ext->kcfg.align <= 0) {
				printf("failed to determine alignment of extern (kcfg) '%s': %d\n",
					ext_name, ext->kcfg.align);
				return -EINVAL;
			}
			ext->kcfg.type = find_kcfg_type(obj->btf, t->type,
							&ext->kcfg.is_signed);
			if (ext->kcfg.type == KCFG_UNKNOWN) {
				printf("extern (kcfg) '%s': type is unsupported\n", ext_name);
				return -ENOTSUP;
			}
		} else if (strcmp(sec_name, KSYMS_SEC) == 0) {
			ksym_sec = sec;
			ext->type = EXT_KSYM;
			skip_mods_and_typedefs(obj->btf, t->type,
					       &ext->ksym.type_id);
		} else {
			printf("unrecognized extern section '%s'\n", sec_name);
			return -ENOTSUP;
		}
	}
	pr_debug("collected %d externs total\n", obj->nr_extern);

	if (!obj->nr_extern)
		return 0;

	/* sort externs by type, for kcfg ones also by (align, size, name) */
	qsort(obj->externs, obj->nr_extern, sizeof(*ext), cmp_externs);

	/* for .ksyms section, we need to turn all externs into allocated
	 * variables in BTF to pass kernel verification; we do this by
	 * pretending that each extern is a 8-byte variable
	 */
	if (ksym_sec) {
		/* find existing 4-byte integer type in BTF to use for fake
		 * extern variables in DATASEC
		 */
		int int_btf_id = find_int_btf_id(obj->btf);
		/* For extern function, a dummy_var added earlier
		 * will be used to replace the vs->type and
		 * its name string will be used to refill
		 * the missing param's name.
		 */
		const struct btf_type *dummy_var;

		dummy_var = btf__type_by_id(obj->btf, dummy_var_btf_id);
		for (i = 0; i < obj->nr_extern; i++) {
			ext = &obj->externs[i];
			if (ext->type != EXT_KSYM)
				continue;
			printf("extern (ksym) #%d: symbol %d, name %s\n",
				 i, ext->sym_idx, ext->name);
		}

		sec = ksym_sec;
		n = btf_vlen(sec);
		for (i = 0, off = 0; i < n; i++, off += sizeof(int)) {
			struct btf_var_secinfo *vs = btf_var_secinfos(sec) + i;
			struct btf_type *vt;

			vt = (void *)btf__type_by_id(obj->btf, vs->type);
			ext_name = btf__name_by_offset(obj->btf, vt->name_off);
			ext = find_extern_by_name(obj, ext_name);
			if (!ext) {
				printf("failed to find extern definition for BTF %s '%s'\n",
					btf_kind_str(vt), ext_name);
				return -ESRCH;
			}
			if (btf_is_func(vt)) {
				const struct btf_type *func_proto;
				struct btf_param *param;
				int j;

				func_proto = btf__type_by_id(obj->btf,
							     vt->type);
				param = btf_params(func_proto);
				/* Reuse the dummy_var string if the
				 * func proto does not have param name.
				 */
				for (j = 0; j < btf_vlen(func_proto); j++)
					if (param[j].type && !param[j].name_off)
						param[j].name_off =
							dummy_var->name_off;
				vs->type = dummy_var_btf_id;
				vt->info &= ~0xffff;
				vt->info |= BTF_FUNC_GLOBAL;
			} else {
				btf_var(vt)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
				vt->type = int_btf_id;
			}
			vs->offset = off;
			vs->size = sizeof(int);
		}
		sec->size = off;
	}

	if (kcfg_sec) {
		sec = kcfg_sec;
		/* for kcfg externs calculate their offsets within a .kconfig map */
		off = 0;
		for (i = 0; i < obj->nr_extern; i++) {
			ext = &obj->externs[i];
			if (ext->type != EXT_KCFG)
				continue;

			ext->kcfg.data_off = roundup(off, ext->kcfg.align);
			off = ext->kcfg.data_off + ext->kcfg.sz;
			printf("extern (kcfg) #%d: symbol %d, off %u, name %s\n",
				 i, ext->sym_idx, ext->kcfg.data_off, ext->name);
		}
		sec->size = off;
		n = btf_vlen(sec);
		for (i = 0; i < n; i++) {
			struct btf_var_secinfo *vs = btf_var_secinfos(sec) + i;

			t = btf__type_by_id(obj->btf, vs->type);
			ext_name = btf__name_by_offset(obj->btf, t->name_off);
			ext = find_extern_by_name(obj, ext_name);
			if (!ext) {
				printf("failed to find extern definition for BTF var '%s'\n",
					ext_name);
				return -ESRCH;
			}
			btf_var(t)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
			vs->offset = ext->kcfg.data_off;
		}
	}
	return 0;
}

static bool prog_is_subprog(const struct bpf_object *obj, const struct bpf_program *prog)
{
	return prog->sec_idx == obj->efile.text_shndx && obj->nr_programs > 1;
}

struct bpf_program *
bpf_object__find_program_by_name(const struct bpf_object *obj,
				 const char *name)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		if (prog_is_subprog(obj, prog))
			continue;
		if (!strcmp(prog->name, name))
			return prog;
	}
	return errno = ENOENT, NULL;
}

static bool bpf_object__shndx_is_data(const struct bpf_object *obj,
				      int shndx)
{
	switch (obj->efile.secs[shndx].sec_type) {
	case SEC_BSS:
	case SEC_DATA:
	case SEC_RODATA:
		return true;
	default:
		return false;
	}
}

static bool bpf_object__shndx_is_maps(const struct bpf_object *obj,
				      int shndx)
{
	return shndx == obj->efile.btf_maps_shndx;
}

static int map_fill_btf_type_info(struct bpf_object *obj, struct bpf_map *map)
{
	int id;

	if (!obj->btf)
		return -ENOENT;

	/* if it's BTF-defined map, we don't need to search for type IDs.
	 * For struct_ops map, it does not need btf_key_type_id and
	 * btf_value_type_id.
	 */
	if (map->sec_idx == obj->efile.btf_maps_shndx || bpf_map__is_struct_ops(map))
		return 0;

	/*
	 * LLVM annotates global data differently in BTF, that is,
	 * only as '.data', '.bss' or '.rodata'.
	 */
	if (!bpf_map__is_internal(map))
		return -ENOENT;

	id = btf__find_by_name(obj->btf, map->real_name);
	if (id < 0)
		return id;

	map->btf_key_type_id = 0;
	map->btf_value_type_id = id;
	return 0;
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

static const struct btf_type *
resolve_func_ptr(const struct btf *btf, __u32 id, __u32 *res_id)
{
	const struct btf_type *t;

	t = skip_mods_and_typedefs(btf, id, NULL);
	if (!btf_is_ptr(t))
		return NULL;

	t = skip_mods_and_typedefs(btf, t->type, res_id);

	return btf_is_func_proto(t) ? t : NULL;
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

static int pathname_concat(char *buf, size_t buf_sz, const char *path, const char *name)
{
	int len;

	len = snprintf(buf, buf_sz, "%s/%s", path, name);
	if (len < 0)
		return -EINVAL;
	if (len >= buf_sz)
		return -ENAMETOOLONG;

	return 0;
}

static int build_map_pin_path(struct bpf_map *map, const char *path)
{
	char buf[PATH_MAX];
	int err;

	if (!path)
		path = "/sys/fs/bpf";

	err = pathname_concat(buf, sizeof(buf), path, bpf_map__name(map));
	if (err)
		return err;

	return bpf_map__set_pin_path(map, buf);
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

static size_t adjust_ringbuf_sz(size_t sz)
{
	__u32 page_sz = sysconf(_SC_PAGE_SIZE);
	__u32 mul;

	/* if user forgot to set any size, make sure they see error */
	if (sz == 0)
		return 0;
	/* Kernel expects BPF_MAP_TYPE_RINGBUF's max_entries to be
	 * a power-of-2 multiple of kernel's page size. If user diligently
	 * satisified these conditions, pass the size through.
	 */
	if ((sz % page_sz) == 0 && is_pow_of_2(sz / page_sz))
		return sz;

	/* Otherwise find closest (page_sz * power_of_2) product bigger than
	 * user-set size to satisfy both user size request and kernel
	 * requirements and substitute correct max_entries for map creation.
	 */
	for (mul = 1; mul <= UINT_MAX / page_sz; mul <<= 1) {
		if (mul * page_sz > sz)
			return mul * page_sz;
	}

	/* if it's impossible to satisfy the conditions (i.e., user size is
	 * very close to UINT_MAX but is not a power-of-2 multiple of
	 * page_size) then just return original size and let kernel reject it
	 */
	return sz;
}

static bool map_is_ringbuf(const struct bpf_map *map)
{
	return map->def.type == BPF_MAP_TYPE_RINGBUF ||
	       map->def.type == BPF_MAP_TYPE_USER_RINGBUF;
}

static void fill_map_from_def(struct bpf_map *map, const struct btf_map_def *def)
{
	map->def.type = def->map_type;
	map->def.key_size = def->key_size;
	map->def.value_size = def->value_size;
	map->def.max_entries = def->max_entries;
	map->def.map_flags = def->map_flags;
	map->map_extra = def->map_extra;

	map->numa_node = def->numa_node;
	map->btf_key_type_id = def->key_type_id;
	map->btf_value_type_id = def->value_type_id;

	/* auto-adjust BPF ringbuf map max_entries to be a multiple of page size */
	if (map_is_ringbuf(map))
		map->def.max_entries = adjust_ringbuf_sz(map->def.max_entries);

	if (def->parts & MAP_DEF_MAP_TYPE)
		pr_debug("map '%s': found type = %u.\n", map->name, def->map_type);

	if (def->parts & MAP_DEF_KEY_TYPE)
		pr_debug("map '%s': found key [%u], sz = %u.\n",
			 map->name, def->key_type_id, def->key_size);
	else if (def->parts & MAP_DEF_KEY_SIZE)
		pr_debug("map '%s': found key_size = %u.\n", map->name, def->key_size);

	if (def->parts & MAP_DEF_VALUE_TYPE)
		pr_debug("map '%s': found value [%u], sz = %u.\n",
			 map->name, def->value_type_id, def->value_size);
	else if (def->parts & MAP_DEF_VALUE_SIZE)
		pr_debug("map '%s': found value_size = %u.\n", map->name, def->value_size);

	if (def->parts & MAP_DEF_MAX_ENTRIES)
		pr_debug("map '%s': found max_entries = %u.\n", map->name, def->max_entries);
	if (def->parts & MAP_DEF_MAP_FLAGS)
		pr_debug("map '%s': found map_flags = 0x%x.\n", map->name, def->map_flags);
	if (def->parts & MAP_DEF_MAP_EXTRA)
		pr_debug("map '%s': found map_extra = 0x%llx.\n", map->name,
			 (unsigned long long)def->map_extra);
	if (def->parts & MAP_DEF_PINNING)
		pr_debug("map '%s': found pinning = %u.\n", map->name, def->pinning);
	if (def->parts & MAP_DEF_NUMA_NODE)
		pr_debug("map '%s': found numa_node = %u.\n", map->name, def->numa_node);

	if (def->parts & MAP_DEF_INNER_MAP)
		pr_debug("map '%s': found inner map definition.\n", map->name);
}

static const char *btf_var_linkage_str(__u32 linkage)
{
	switch (linkage) {
	case BTF_VAR_STATIC: return "static";
	case BTF_VAR_GLOBAL_ALLOCATED: return "global";
	case BTF_VAR_GLOBAL_EXTERN: return "extern";
	default: return "unknown";
	}
}

static int bpf_object__init_user_btf_map(struct bpf_object *obj,
					 const struct btf_type *sec,
					 int var_idx, int sec_idx,
					 const Elf_Data *data, bool strict,
					 const char *pin_root_path)
{
	struct btf_map_def map_def = {}, inner_def = {};
	const struct btf_type *var, *def;
	const struct btf_var_secinfo *vi;
	const struct btf_var *var_extra;
	const char *map_name;
	struct bpf_map *map;
	int err;

	vi = btf_var_secinfos(sec) + var_idx;
	var = btf__type_by_id(obj->btf, vi->type);
	var_extra = btf_var(var);
	map_name = btf__name_by_offset(obj->btf, var->name_off);

	if (map_name == NULL || map_name[0] == '\0') {
		printf("map #%d: empty name.\n", var_idx);
		return -EINVAL;
	}
	if ((__u64)vi->offset + vi->size > data->d_size) {
		printf("map '%s' BTF data is corrupted.\n", map_name);
		return -EINVAL;
	}
	if (!btf_is_var(var)) {
		printf("map '%s': unexpected var kind %s.\n",
			map_name, btf_kind_str(var));
		return -EINVAL;
	}
	if (var_extra->linkage != BTF_VAR_GLOBAL_ALLOCATED) {
		printf("map '%s': unsupported map linkage %s.\n",
			map_name, btf_var_linkage_str(var_extra->linkage));
		return -EOPNOTSUPP;
	}

	def = skip_mods_and_typedefs(obj->btf, var->type, NULL);
	if (!btf_is_struct(def)) {
		printf("map '%s': unexpected def kind %s.\n",
			map_name, btf_kind_str(var));
		return -EINVAL;
	}
	if (def->size > vi->size) {
		printf("map '%s': invalid def size.\n", map_name);
		return -EINVAL;
	}

	map = bpf_object__add_map(obj);
	if (IS_ERR(map))
		return PTR_ERR(map);
	map->name = strdup(map_name);
	if (!map->name) {
		printf("map '%s': failed to alloc map name.\n", map_name);
		return -ENOMEM;
	}
	map->libbpf_type = LIBBPF_MAP_UNSPEC;
	map->def.type = BPF_MAP_TYPE_UNSPEC;
	map->sec_idx = sec_idx;
	map->sec_offset = vi->offset;
	map->btf_var_idx = var_idx;
	pr_debug("map '%s': at sec_idx %d, offset %zu.\n",
		 map_name, map->sec_idx, map->sec_offset);

	err = parse_btf_map_def(map->name, obj->btf, def, strict, &map_def, &inner_def);
	if (err)
		return err;

	fill_map_from_def(map, &map_def);

	if (map_def.pinning == LIBBPF_PIN_BY_NAME) {
		err = build_map_pin_path(map, pin_root_path);
		if (err) {
			printf("map '%s': couldn't build pin path.\n", map->name);
			return err;
		}
	}

	if (map_def.parts & MAP_DEF_INNER_MAP) {
		map->inner_map = calloc(1, sizeof(*map->inner_map));
		if (!map->inner_map)
			return -ENOMEM;
		map->inner_map->fd = -1;
		map->inner_map->sec_idx = sec_idx;
		map->inner_map->name = malloc(strlen(map_name) + sizeof(".inner") + 1);
		if (!map->inner_map->name)
			return -ENOMEM;
		sprintf(map->inner_map->name, "%s.inner", map_name);

		fill_map_from_def(map->inner_map, &inner_def);
	}

	err = map_fill_btf_type_info(obj, map);
	if (err)
		return err;

	return 0;
}

static int bpf_object__init_user_btf_maps(struct bpf_object *obj, bool strict,
					  const char *pin_root_path)
{
	const struct btf_type *sec = NULL;
	int nr_types, i, vlen, err;
	const struct btf_type *t;
	const char *name;
	Elf_Data *data;
	Elf_Scn *scn;

	if (obj->efile.btf_maps_shndx < 0)
		return 0;

	/**
	 * 获取.map的section header
	 */
	scn = elf_sec_by_idx(obj, obj->efile.btf_maps_shndx);
	/**
	 * 获取.map的section data
	 */
	data = elf_sec_data(obj, scn);
	if (!scn || !data) {
		printf("elf: failed to get %s map definitions for %s\n",
			MAPS_ELF_SEC, obj->path);
		return -EINVAL;
	}

	nr_types = btf__type_cnt(obj->btf);
	for (i = 1; i < nr_types; i++) {
		t = btf__type_by_id(obj->btf, i);
		if (!btf_is_datasec(t))
			continue;
		name = btf__name_by_offset(obj->btf, t->name_off);
		if (strcmp(name, MAPS_ELF_SEC) == 0) {
			sec = t;
			obj->efile.btf_maps_sec_btf_id = i;
			break;
		}
	}

	if (!sec) {
		printf("DATASEC '%s' not found.\n", MAPS_ELF_SEC);
		return -ENOENT;
	}

	vlen = btf_vlen(sec);
	for (i = 0; i < vlen; i++) {
		err = bpf_object__init_user_btf_map(obj, sec, i,
						    obj->efile.btf_maps_shndx,
						    data, strict,
						    pin_root_path);
		if (err)
			return err;
	}

	return 0;
}

static int bpf_object__init_maps(struct bpf_object *obj,
				 const struct bpf_object_open_opts *opts)
{
	const char *pin_root_path;
	bool strict;
	int err = 0;

	strict = !OPTS_GET(opts, relaxed_maps, false);
	pin_root_path = OPTS_GET(opts, pin_root_path, NULL);

	err = bpf_object__init_user_btf_maps(obj, strict, pin_root_path);
	err = err ?: bpf_object__init_global_data_maps(obj);
	err = err ?: bpf_object__init_kconfig_map(obj);
	err = err ?: bpf_object_init_struct_ops(obj);

	return err;
}

static enum libbpf_map_type
bpf_object__section_to_libbpf_map_type(const struct bpf_object *obj, int shndx)
{
	if (shndx == obj->efile.symbols_shndx)
		return LIBBPF_MAP_KCONFIG;

	switch (obj->efile.secs[shndx].sec_type) {
	case SEC_BSS:
		return LIBBPF_MAP_BSS;
	case SEC_DATA:
		return LIBBPF_MAP_DATA;
	case SEC_RODATA:
		return LIBBPF_MAP_RODATA;
	default:
		return LIBBPF_MAP_UNSPEC;
	}
}

static int bpf_program__record_reloc(struct bpf_program *prog,
				     struct reloc_desc *reloc_desc,
				     __u32 insn_idx, const char *sym_name,
				     const Elf64_Sym *sym, const Elf64_Rel *rel)
{
	struct bpf_insn *insn = &prog->insns[insn_idx];
	size_t map_idx, nr_maps = prog->obj->nr_maps;
	struct bpf_object *obj = prog->obj;
	__u32 shdr_idx = sym->st_shndx;
	enum libbpf_map_type type;
	const char *sym_sec_name;
	struct bpf_map *map;

	if (!is_call_insn(insn) && !is_ldimm64_insn(insn)) {
		printf("prog '%s': invalid relo against '%s' for insns[%d].code 0x%x\n",
			prog->name, sym_name, insn_idx, insn->code);
		return -LIBBPF_ERRNO__RELOC;
	}

	if (sym_is_extern(sym)) {
		int sym_idx = ELF64_R_SYM(rel->r_info);
		int i, n = obj->nr_extern;
		struct extern_desc *ext;

		for (i = 0; i < n; i++) {
			ext = &obj->externs[i];
			if (ext->sym_idx == sym_idx)
				break;
		}
		if (i >= n) {
			printf("prog '%s': extern relo failed to find extern for '%s' (%d)\n",
				prog->name, sym_name, sym_idx);
			return -LIBBPF_ERRNO__RELOC;
		}
		printf("prog '%s': found extern #%d '%s' (sym %d) for insn #%u\n",
			 prog->name, i, ext->name, ext->sym_idx, insn_idx);
		if (insn->code == (BPF_JMP | BPF_CALL))
			reloc_desc->type = RELO_EXTERN_CALL;
		else
			reloc_desc->type = RELO_EXTERN_LD64;
		reloc_desc->insn_idx = insn_idx;
		reloc_desc->ext_idx = i;
		return 0;
	}

	/* sub-program call relocation */
	if (is_call_insn(insn)) {
		if (insn->src_reg != BPF_PSEUDO_CALL) {
			printf("prog '%s': incorrect bpf_call opcode\n", prog->name);
			return -LIBBPF_ERRNO__RELOC;
		}
		/* text_shndx can be 0, if no default "main" program exists */
		if (!shdr_idx || shdr_idx != obj->efile.text_shndx) {
			sym_sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, shdr_idx));
			printf("prog '%s': bad call relo against '%s' in section '%s'\n",
				prog->name, sym_name, sym_sec_name);
			return -LIBBPF_ERRNO__RELOC;
		}
		if (sym->st_value % BPF_INSN_SZ) {
			printf("prog '%s': bad call relo against '%s' at offset %zu\n",
				prog->name, sym_name, (size_t)sym->st_value);
			return -LIBBPF_ERRNO__RELOC;
		}
		reloc_desc->type = RELO_CALL;
		reloc_desc->insn_idx = insn_idx;
		reloc_desc->sym_off = sym->st_value;
		return 0;
	}

	if (!shdr_idx || shdr_idx >= SHN_LORESERVE) {
		printf("prog '%s': invalid relo against '%s' in special section 0x%x; forgot to initialize global var?..\n",
			prog->name, sym_name, shdr_idx);
		return -LIBBPF_ERRNO__RELOC;
	}

	/* loading subprog addresses */
	if (sym_is_subprog(sym, obj->efile.text_shndx)) {
		/* global_func: sym->st_value = offset in the section, insn->imm = 0.
		 * local_func: sym->st_value = 0, insn->imm = offset in the section.
		 */
		if ((sym->st_value % BPF_INSN_SZ) || (insn->imm % BPF_INSN_SZ)) {
			printf("prog '%s': bad subprog addr relo against '%s' at offset %zu+%d\n",
				prog->name, sym_name, (size_t)sym->st_value, insn->imm);
			return -LIBBPF_ERRNO__RELOC;
		}

		reloc_desc->type = RELO_SUBPROG_ADDR;
		reloc_desc->insn_idx = insn_idx;
		reloc_desc->sym_off = sym->st_value;
		return 0;
	}

	type = bpf_object__section_to_libbpf_map_type(obj, shdr_idx);
	sym_sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, shdr_idx));

	/* generic map reference relocation */
	if (type == LIBBPF_MAP_UNSPEC) {
		if (!bpf_object__shndx_is_maps(obj, shdr_idx)) {
			printf("prog '%s': bad map relo against '%s' in section '%s'\n",
				prog->name, sym_name, sym_sec_name);
			return -LIBBPF_ERRNO__RELOC;
		}
		for (map_idx = 0; map_idx < nr_maps; map_idx++) {
			map = &obj->maps[map_idx];
			if (map->libbpf_type != type ||
			    map->sec_idx != sym->st_shndx ||
			    map->sec_offset != sym->st_value)
				continue;
			pr_debug("prog '%s': found map %zd (%s, sec %d, off %zu) for insn #%u\n",
				 prog->name, map_idx, map->name, map->sec_idx,
				 map->sec_offset, insn_idx);
			break;
		}
		if (map_idx >= nr_maps) {
			pr_warn("prog '%s': map relo failed to find map for section '%s', off %zu\n",
				prog->name, sym_sec_name, (size_t)sym->st_value);
			return -LIBBPF_ERRNO__RELOC;
		}
		reloc_desc->type = RELO_LD64;
		reloc_desc->insn_idx = insn_idx;
		reloc_desc->map_idx = map_idx;
		reloc_desc->sym_off = 0; /* sym->st_value determines map_idx */
		return 0;
	}

	/* global data map relocation */
	if (!bpf_object__shndx_is_data(obj, shdr_idx)) {
		printf("prog '%s': bad data relo against section '%s'\n",
			prog->name, sym_sec_name);
		return -LIBBPF_ERRNO__RELOC;
	}
	for (map_idx = 0; map_idx < nr_maps; map_idx++) {
		map = &obj->maps[map_idx];
		if (map->libbpf_type != type || map->sec_idx != sym->st_shndx)
			continue;
		pr_debug("prog '%s': found data map %zd (%s, sec %d, off %zu) for insn %u\n",
			 prog->name, map_idx, map->name, map->sec_idx,
			 map->sec_offset, insn_idx);
		break;
	}
	if (map_idx >= nr_maps) {
		printf("prog '%s': data relo failed to find map for section '%s'\n",
			prog->name, sym_sec_name);
		return -LIBBPF_ERRNO__RELOC;
	}

	reloc_desc->type = RELO_DATA;
	reloc_desc->insn_idx = insn_idx;
	reloc_desc->map_idx = map_idx;
	reloc_desc->sym_off = sym->st_value;
	return 0;
}

static bool prog_contains_insn(const struct bpf_program *prog, size_t insn_idx)
{
	return insn_idx >= prog->sec_insn_off &&
	       insn_idx < prog->sec_insn_off + prog->sec_insn_cnt;
}

static struct bpf_program *find_prog_by_sec_insn(const struct bpf_object *obj,
						 size_t sec_idx, size_t insn_idx)
{
	int l = 0, r = obj->nr_programs - 1, m;
	struct bpf_program *prog;

	if (!obj->nr_programs)
		return NULL;

	while (l < r) {
		m = l + (r - l + 1) / 2;
		prog = &obj->programs[m];

		if (prog->sec_idx < sec_idx ||
		    (prog->sec_idx == sec_idx && prog->sec_insn_off <= insn_idx))
			l = m;
		else
			r = m - 1;
	}
	/* matching program could be at index l, but it still might be the
	 * wrong one, so we need to double check conditions for the last time
	 */
	prog = &obj->programs[l];
	if (prog->sec_idx == sec_idx && prog_contains_insn(prog, insn_idx))
		return prog;
	return NULL;
}

static int
bpf_object__collect_prog_relos(struct bpf_object *obj, Elf64_Shdr *shdr, Elf_Data *data)
{
	const char *relo_sec_name, *sec_name;
	size_t sec_idx = shdr->sh_info, sym_idx;
	struct bpf_program *prog;
	struct reloc_desc *relos;
	int err, i, nrels;
	const char *sym_name;
	__u32 insn_idx;
	Elf_Scn *scn;
	Elf_Data *scn_data;
	Elf64_Sym *sym;
	Elf64_Rel *rel;

	if (sec_idx >= obj->efile.sec_cnt)
		return -EINVAL;

	scn = elf_sec_by_idx(obj, sec_idx);
	scn_data = elf_sec_data(obj, scn);

	relo_sec_name = elf_sec_str(obj, shdr->sh_name);
	sec_name = elf_sec_name(obj, scn);
	if (!relo_sec_name || !sec_name)
		return -EINVAL;

	pr_debug("sec '%s': collecting relocation for section(%zu) '%s'\n",
		 relo_sec_name, sec_idx, sec_name);
	nrels = shdr->sh_size / shdr->sh_entsize;

	for (i = 0; i < nrels; i++) {
		rel = elf_rel_by_idx(data, i);
		if (!rel) {
			printf("sec '%s': failed to get relo #%d\n", relo_sec_name, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		sym_idx = ELF64_R_SYM(rel->r_info);
		sym = elf_sym_by_idx(obj, sym_idx);
		if (!sym) {
			printf("sec '%s': symbol #%zu not found for relo #%d\n",
				relo_sec_name, sym_idx, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (sym->st_shndx >= obj->efile.sec_cnt) {
			printf("sec '%s': corrupted symbol #%zu pointing to invalid section #%zu for relo #%d\n",
				relo_sec_name, sym_idx, (size_t)sym->st_shndx, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (rel->r_offset % BPF_INSN_SZ || rel->r_offset >= scn_data->d_size) {
			printf("sec '%s': invalid offset 0x%zx for relo #%d\n",
				relo_sec_name, (size_t)rel->r_offset, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		insn_idx = rel->r_offset / BPF_INSN_SZ;
		/* relocations against static functions are recorded as
		 * relocations against the section that contains a function;
		 * in such case, symbol will be STT_SECTION and sym.st_name
		 * will point to empty string (0), so fetch section name
		 * instead
		 */
		if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION && sym->st_name == 0)
			sym_name = elf_sec_name(obj, elf_sec_by_idx(obj, sym->st_shndx));
		else
			sym_name = elf_sym_str(obj, sym->st_name);
		sym_name = sym_name ?: "<?";

		pr_debug("sec '%s': relo #%d: insn #%u against '%s'\n",
			 relo_sec_name, i, insn_idx, sym_name);

		prog = find_prog_by_sec_insn(obj, sec_idx, insn_idx);
		if (!prog) {
			printf("sec '%s': relo #%d: couldn't find program in section '%s' for insn #%u, probably overridden weak function, skipping...\n",
				relo_sec_name, i, sec_name, insn_idx);
			continue;
		}

		relos = libbpf_reallocarray(prog->reloc_desc,
					    prog->nr_reloc + 1, sizeof(*relos));
		if (!relos)
			return -ENOMEM;
		prog->reloc_desc = relos;

		/* adjust insn_idx to local BPF program frame of reference */
		insn_idx -= prog->sec_insn_off;
		err = bpf_program__record_reloc(prog, &relos[prog->nr_reloc],
						insn_idx, sym_name, sym, rel);
		if (err)
			return err;

		prog->nr_reloc++;
	}
	return 0;
}

static bool bpf_core_is_flavor_sep(const char *s)
{
	/* check X___Y name pattern, where X and Y are not underscores */
	return s[0] != '_' &&				      /* X */
	       s[1] == '_' && s[2] == '_' && s[3] == '_' &&   /* ___ */
	       s[4] != '_';				      /* Y */
}

/* Given 'some_struct_name___with_flavor' return the length of a name prefix
 * before last triple underscore. Struct name part after last triple
 * underscore is ignored by BPF CO-RE relocation during relocation matching.
 */
size_t bpf_core_essential_name_len(const char *name)
{
	size_t n = strlen(name);
	int i;

	for (i = n - 5; i >= 0; i--) {
		if (bpf_core_is_flavor_sep(name + i))
			return i + 1;
	}
	return n;
}

static int cmp_relocs(const void *_a, const void *_b)
{
	const struct reloc_desc *a = _a;
	const struct reloc_desc *b = _b;

	if (a->insn_idx != b->insn_idx)
		return a->insn_idx < b->insn_idx ? -1 : 1;

	/* no two relocations should have the same insn_idx, but ... */
	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;

	return 0;
}

static void bpf_object__sort_relos(struct bpf_object *obj)
{
	int i;

	for (i = 0; i < obj->nr_programs; i++) {
		struct bpf_program *p = &obj->programs[i];

		if (!p->nr_reloc)
			continue;

		qsort(p->reloc_desc, p->nr_reloc, sizeof(*p->reloc_desc), cmp_relocs);
	}
}

static const struct bpf_sec_def *find_sec_def(const char *sec_name);

static int bpf_object_init_progs(struct bpf_object *obj, const struct bpf_object_open_opts *opts)
{
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, obj) {
		prog->sec_def = find_sec_def(prog->sec_name);
		if (!prog->sec_def) {
			/* couldn't guess, but user might manually specify */
			pr_debug("prog '%s': unrecognized ELF section name '%s'\n",
				prog->name, prog->sec_name);
			continue;
		}

		prog->type = prog->sec_def->prog_type;
		prog->expected_attach_type = prog->sec_def->expected_attach_type;

		/* sec_def can have custom callback which should be called
		 * after bpf_program is initialized to adjust its properties
		 */
		if (prog->sec_def->prog_setup_fn) {
			err = prog->sec_def->prog_setup_fn(prog, prog->sec_def->cookie);
			if (err < 0) {
				printf("prog '%s': failed to initialize: %d\n",
					prog->name, err);
				return err;
			}
		}
	}

	return 0;
}

static int bpf_object__collect_st_ops_relos(struct bpf_object *obj,
					    Elf64_Shdr *shdr, Elf_Data *data);

static int bpf_object__collect_map_relos(struct bpf_object *obj,
					 Elf64_Shdr *shdr, Elf_Data *data)
{
	const int bpf_ptr_sz = 8, host_ptr_sz = sizeof(void *);
	int i, j, nrels, new_sz;
	const struct btf_var_secinfo *vi = NULL;
	const struct btf_type *sec, *var, *def;
	struct bpf_map *map = NULL, *targ_map = NULL;
	struct bpf_program *targ_prog = NULL;
	bool is_prog_array, is_map_in_map;
	const struct btf_member *member;
	const char *name, *mname, *type;
	unsigned int moff;
	Elf64_Sym *sym;
	Elf64_Rel *rel;
	void *tmp;

	if (!obj->efile.btf_maps_sec_btf_id || !obj->btf)
		return -EINVAL;
	sec = btf__type_by_id(obj->btf, obj->efile.btf_maps_sec_btf_id);
	if (!sec)
		return -EINVAL;

	nrels = shdr->sh_size / shdr->sh_entsize;
	for (i = 0; i < nrels; i++) {
		rel = elf_rel_by_idx(data, i);
		if (!rel) {
			printf(".maps relo #%d: failed to get ELF relo\n", i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		sym = elf_sym_by_idx(obj, ELF64_R_SYM(rel->r_info));
		if (!sym) {
			printf(".maps relo #%d: symbol %zx not found\n",
				i, (size_t)ELF64_R_SYM(rel->r_info));
			return -LIBBPF_ERRNO__FORMAT;
		}
		name = elf_sym_str(obj, sym->st_name) ?: "<?>";

		printf(".maps relo #%d: for %zd value %zd rel->r_offset %zu name %d ('%s')\n",
			 i, (ssize_t)(rel->r_info >> 32), (size_t)sym->st_value,
			 (size_t)rel->r_offset, sym->st_name, name);

		for (j = 0; j < obj->nr_maps; j++) {
			map = &obj->maps[j];
			if (map->sec_idx != obj->efile.btf_maps_shndx)
				continue;

			vi = btf_var_secinfos(sec) + map->btf_var_idx;
			if (vi->offset <= rel->r_offset &&
			    rel->r_offset + bpf_ptr_sz <= vi->offset + vi->size)
				break;
		}
		if (j == obj->nr_maps) {
			printf(".maps relo #%d: cannot find map '%s' at rel->r_offset %zu\n",
				i, name, (size_t)rel->r_offset);
			return -EINVAL;
		}

		is_map_in_map = bpf_map_type__is_map_in_map(map->def.type);
		is_prog_array = map->def.type == BPF_MAP_TYPE_PROG_ARRAY;
		type = is_map_in_map ? "map" : "prog";
		if (is_map_in_map) {
			if (sym->st_shndx != obj->efile.btf_maps_shndx) {
				printf(".maps relo #%d: '%s' isn't a BTF-defined map\n",
					i, name);
				return -LIBBPF_ERRNO__RELOC;
			}
			if (map->def.type == BPF_MAP_TYPE_HASH_OF_MAPS &&
			    map->def.key_size != sizeof(int)) {
				printf(".maps relo #%d: hash-of-maps '%s' should have key size %zu.\n",
					i, map->name, sizeof(int));
				return -EINVAL;
			}
			targ_map = bpf_object__find_map_by_name(obj, name);
			if (!targ_map) {
				printf(".maps relo #%d: '%s' isn't a valid map reference\n",
					i, name);
				return -ESRCH;
			}
		} else if (is_prog_array) {
			targ_prog = bpf_object__find_program_by_name(obj, name);
			if (!targ_prog) {
				printf(".maps relo #%d: '%s' isn't a valid program reference\n",
					i, name);
				return -ESRCH;
			}
			if (targ_prog->sec_idx != sym->st_shndx ||
			    targ_prog->sec_insn_off * 8 != sym->st_value ||
			    prog_is_subprog(obj, targ_prog)) {
				printf(".maps relo #%d: '%s' isn't an entry-point program\n",
					i, name);
				return -LIBBPF_ERRNO__RELOC;
			}
		} else {
			return -EINVAL;
		}

		var = btf__type_by_id(obj->btf, vi->type);
		def = skip_mods_and_typedefs(obj->btf, var->type, NULL);
		if (btf_vlen(def) == 0)
			return -EINVAL;
		member = btf_members(def) + btf_vlen(def) - 1;
		mname = btf__name_by_offset(obj->btf, member->name_off);
		if (strcmp(mname, "values"))
			return -EINVAL;

		moff = btf_member_bit_offset(def, btf_vlen(def) - 1) / 8;
		if (rel->r_offset - vi->offset < moff)
			return -EINVAL;

		moff = rel->r_offset - vi->offset - moff;
		/* here we use BPF pointer size, which is always 64 bit, as we
		 * are parsing ELF that was built for BPF target
		 */
		if (moff % bpf_ptr_sz)
			return -EINVAL;
		moff /= bpf_ptr_sz;
		if (moff >= map->init_slots_sz) {
			new_sz = moff + 1;
			tmp = libbpf_reallocarray(map->init_slots, new_sz, host_ptr_sz);
			if (!tmp)
				return -ENOMEM;
			map->init_slots = tmp;
			memset(map->init_slots + map->init_slots_sz, 0,
			       (new_sz - map->init_slots_sz) * host_ptr_sz);
			map->init_slots_sz = new_sz;
		}
		map->init_slots[moff] = is_map_in_map ? (void *)targ_map : (void *)targ_prog;

		printf(".maps relo #%d: map '%s' slot [%d] points to %s '%s'\n",
			 i, map->name, moff, type, name);
	}

	return 0;
}

static int bpf_object__collect_relos(struct bpf_object *obj)
{
	int i, err;

	for (i = 0; i < obj->efile.sec_cnt; i++) {
		struct elf_sec_desc *sec_desc = &obj->efile.secs[i];
		Elf64_Shdr *shdr;
		Elf_Data *data;
		int idx;

		if (sec_desc->sec_type != SEC_RELO)
			continue;

		shdr = sec_desc->shdr;
		data = sec_desc->data;
		idx = shdr->sh_info;

		if (shdr->sh_type != SHT_REL) {
			printf("internal error at %d\n", __LINE__);
			return -LIBBPF_ERRNO__INTERNAL;
		}

		if (idx == obj->efile.st_ops_shndx || idx == obj->efile.st_ops_link_shndx) {
			err = bpf_object__collect_st_ops_relos(obj, shdr, data);
		} else if (idx == obj->efile.btf_maps_shndx) {
			err = bpf_object__collect_map_relos(obj, shdr, data);
		} else {
			err = bpf_object__collect_prog_relos(obj, shdr, data);
		}
		if (err)
			return err;
	}

	bpf_object__sort_relos(obj);
	return 0;
}

static struct bpf_object *bpf_object_open(const char *path, const void *obj_buf, size_t obj_buf_sz,
					  const struct bpf_object_open_opts *opts)
{
	const char *obj_name, *kconfig, *btf_tmp_path;
	struct bpf_object *obj;
	char tmp_name[64];
	char err;
	char *log_buf;
	size_t log_size;
	__u32 log_level;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("failed to inint libelf for %s\n", path ? path : "mem buf");
		return ERR_PTR(-LIBBPF_ERRNO__LIBELF);
	}

	if (!OPTS_VALID(opts, bpf_object_open_opts))
		return ERR_PTR(-EINVAL);

	obj_name = OPTS_GET(opts, object_name, NULL);
	if (obj_buf) {
		if (!obj_name) {
			snprintf(tmp_name, sizeof(tmp_name), "%lx-%lx",
				 (unsigned long)obj_buf,
				 (unsigned long)obj_buf_sz);
		}
		path = obj_name;
		pr_debug("loading object '%s' from buffer\n", obj_name);
	}

	log_buf = OPTS_GET(opts, kernel_log_buf, NULL);
	log_size = OPTS_GET(opts, kernel_log_size, 0);
	log_level = OPTS_GET(opts, kernel_log_level, 0);
	if (log_size > UINT_MAX)
		return ERR_PTR(-EINVAL);
	if (log_size && !log_buf)
		return ERR_PTR(-EINVAL);
	
	/**
	 * 创建并初始化一个bpf_object对象
	 */
	obj = bpf_object__new(path, obj_buf, obj_buf_sz, obj_name);
	if (IS_ERR(obj))
		return obj;

	/**
	 * 初始化log相关内容
	 */
	obj->log_buf = log_buf;
	obj->log_size = log_size;
	obj->log_level = log_level;

	btf_tmp_path = OPTS_GET(opts, btf_custom_path, NULL);
	if (btf_tmp_path) {
		if (strlen(btf_tmp_path) >= PATH_MAX) {
			err = -ENAMETOOLONG;
			goto out;
		}
		obj->btf_custom_path = strdup(btf_tmp_path);
		if (!obj->btf_custom_path) {
			err = -ENOMEM;
			goto out;
		}
	}

	kconfig = OPTS_GET(opts, kconfig, NULL);
	if (kconfig) {
		obj->kconfig = strdup(kconfig);
		if (!obj->kconfig) {
			err = -ENOMEM;
			goto out;
		}
	}

	err = bpf_object__elf_init(obj);
	err = err ? : bpf_object__check_endianness(obj);
	err = err ? : bpf_object__elf_collect(obj);
	err = err ? : bpf_object__collect_externs(obj);
	err = err ? : bpf_object_fixup_btf(obj);
	err = err ? : bpf_object__init_maps(obj, opts);
	err = err ? : bpf_object_init_progs(obj, opts);
	err = err ? : bpf_object__collect_relos(obj);
	if (err)
		goto out;

	bpf_object__elf_finish(obj);

	return obj;
out:
	bpf_object__close(obj);
	return ERR_PTR(err);
}

struct bpf_object *
bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
		     const struct bpf_object_open_opts *opts)
{
	if (!obj_buf || obj_buf_sz == 0)
		return libbpf_err_ptr(-EINVAL);

	return libbpf_ptr(bpf_object_open(NULL, obj_buf, obj_buf_sz, opts));
}

static int bpf_object_unload(struct bpf_object *obj)
{
	size_t i;

	if (!obj)
		return libbpf_err(-EINVAL);

	for (i = 0; i < obj->nr_maps; i++) {
		zclose(obj->maps[i].fd);
		if (obj->maps[i].st_ops)
			zfree(&obj->maps[i].st_ops->kern_vdata);
	}

	for (i = 0; i < obj->nr_programs; i++)
		bpf_program__unload(&obj->programs[i]);

	return 0;
}

int bpf_map__set_pin_path(struct bpf_map *map, const char *path)
{
	char *new = NULL;

	if (path) {
		new = strdup(path);
		if (!new)
			return libbpf_err(-errno);
	}

	free(map->pin_path);
	map->pin_path = new;
	return 0;
}

static void bpf_map__destroy(struct bpf_map *map)
{
	if (map->inner_map) {
		bpf_map__destroy(map->inner_map);
		zfree(&map->inner_map);
	}

	zfree(&map->init_slots);
	map->init_slots_sz = 0;

	if (map->mmaped) {
		size_t mmap_sz;

		mmap_sz = bpf_map_mmap_sz(map->def.value_size, map->def.max_entries);
		munmap(map->mmaped, mmap_sz);
		map->mmaped = NULL;
	}

	if (map->st_ops) {
		zfree(&map->st_ops->data);
		zfree(&map->st_ops->progs);
		zfree(&map->st_ops->kern_func_off);
		zfree(&map->st_ops);
	}

	zfree(&map->name);
	zfree(&map->real_name);
	zfree(&map->pin_path);

	if (map->fd >= 0)
		zclose(map->fd);
}

void bpf_object__close(struct bpf_object *obj)
{
	size_t i;

	if (IS_ERR_OR_NULL(obj))
		return;

	usdt_manager_free(obj->usdt_man);
	obj->usdt_man = NULL;

	bpf_gen__free(obj->gen_loader);
	bpf_object__elf_finish(obj);
	bpf_object_unload(obj);
	btf__free(obj->btf);
	btf__free(obj->btf_vmlinux);
	btf_ext__free(obj->btf_ext);

	for (i = 0; i < obj->nr_maps; i++)
		bpf_map__destroy(&obj->maps[i]);

	zfree(&obj->btf_custom_path);
	zfree(&obj->kconfig);

	for (i = 0; i < obj->nr_extern; i++)
		zfree(&obj->externs[i].essent_name);

	zfree(&obj->externs);
	obj->nr_extern = 0;

	zfree(&obj->maps);
	obj->nr_maps = 0;

	if (obj->programs && obj->nr_programs) {
		for (i = 0; i < obj->nr_programs; i++)
			bpf_program__exit(&obj->programs[i]);
	}
	zfree(&obj->programs);

	free(obj);
}

const char *bpf_object__name(const struct bpf_object *obj)
{
	return obj ? obj->name : libbpf_err_ptr(-EINVAL);
}

unsigned int bpf_object__kversion(const struct bpf_object *obj)
{
	return obj ? obj->kern_version : 0;
}

struct btf *bpf_object__btf(const struct bpf_object *obj)
{
	return obj ? obj->btf : NULL;
}

int bpf_object__set_kversion(struct bpf_object *obj, __u32 kern_version)
{
	if (obj->loaded)
		return libbpf_err(-EINVAL);

	obj->kern_version = kern_version;

	return 0;
}

int bpf_object__gen_loader(struct bpf_object *obj, struct gen_loader_opts *opts)
{
	struct bpf_gen *gen;

	if (!opts)
		return -EFAULT;
	if (!OPTS_VALID(opts, gen_loader_opts))
		return -EINVAL;
	gen = calloc(sizeof(*gen), 1);
	if (!gen)
		return -ENOMEM;
	gen->opts = opts;
	obj->gen_loader = gen;
	return 0;
}

static struct bpf_program *
__bpf_program__iter(const struct bpf_program *p, const struct bpf_object *obj,
		    bool forward)
{
	size_t nr_programs = obj->nr_programs;
	ssize_t idx;

	if (!nr_programs)
		return NULL;

	if (!p)
		/* Iter from the beginning */
		return forward ? &obj->programs[0] :
			&obj->programs[nr_programs - 1];

	if (p->obj != obj) {
		printf("error: program handler doesn't match object\n");
		return errno = EINVAL, NULL;
	}

	idx = (p - obj->programs) + (forward ? 1 : -1);
	if (idx >= obj->nr_programs || idx < 0)
		return NULL;
	return &obj->programs[idx];
}

struct bpf_program *
bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prev)
{
	struct bpf_program *prog = prev;

	do {
		prog = __bpf_program__iter(prog, obj, true);
	} while (prog && prog_is_subprog(obj, prog));

	return prog;
}

const char *bpf_program__name(const struct bpf_program *prog)
{
	return prog->name;
}

const char *bpf_program__section_name(const struct bpf_program *prog)
{
	return prog->sec_name;
}

static bool map_uses_real_name(const struct bpf_map *map)
{
	/* Since libbpf started to support custom .data.* and .rodata.* maps,
	 * their user-visible name differs from kernel-visible name. Users see
	 * such map's corresponding ELF section name as a map name.
	 * This check distinguishes .data/.rodata from .data.* and .rodata.*
	 * maps to know which name has to be returned to the user.
	 */
	if (map->libbpf_type == LIBBPF_MAP_DATA && strcmp(map->real_name, DATA_SEC) != 0)
		return true;
	if (map->libbpf_type == LIBBPF_MAP_RODATA && strcmp(map->real_name, RODATA_SEC) != 0)
		return true;
	return false;
}

const char *bpf_map__name(const struct bpf_map *map)
{
	if (!map)
		return NULL;

	if (map_uses_real_name(map))
		return map->real_name;

	return map->name;
}

bool bpf_map__is_internal(const struct bpf_map *map)
{
	return map->libbpf_type != LIBBPF_MAP_UNSPEC;
}

#define SEC_DEF(sec_pfx, ptype, atype, flags, ...) {			    \
	.sec = (char *)sec_pfx,						    \
	.prog_type = BPF_PROG_TYPE_##ptype,				    \
	.expected_attach_type = atype,					    \
	.cookie = (long)(flags),					    \
	.prog_prepare_load_fn = libbpf_prepare_prog_load,		    \
	__VA_ARGS__							    \
}

static const struct bpf_sec_def section_defs[] = {
	// SEC_DEF("socket",		SOCKET_FILTER, 0, SEC_NONE),
	// SEC_DEF("sk_reuseport/migrate",	SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, SEC_ATTACHABLE),
	// SEC_DEF("sk_reuseport",		SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT, SEC_ATTACHABLE),
	// SEC_DEF("kprobe+",		KPROBE,	0, SEC_NONE, attach_kprobe),
	// SEC_DEF("uprobe+",		KPROBE,	0, SEC_NONE, attach_uprobe),
	// SEC_DEF("uprobe.s+",		KPROBE,	0, SEC_SLEEPABLE, attach_uprobe),
	// SEC_DEF("kretprobe+",		KPROBE, 0, SEC_NONE, attach_kprobe),
	// SEC_DEF("uretprobe+",		KPROBE, 0, SEC_NONE, attach_uprobe),
	// SEC_DEF("uretprobe.s+",		KPROBE, 0, SEC_SLEEPABLE, attach_uprobe),
	// SEC_DEF("kprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
	// SEC_DEF("kretprobe.multi+",	KPROBE,	BPF_TRACE_KPROBE_MULTI, SEC_NONE, attach_kprobe_multi),
	// SEC_DEF("uprobe.multi+",	KPROBE,	BPF_TRACE_UPROBE_MULTI, SEC_NONE, attach_uprobe_multi),
	// SEC_DEF("uretprobe.multi+",	KPROBE,	BPF_TRACE_UPROBE_MULTI, SEC_NONE, attach_uprobe_multi),
	// SEC_DEF("uprobe.multi.s+",	KPROBE,	BPF_TRACE_UPROBE_MULTI, SEC_SLEEPABLE, attach_uprobe_multi),
	// SEC_DEF("uretprobe.multi.s+",	KPROBE,	BPF_TRACE_UPROBE_MULTI, SEC_SLEEPABLE, attach_uprobe_multi),
	// SEC_DEF("ksyscall+",		KPROBE,	0, SEC_NONE, attach_ksyscall),
	// SEC_DEF("kretsyscall+",		KPROBE, 0, SEC_NONE, attach_ksyscall),
	// SEC_DEF("usdt+",		KPROBE,	0, SEC_USDT, attach_usdt),
	// SEC_DEF("usdt.s+",		KPROBE,	0, SEC_USDT | SEC_SLEEPABLE, attach_usdt),
	// SEC_DEF("tc/ingress",		SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE), /* alias for tcx */
	// SEC_DEF("tc/egress",		SCHED_CLS, BPF_TCX_EGRESS, SEC_NONE),  /* alias for tcx */
	// SEC_DEF("tcx/ingress",		SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE),
	// SEC_DEF("tcx/egress",		SCHED_CLS, BPF_TCX_EGRESS, SEC_NONE),
	// SEC_DEF("tc",			SCHED_CLS, 0, SEC_NONE), /* deprecated / legacy, use tcx */
	// SEC_DEF("classifier",		SCHED_CLS, 0, SEC_NONE), /* deprecated / legacy, use tcx */
	// SEC_DEF("action",		SCHED_ACT, 0, SEC_NONE), /* deprecated / legacy, use tcx */
	// SEC_DEF("tracepoint+",		TRACEPOINT, 0, SEC_NONE, attach_tp),
	// SEC_DEF("tp+",			TRACEPOINT, 0, SEC_NONE, attach_tp),
	// SEC_DEF("raw_tracepoint+",	RAW_TRACEPOINT, 0, SEC_NONE, attach_raw_tp),
	// SEC_DEF("raw_tp+",		RAW_TRACEPOINT, 0, SEC_NONE, attach_raw_tp),
	// SEC_DEF("raw_tracepoint.w+",	RAW_TRACEPOINT_WRITABLE, 0, SEC_NONE, attach_raw_tp),
	// SEC_DEF("raw_tp.w+",		RAW_TRACEPOINT_WRITABLE, 0, SEC_NONE, attach_raw_tp),
	// SEC_DEF("tp_btf+",		TRACING, BPF_TRACE_RAW_TP, SEC_ATTACH_BTF, attach_trace),
	// SEC_DEF("fentry+",		TRACING, BPF_TRACE_FENTRY, SEC_ATTACH_BTF, attach_trace),
	// SEC_DEF("fmod_ret+",		TRACING, BPF_MODIFY_RETURN, SEC_ATTACH_BTF, attach_trace),
	// SEC_DEF("fexit+",		TRACING, BPF_TRACE_FEXIT, SEC_ATTACH_BTF, attach_trace),
	// SEC_DEF("fentry.s+",		TRACING, BPF_TRACE_FENTRY, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
	// SEC_DEF("fmod_ret.s+",		TRACING, BPF_MODIFY_RETURN, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
	// SEC_DEF("fexit.s+",		TRACING, BPF_TRACE_FEXIT, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_trace),
	// SEC_DEF("freplace+",		EXT, 0, SEC_ATTACH_BTF, attach_trace),
	// SEC_DEF("lsm+",			LSM, BPF_LSM_MAC, SEC_ATTACH_BTF, attach_lsm),
	// SEC_DEF("lsm.s+",		LSM, BPF_LSM_MAC, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_lsm),
	// SEC_DEF("lsm_cgroup+",		LSM, BPF_LSM_CGROUP, SEC_ATTACH_BTF),
	// SEC_DEF("iter+",		TRACING, BPF_TRACE_ITER, SEC_ATTACH_BTF, attach_iter),
	// SEC_DEF("iter.s+",		TRACING, BPF_TRACE_ITER, SEC_ATTACH_BTF | SEC_SLEEPABLE, attach_iter),
	// SEC_DEF("syscall",		SYSCALL, 0, SEC_SLEEPABLE),
	// SEC_DEF("xdp.frags/devmap",	XDP, BPF_XDP_DEVMAP, SEC_XDP_FRAGS),
	// SEC_DEF("xdp/devmap",		XDP, BPF_XDP_DEVMAP, SEC_ATTACHABLE),
	// SEC_DEF("xdp.frags/cpumap",	XDP, BPF_XDP_CPUMAP, SEC_XDP_FRAGS),
	// SEC_DEF("xdp/cpumap",		XDP, BPF_XDP_CPUMAP, SEC_ATTACHABLE),
	// SEC_DEF("xdp.frags",		XDP, BPF_XDP, SEC_XDP_FRAGS),
	// SEC_DEF("xdp",			XDP, BPF_XDP, SEC_ATTACHABLE_OPT),
	// SEC_DEF("perf_event",		PERF_EVENT, 0, SEC_NONE),
	// SEC_DEF("lwt_in",		LWT_IN, 0, SEC_NONE),
	// SEC_DEF("lwt_out",		LWT_OUT, 0, SEC_NONE),
	// SEC_DEF("lwt_xmit",		LWT_XMIT, 0, SEC_NONE),
	// SEC_DEF("lwt_seg6local",	LWT_SEG6LOCAL, 0, SEC_NONE),
	// SEC_DEF("sockops",		SOCK_OPS, BPF_CGROUP_SOCK_OPS, SEC_ATTACHABLE_OPT),
	// SEC_DEF("sk_skb/stream_parser",	SK_SKB, BPF_SK_SKB_STREAM_PARSER, SEC_ATTACHABLE_OPT),
	// SEC_DEF("sk_skb/stream_verdict",SK_SKB, BPF_SK_SKB_STREAM_VERDICT, SEC_ATTACHABLE_OPT),
	// SEC_DEF("sk_skb",		SK_SKB, 0, SEC_NONE),
	// SEC_DEF("sk_msg",		SK_MSG, BPF_SK_MSG_VERDICT, SEC_ATTACHABLE_OPT),
	// SEC_DEF("lirc_mode2",		LIRC_MODE2, BPF_LIRC_MODE2, SEC_ATTACHABLE_OPT),
	// SEC_DEF("flow_dissector",	FLOW_DISSECTOR, BPF_FLOW_DISSECTOR, SEC_ATTACHABLE_OPT),
	// SEC_DEF("cgroup_skb/ingress",	CGROUP_SKB, BPF_CGROUP_INET_INGRESS, SEC_ATTACHABLE_OPT),
	// SEC_DEF("cgroup_skb/egress",	CGROUP_SKB, BPF_CGROUP_INET_EGRESS, SEC_ATTACHABLE_OPT),
	// SEC_DEF("cgroup/skb",		CGROUP_SKB, 0, SEC_NONE),
	// SEC_DEF("cgroup/sock_create",	CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sock_release",	CGROUP_SOCK, BPF_CGROUP_INET_SOCK_RELEASE, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sock",		CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE, SEC_ATTACHABLE_OPT),
	// SEC_DEF("cgroup/post_bind4",	CGROUP_SOCK, BPF_CGROUP_INET4_POST_BIND, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/post_bind6",	CGROUP_SOCK, BPF_CGROUP_INET6_POST_BIND, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/bind4",		CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_BIND, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/bind6",		CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_BIND, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/connect4",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/connect6",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/connect_unix",	CGROUP_SOCK_ADDR, BPF_CGROUP_UNIX_CONNECT, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sendmsg4",	CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sendmsg6",	CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sendmsg_unix",	CGROUP_SOCK_ADDR, BPF_CGROUP_UNIX_SENDMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/recvmsg4",	CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/recvmsg6",	CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/recvmsg_unix",	CGROUP_SOCK_ADDR, BPF_CGROUP_UNIX_RECVMSG, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getpeername4",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETPEERNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getpeername6",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_GETPEERNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getpeername_unix", CGROUP_SOCK_ADDR, BPF_CGROUP_UNIX_GETPEERNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getsockname4",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETSOCKNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getsockname6",	CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_GETSOCKNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getsockname_unix", CGROUP_SOCK_ADDR, BPF_CGROUP_UNIX_GETSOCKNAME, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/sysctl",	CGROUP_SYSCTL, BPF_CGROUP_SYSCTL, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/getsockopt",	CGROUP_SOCKOPT, BPF_CGROUP_GETSOCKOPT, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/setsockopt",	CGROUP_SOCKOPT, BPF_CGROUP_SETSOCKOPT, SEC_ATTACHABLE),
	// SEC_DEF("cgroup/dev",		CGROUP_DEVICE, BPF_CGROUP_DEVICE, SEC_ATTACHABLE_OPT),
	// SEC_DEF("struct_ops+",		STRUCT_OPS, 0, SEC_NONE),
	// SEC_DEF("struct_ops.s+",	STRUCT_OPS, 0, SEC_SLEEPABLE),
	// SEC_DEF("sk_lookup",		SK_LOOKUP, BPF_SK_LOOKUP, SEC_ATTACHABLE),
	// SEC_DEF("netfilter",		NETFILTER, BPF_NETFILTER, SEC_NONE),
};

enum bpf_prog_type bpf_program__type(const struct bpf_program *prog)
{
	return prog->type;
}

static size_t custom_sec_def_cnt;
static struct bpf_sec_def *custom_sec_defs;
static struct bpf_sec_def custom_fallback_def;
static bool has_custom_fallback_def;
static int last_custom_sec_def_handler_id;

enum bpf_attach_type bpf_program__expected_attach_type(const struct bpf_program *prog)
{
	return prog->expected_attach_type;
}

static bool sec_def_matches(const struct bpf_sec_def *sec_def, const char *sec_name)
{
	size_t len = strlen(sec_def->sec);

	/* "type/" always has to have proper SEC("type/extras") form */
	if (sec_def->sec[len - 1] == '/') {
		if (str_has_pfx(sec_name, sec_def->sec))
			return true;
		return false;
	}

	/* "type+" means it can be either exact SEC("type") or
	 * well-formed SEC("type/extras") with proper '/' separator
	 */
	if (sec_def->sec[len - 1] == '+') {
		len--;
		/* not even a prefix */
		if (strncmp(sec_name, sec_def->sec, len) != 0)
			return false;
		/* exact match or has '/' separator */
		if (sec_name[len] == '\0' || sec_name[len] == '/')
			return true;
		return false;
	}

	return strcmp(sec_name, sec_def->sec) == 0;
}

static const struct bpf_sec_def *find_sec_def(const char *sec_name)
{
	const struct bpf_sec_def *sec_def;
	int i, n;

	n = custom_sec_def_cnt;
	for (i = 0; i < n; i++) {
		sec_def = &custom_sec_defs[i];
		if (sec_def_matches(sec_def, sec_name))
			return sec_def;
	}

	n = ARRAY_SIZE(section_defs);
	for (i = 0; i < n; i++) {
		sec_def = &section_defs[i];
		if (sec_def_matches(sec_def, sec_name))
			return sec_def;
	}

	if (has_custom_fallback_def)
		return &custom_fallback_def;

	return NULL;
}

static struct bpf_map *find_struct_ops_map_by_offset(struct bpf_object *obj,
						     int sec_idx,
						     size_t offset)
{
	struct bpf_map *map;
	size_t i;

	for (i = 0; i < obj->nr_maps; i++) {
		map = &obj->maps[i];
		if (!bpf_map__is_struct_ops(map))
			continue;
		if (map->sec_idx == sec_idx &&
		    map->sec_offset <= offset &&
		    offset - map->sec_offset < map->def.value_size)
			return map;
	}

	return NULL;
}

/* Collect the reloc from ELF and populate the st_ops->progs[] */
static int bpf_object__collect_st_ops_relos(struct bpf_object *obj,
					    Elf64_Shdr *shdr, Elf_Data *data)
{
	const struct btf_member *member;
	struct bpf_struct_ops *st_ops;
	struct bpf_program *prog;
	unsigned int shdr_idx;
	const struct btf *btf;
	struct bpf_map *map;
	unsigned int moff, insn_idx;
	const char *name;
	__u32 member_idx;
	Elf64_Sym *sym;
	Elf64_Rel *rel;
	int i, nrels;

	btf = obj->btf;
	nrels = shdr->sh_size / shdr->sh_entsize;
	for (i = 0; i < nrels; i++) {
		rel = elf_rel_by_idx(data, i);
		if (!rel) {
			printf("struct_ops reloc: failed to get %d reloc\n", i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		sym = elf_sym_by_idx(obj, ELF64_R_SYM(rel->r_info));
		if (!sym) {
			printf("struct_ops reloc: symbol %zx not found\n",
				(size_t)ELF64_R_SYM(rel->r_info));
			return -LIBBPF_ERRNO__FORMAT;
		}

		name = elf_sym_str(obj, sym->st_name) ?: "<?>";
		map = find_struct_ops_map_by_offset(obj, shdr->sh_info, rel->r_offset);
		if (!map) {
			printf("struct_ops reloc: cannot find map at rel->r_offset %zu\n",
				(size_t)rel->r_offset);
			return -EINVAL;
		}

		moff = rel->r_offset - map->sec_offset;
		shdr_idx = sym->st_shndx;
		st_ops = map->st_ops;
		printf("struct_ops reloc %s: for %lld value %lld shdr_idx %u rel->r_offset %zu map->sec_offset %zu name %d (\'%s\')\n",
			 map->name,
			 (long long)(rel->r_info >> 32),
			 (long long)sym->st_value,
			 shdr_idx, (size_t)rel->r_offset,
			 map->sec_offset, sym->st_name, name);

		if (shdr_idx >= SHN_LORESERVE) {
			printf("struct_ops reloc %s: rel->r_offset %zu shdr_idx %u unsupported non-static function\n",
				map->name, (size_t)rel->r_offset, shdr_idx);
			return -LIBBPF_ERRNO__RELOC;
		}
		if (sym->st_value % BPF_INSN_SZ) {
			printf("struct_ops reloc %s: invalid target program offset %llu\n",
				map->name, (unsigned long long)sym->st_value);
			return -LIBBPF_ERRNO__FORMAT;
		}
		insn_idx = sym->st_value / BPF_INSN_SZ;

		member = find_member_by_offset(st_ops->type, moff * 8);
		if (!member) {
			printf("struct_ops reloc %s: cannot find member at moff %u\n",
				map->name, moff);
			return -EINVAL;
		}
		member_idx = member - btf_members(st_ops->type);
		name = btf__name_by_offset(btf, member->name_off);

		if (!resolve_func_ptr(btf, member->type, NULL)) {
			printf("struct_ops reloc %s: cannot relocate non func ptr %s\n",
				map->name, name);
			return -EINVAL;
		}

		prog = find_prog_by_sec_insn(obj, shdr_idx, insn_idx);
		if (!prog) {
			printf("struct_ops reloc %s: cannot find prog at shdr_idx %u to relocate func ptr %s\n",
				map->name, shdr_idx, name);
			return -EINVAL;
		}

		/* prevent the use of BPF prog with invalid type */
		if (prog->type != BPF_PROG_TYPE_STRUCT_OPS) {
			printf("struct_ops reloc %s: prog %s is not struct_ops BPF program\n",
				map->name, prog->name);
			return -EINVAL;
		}

		/* if we haven't yet processed this BPF program, record proper
		 * attach_btf_id and member_idx
		 */
		if (!prog->attach_btf_id) {
			prog->attach_btf_id = st_ops->type_id;
			prog->expected_attach_type = member_idx;
		}

		/* struct_ops BPF prog can be re-used between multiple
		 * .struct_ops & .struct_ops.link as long as it's the
		 * same struct_ops struct definition and the same
		 * function pointer field
		 */
		if (prog->attach_btf_id != st_ops->type_id ||
		    prog->expected_attach_type != member_idx) {
			printf("struct_ops reloc %s: cannot use prog %s in sec %s with type %u attach_btf_id %u expected_attach_type %u for func ptr %s\n",
				map->name, prog->name, prog->sec_name, prog->type,
				prog->attach_btf_id, prog->expected_attach_type, name);
			return -EINVAL;
		}

		st_ops->progs[member_idx] = prog;
	}

	return 0;
}

#define BTF_TRACE_PREFIX "btf_trace_"
#define BTF_LSM_PREFIX "bpf_lsm_"
#define BTF_ITER_PREFIX "bpf_iter_"
#define BTF_MAX_NAME_SIZE 128

static int find_btf_by_prefix_kind(const struct btf *btf, const char *prefix,
				   const char *name, __u32 kind)
{
	char btf_type_name[BTF_MAX_NAME_SIZE];
	int ret;

	ret = snprintf(btf_type_name, sizeof(btf_type_name),
		       "%s%s", prefix, name);
	/* snprintf returns the number of characters written excluding the
	 * terminating null. So, if >= BTF_MAX_NAME_SIZE are written, it
	 * indicates truncation.
	 */
	if (ret < 0 || ret >= sizeof(btf_type_name))
		return -ENAMETOOLONG;
	return btf__find_by_name_kind(btf, btf_type_name, kind);
}

/**
 * __bpf_map_iter - 在obj->maps中，返回从m开始之后的第i个map
 */
static struct bpf_map *
__bpf_map__iter(const struct bpf_map *m, const struct bpf_object *obj, int i)
{
	ssize_t idx;
	struct bpf_map *s, *e;

	if (!obj || !obj->maps)
		return errno = EINVAL, NULL;

	/**
	 * 获取maps起始地址和结束地址
	 */
	s = obj->maps;
	e = obj->maps + obj->nr_maps;

	/**
	 * 若m不在maps地址范围内，保存错误码并返回NULL
	 */
	if ((m < s) || (m >= e)) {
		printf("error in %s: map handler doesn't belong to object\n",
			 __func__);
		return errno = EINVAL, NULL;
	}

	/**
	 * 计算目标map的索引，并返回目标map地址
	 */
	idx = (m - obj->maps) + i;
	if (idx >= obj->nr_maps || idx < 0)
		return NULL;
	return &obj->maps[idx];
}

struct bpf_map *
bpf_object__next_map(const struct bpf_object *obj, const struct bpf_map *prev)
{
	/**
	 * prev为NULL，返回maps首地址
	 */
	if (prev == NULL)
		return obj->maps;

	/**
	 * 返回prev的下一个map
	 */
	return __bpf_map__iter(prev, obj, 1);
}

struct bpf_map *
bpf_object__prev_map(const struct bpf_object *obj, const struct bpf_map *next)
{
	if (next == NULL) {
		if (!obj->nr_maps)
			return NULL;
		return obj->maps + obj->nr_maps - 1;
	}

	return __bpf_map__iter(next, obj, -1);
}

struct bpf_map *
bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name)
{
	struct bpf_map *pos;

	bpf_object__for_each_map(pos, obj) {
		/* if it's a special internal map name (which always starts
		 * with dot) then check if that special name matches the
		 * real map name (ELF section name)
		 */
		if (name[0] == '.') {
			if (pos->real_name && strcmp(pos->real_name, name) == 0)
				return pos;
			continue;
		}
		/* otherwise map name has to be an exact match */
		if (map_uses_real_name(pos)) {
			if (strcmp(pos->real_name, name) == 0)
				return pos;
			continue;
		}
		if (strcmp(pos->name, name) == 0)
			return pos;
	}
	return errno = ENOENT, NULL;
}

__u32 bpf_map__max_entries(const struct bpf_map *map)
{
	return map->def.max_entries;
}

__u32 bpf_map__map_flags(const struct bpf_map *map)
{
	return map->def.map_flags;
}

__u32 bpf_map__value_size(const struct bpf_map *map)
{
	return map->def.value_size;
}
