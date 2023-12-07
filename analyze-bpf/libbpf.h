#ifndef _LIBBPF_H
#define _LIBBPF_H

#include <stdarg.h>

#include "include/uapi/linux/bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

enum libbpf_errno {
	__LIBBPF_ERRNO__START = 4000,

	/* Something wrong in libelf */
	LIBBPF_ERRNO__LIBELF = __LIBBPF_ERRNO__START,
	LIBBPF_ERRNO__FORMAT,	/* BPF object format invalid */
	LIBBPF_ERRNO__KVERSION,	/* Incorrect or no 'version' section */
	LIBBPF_ERRNO__ENDIAN,	/* Endian mismatch */
	LIBBPF_ERRNO__INTERNAL,	/* Internal error in libbpf */
	LIBBPF_ERRNO__RELOC,	/* Relocation failed */
	LIBBPF_ERRNO__LOAD,	/* Load program failure for unknown reason */
	LIBBPF_ERRNO__VERIFY,	/* Kernel verifier blocks program loading */
	LIBBPF_ERRNO__PROG2BIG,	/* Program too big */
	LIBBPF_ERRNO__KVER,	/* Incorrect kernel version */
	LIBBPF_ERRNO__PROGTYPE,	/* Kernel doesn't support this program type */
	LIBBPF_ERRNO__WRNGPID,	/* Wrong pid in netlink message */
	LIBBPF_ERRNO__INVSEQ,	/* Invalid netlink sequence */
	LIBBPF_ERRNO__NLPARSE,	/* netlink parsing error */
	__LIBBPF_ERRNO__END,
};

enum libbpf_print_level {
        LIBBPF_WARN,
        LIBBPF_INFO,
        LIBBPF_DEBUG,
};

typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level,
				 const char *, va_list ap);

/* Hide internal to user */
struct bpf_object;

struct bpf_object_open_opts {
	/* size of this struct, for forward/backward compatibility */
	size_t sz;
	/* object name override, if provided:
	 * - for object open from file, this will override setting object
	 *   name from file path's base name;
	 * - for object open from memory buffer, this will specify an object
	 *   name and will override default "<addr>-<buf-size>" name;
	 */
	const char *object_name;
	/* parse map definitions non-strictly, allowing extra attributes/data */
	bool relaxed_maps;
	/* maps that set the 'pinning' attribute in their definition will have
	 * their pin_path attribute set to a file in this directory, and be
	 * auto-pinned to that path on load; defaults to "/sys/fs/bpf".
	 */
	const char *pin_root_path;

	__u32 :32; /* stub out now removed attach_prog_fd */

	/* Additional kernel config content that augments and overrides
	 * system Kconfig for CONFIG_xxx externs.
	 */
	const char *kconfig;
	/* Path to the custom BTF to be used for BPF CO-RE relocations.
	 * This custom BTF completely replaces the use of vmlinux BTF
	 * for the purpose of CO-RE relocations.
	 * NOTE: any other BPF feature (e.g., fentry/fexit programs,
	 * struct_ops, etc) will need actual kernel BTF at /sys/kernel/btf/vmlinux.
	 */
	const char *btf_custom_path;
	/* Pointer to a buffer for storing kernel logs for applicable BPF
	 * commands. Valid kernel_log_size has to be specified as well and are
	 * passed-through to bpf() syscall. Keep in mind that kernel might
	 * fail operation with -ENOSPC error if provided buffer is too small
	 * to contain entire log output.
	 * See the comment below for kernel_log_level for interaction between
	 * log_buf and log_level settings.
	 *
	 * If specified, this log buffer will be passed for:
	 *   - each BPF progral load (BPF_PROG_LOAD) attempt, unless overriden
	 *     with bpf_program__set_log() on per-program level, to get
	 *     BPF verifier log output.
	 *   - during BPF object's BTF load into kernel (BPF_BTF_LOAD) to get
	 *     BTF sanity checking log.
	 *
	 * Each BPF command (BPF_BTF_LOAD or BPF_PROG_LOAD) will overwrite
	 * previous contents, so if you need more fine-grained control, set
	 * per-program buffer with bpf_program__set_log_buf() to preserve each
	 * individual program's verification log. Keep using kernel_log_buf
	 * for BTF verification log, if necessary.
	 */
	char *kernel_log_buf;
	size_t kernel_log_size;
	/*
	 * Log level can be set independently from log buffer. Log_level=0
	 * means that libbpf will attempt loading BTF or program without any
	 * logging requested, but will retry with either its own or custom log
	 * buffer, if provided, and log_level=1 on any error.
	 * And vice versa, setting log_level>0 will request BTF or prog
	 * loading with verbose log from the first attempt (and as such also
	 * for successfully loaded BTF or program), and the actual log buffer
	 * could be either libbpf's own auto-allocated log buffer, if
	 * kernel_log_buffer is NULL, or user-provided custom kernel_log_buf.
	 * If user didn't provide custom log buffer, libbpf will emit captured
	 * logs through its print callback.
	 */
	__u32 kernel_log_level;

	size_t :0;
};
#define bpf_object_open_opts__last_field kernel_log_level

/**
 * @brief **bpf_object__open_mem()** creates a bpf_object by reading
 * the BPF objects raw bytes from a memory buffer containing a valid
 * BPF ELF object file.
 * @param obj_buf pointer to the buffer containing ELF file bytes
 * @param obj_buf_sz number of bytes in the buffer
 * @param opts options for how to load the bpf object
 * @return pointer to the new bpf_object; or NULL is returned on error,
 * error code is stored in errno
 */
struct bpf_object *
bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
		     const struct bpf_object_open_opts *opts);

/* Accessors of bpf_program */
struct bpf_program;

struct bpf_program *
bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prog);

#define bpf_object__for_each_program(pos, obj)			\
	for ((pos) = bpf_object__next_program((obj), NULL);	\
	     (pos) != NULL;					\
	     (pos) = bpf_object__next_program((obj), (pos)))

struct bpf_link;

struct bpf_map;

/* get map name */
const char *bpf_map__name(const struct bpf_map *map);

/**
 * @brief **bpf_map__is_internal()** tells the caller whether or not the
 * passed map is a special map created by libbpf automatically for things like
 * global variables, __ksym externs, Kconfig values, etc
 * @param map the bpf_map
 * @return true, if the map is an internal map; false, otherwise
 */
bool bpf_map__is_internal(const struct bpf_map *map);

/**
 * @brief **bpf_map__set_pin_path()** sets the path attribute that tells where the
 * BPF map should be pinned. This does not actually create the 'pin'.
 * @param map The bpf_map
 * @param path The path
 * @return 0, on success; negative error, otherwise
 */
int bpf_map__set_pin_path(struct bpf_map *map, const char *path);

struct bpf_linker_opts {
	/* size of this struct, for forward/backward compatibility */
	size_t sz;
};
#define bpf_linker_opts__last_field sz

struct bpf_linker_file_opts {
	/* size of this struct, for forward/backward compatibility */
	size_t sz;
};
#define bpf_linker_file_opts__last_field sz

struct bpf_linker;

struct bpf_linker *bpf_linker__new(const char *filename, struct bpf_linker_opts *opts);
int bpf_linker__add_file(struct bpf_linker *linker,
				    const char *filename,
				    const struct bpf_linker_file_opts *opts);
int bpf_linker__finalize(struct bpf_linker *linker);
void bpf_linker__free(struct bpf_linker *linker);

/*
 * Custom handling of BPF program's SEC() definitions
 */

struct bpf_prog_load_opts; /* defined in bpf.h */

/* Called during bpf_object__open() for each recognized BPF program. Callback
 * can use various bpf_program__set_*() setters to adjust whatever properties
 * are necessary.
 */
typedef int (*libbpf_prog_setup_fn_t)(struct bpf_program *prog, long cookie);

/* Called right before libbpf performs bpf_prog_load() to load BPF program
 * into the kernel. Callback can adjust opts as necessary.
 */
typedef int (*libbpf_prog_prepare_load_fn_t)(struct bpf_program *prog,
					     struct bpf_prog_load_opts *opts, long cookie);

/* Called during skeleton attach or through bpf_program__attach(). If
 * auto-attach is not supported, callback should return 0 and set link to
 * NULL (it's not considered an error during skeleton attach, but it will be
 * an error for bpf_program__attach() calls). On error, error should be
 * returned directly and link set to NULL. On success, return 0 and set link
 * to a valid struct bpf_link.
 */
typedef int (*libbpf_prog_attach_fn_t)(const struct bpf_program *prog, long cookie,
				       struct bpf_link **link);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBBPF_H  */
