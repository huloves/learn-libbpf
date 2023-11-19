#ifndef _LIBBPF_H
#define _LIBBPF_H

#include <stdarg.h>

#include "include/uapi/linux/bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

enum libbpf_errno {
	__LIBBPF_ERRNO__START = 4000,
	__LIBBPF_ERRNO__END,
};

enum libbpf_print_level {
        LIBBPF_WARN,
        LIBBPF_INFO,
        LIBBPF_DEBUG,
};

typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level,
				 const char *, va_list ap);

/* Accessors of bpf_program */
struct bpf_program;
struct bpf_link;

struct bpf_map;

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
