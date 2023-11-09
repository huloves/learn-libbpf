#ifndef _LIBBPF_H
#define _LIBBPF_H

struct bpf_linker_opts {
	/* size of this struct, for forward/backward compatibility */
	size_t sz;
};

struct bpf_linker;

struct bpf_linker *bpf_linker__new(const char *filename, struct bpf_linker_opts *opts);

#endif /* _LIBBPF_H  */
