#ifndef _LIBBPF_H
#define _LIBBPF_H

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

#endif /* _LIBBPF_H  */
