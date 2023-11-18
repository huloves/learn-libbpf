#ifndef _LIBBPF_LEGACY_H
#define _LIBBPF_LEGACY_H

long libbpf_get_error(const void *ptr);

const void *btf__get_raw_data(const struct btf *btf, __u32 *size);
const void *btf_ext__get_raw_data(const struct btf_ext *btf_ext, __u32 *size);

#endif /* _LIBBPF_LEGACY_H */
