#ifndef _BTF_H
#define _BTF_H

#include <stdarg.h>
#include <stdbool.h>
#include <linux/btf.h>
// #include "include/uapi/linux/btf.h"
#include <linux/types.h>

#define BTF_ELF_SEC ".BTF"
#define BTF_EXT_ELF_SEC ".BTF.ext"
#define MAPS_ELF_SEC ".maps"

struct btf;

/**
 * @brief **btf__free()** frees all data of a BTF object
 * @param btf BTF object to free
 */
void btf__free(struct btf *btf);

/**
 * @brief **btf__new()** creates a new instance of a BTF object from the raw
 * bytes of an ELF's BTF section
 * @param data raw bytes
 * @param size number of bytes passed in `data`
 * @return new BTF object instance which has to be eventually freed with
 * **btf__free()**
 *
 * On error, error-code-encoded-as-pointer is returned, not a NULL. To extract
 * error code from such a pointer `libbpf_get_error()` should be used. If
 * `libbpf_set_strict_mode(LIBBPF_STRICT_CLEAN_PTRS)` is enabled, NULL is
 * returned on error instead. In both cases thread-local `errno` variable is
 * always set to error code as well.
 */
struct btf *btf__new(const void *data, __u32 size);

/**
 * @brief **btf__new_empty()** creates an empty BTF object.  Use
 * `btf__add_*()` to populate such BTF object.
 * @return new BTF object instance which has to be eventually freed with
 * **btf__free()**
 *
 * On error, error-code-encoded-as-pointer is returned, not a NULL. To extract
 * error code from such a pointer `libbpf_get_error()` should be used. If
 * `libbpf_set_strict_mode(LIBBPF_STRICT_CLEAN_PTRS)` is enabled, NULL is
 * returned on error instead. In both cases thread-local `errno` variable is
 * always set to error code as well.
 */
struct btf *btf__new_empty(void);

__u32 btf__type_cnt(const struct btf *btf);
const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id);
__s64 btf__resolve_size(const struct btf *btf, __u32 type_id);
const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
const char *btf__str_by_offset(const struct btf *btf, __u32 offset);

struct btf_ext *btf_ext__new(const __u8 *data, __u32 size);
void btf_ext__free(struct btf_ext *btf_ext);

int btf__add_str(struct btf *btf, const char *s);
int btf__add_type(struct btf *btf, const struct btf *src_btf,
			     const struct btf_type *src_type);

/*
 * A set of helpers for easier BTF types handling.
 *
 * The inline functions below rely on constants from the kernel headers which
 * may not be available for applications including this header file. To avoid
 * compilation errors, we define all the constants here that were added after
 * the initial introduction of the BTF_KIND* constants.
 */
#ifndef BTF_KIND_FUNC
#define BTF_KIND_FUNC		12	/* Function	*/
#define BTF_KIND_FUNC_PROTO	13	/* Function Proto	*/
#endif
#ifndef BTF_KIND_VAR
#define BTF_KIND_VAR		14	/* Variable	*/
#define BTF_KIND_DATASEC	15	/* Section	*/
#endif
#ifndef BTF_KIND_FLOAT
#define BTF_KIND_FLOAT		16	/* Floating point	*/
#endif
/* The kernel header switched to enums, so the following were never #defined */
#define BTF_KIND_DECL_TAG	17	/* Decl Tag */
#define BTF_KIND_TYPE_TAG	18	/* Type Tag */
#define BTF_KIND_ENUM64		19	/* Enum for up-to 64bit values */

static inline __u16 btf_kind(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info);
}

static inline __u16 btf_vlen(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

static inline bool btf_kflag(const struct btf_type *t)
{
	return BTF_INFO_KFLAG(t->info);
}

static inline bool btf_is_void(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_UNKN;
}

static inline bool btf_is_int(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_INT;
}

static inline bool btf_is_ptr(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_PTR;
}

static inline bool btf_is_array(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_ARRAY;
}

static inline bool btf_is_struct(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_STRUCT;
}

static inline bool btf_is_union(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_UNION;
}

static inline bool btf_is_composite(const struct btf_type *t)
{
	__u16 kind = btf_kind(t);

	return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION;
}

static inline bool btf_is_enum(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_ENUM;
}

static inline bool btf_is_enum64(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_ENUM64;
}

static inline bool btf_is_fwd(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FWD;
}

static inline bool btf_is_typedef(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_TYPEDEF;
}

static inline bool btf_is_volatile(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_VOLATILE;
}

static inline bool btf_is_const(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_CONST;
}

static inline bool btf_is_restrict(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_RESTRICT;
}

static inline bool btf_is_mod(const struct btf_type *t)
{
	__u16 kind = btf_kind(t);

	return kind == BTF_KIND_VOLATILE ||
	       kind == BTF_KIND_CONST ||
	       kind == BTF_KIND_RESTRICT ||
	       kind == BTF_KIND_TYPE_TAG;
}

static inline bool btf_is_func(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FUNC;
}

static inline bool btf_is_func_proto(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FUNC_PROTO;
}

static inline bool btf_is_var(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_VAR;
}

static inline bool btf_is_datasec(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_DATASEC;
}

static inline bool btf_is_float(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FLOAT;
}

static inline bool btf_is_decl_tag(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_DECL_TAG;
}

static inline bool btf_is_type_tag(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_TYPE_TAG;
}

static inline bool btf_is_any_enum(const struct btf_type *t)
{
	return btf_is_enum(t) || btf_is_enum64(t);
}

static inline bool btf_kind_core_compat(const struct btf_type *t1,
					const struct btf_type *t2)
{
	return btf_kind(t1) == btf_kind(t2) ||
	       (btf_is_any_enum(t1) && btf_is_any_enum(t2));
}

static inline __u8 btf_int_encoding(const struct btf_type *t)
{
	return BTF_INT_ENCODING(*(__u32 *)(t + 1));
}

static inline __u8 btf_int_offset(const struct btf_type *t)
{
	return BTF_INT_OFFSET(*(__u32 *)(t + 1));
}

static inline __u8 btf_int_bits(const struct btf_type *t)
{
	return BTF_INT_BITS(*(__u32 *)(t + 1));
}

static inline struct btf_array *btf_array(const struct btf_type *t)
{
	return (struct btf_array *)(t + 1);
}

static inline struct btf_enum *btf_enum(const struct btf_type *t)
{
	return (struct btf_enum *)(t + 1);
}

struct btf_enum64;

static inline struct btf_enum64 *btf_enum64(const struct btf_type *t)
{
	return (struct btf_enum64 *)(t + 1);
}

static inline __u64 btf_enum64_value(const struct btf_enum64 *e)
{
	/* struct btf_enum64 is introduced in Linux 6.0, which is very
	 * bleeding-edge. Here we are avoiding relying on struct btf_enum64
	 * definition coming from kernel UAPI headers to support wider range
	 * of system-wide kernel headers.
	 *
	 * Given this header can be also included from C++ applications, that
	 * further restricts C tricks we can use (like using compatible
	 * anonymous struct). So just treat struct btf_enum64 as
	 * a three-element array of u32 and access second (lo32) and third
	 * (hi32) elements directly.
	 *
	 * For reference, here is a struct btf_enum64 definition:
	 *
	 * const struct btf_enum64 {
	 *	__u32	name_off;
	 *	__u32	val_lo32;
	 *	__u32	val_hi32;
	 * };
	 */
	const __u32 *e64 = (const __u32 *)e;

	return ((__u64)e64[2] << 32) | e64[1];
}

static inline struct btf_member *btf_members(const struct btf_type *t)
{
	return (struct btf_member *)(t + 1);
}

/* Get bit offset of a member with specified index. */
static inline __u32 btf_member_bit_offset(const struct btf_type *t,
					  __u32 member_idx)
{
	const struct btf_member *m = btf_members(t) + member_idx;
	bool kflag = btf_kflag(t);

	return kflag ? BTF_MEMBER_BIT_OFFSET(m->offset) : m->offset;
}
/*
 * Get bitfield size of a member, assuming t is BTF_KIND_STRUCT or
 * BTF_KIND_UNION. If member is not a bitfield, zero is returned.
 */
static inline __u32 btf_member_bitfield_size(const struct btf_type *t,
					     __u32 member_idx)
{
	const struct btf_member *m = btf_members(t) + member_idx;
	bool kflag = btf_kflag(t);

	return kflag ? BTF_MEMBER_BITFIELD_SIZE(m->offset) : 0;
}

static inline struct btf_param *btf_params(const struct btf_type *t)
{
	return (struct btf_param *)(t + 1);
}

static inline struct btf_var *btf_var(const struct btf_type *t)
{
	return (struct btf_var *)(t + 1);
}

static inline struct btf_var_secinfo *
btf_var_secinfos(const struct btf_type *t)
{
	return (struct btf_var_secinfo *)(t + 1);
}

struct btf_decl_tag;
static inline struct btf_decl_tag *btf_decl_tag(const struct btf_type *t)
{
	return (struct btf_decl_tag *)(t + 1);
}

#endif /* _BTF_H */
