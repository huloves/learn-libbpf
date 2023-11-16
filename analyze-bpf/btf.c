#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
// #include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <byteswap.h>
#include "btf.h"
#include "libbpf_internal.h"
#include "strset.h"

#include "include/uapi/linux/bpf.h"

#define BTF_MAX_NR_TYPES 0x7fffffffU
#define BTF_MAX_STR_OFFSET 0x7fffffffU

static struct btf_type btf_void;

struct btf {
	/* raw BTF data in native endianness */
	void *raw_data;
	/* raw BTF data in non-native endianness */
	void *raw_data_swapped;
	__u32 raw_size;
	/* whether target endianness differs from the native one */
	bool swapped_endian;

	/*
	 * When BTF is loaded from an ELF or raw memory it is stored
	 * in a contiguous memory block. The hdr, type_data, and, strs_data
	 * point inside that memory region to their respective parts of BTF
	 * representation:
	 *
	 * +--------------------------------+
	 * |  Header  |  Types  |  Strings  |
	 * +--------------------------------+
	 * ^          ^         ^
	 * |          |         |
	 * hdr        |         |
	 * types_data-+         |
	 * strs_data------------+
	 *
	 * If BTF data is later modified, e.g., due to types added or
	 * removed, BTF deduplication performed, etc, this contiguous
	 * representation is broken up into three independently allocated
	 * memory regions to be able to modify them independently.
	 * raw_data is nulled out at that point, but can be later allocated
	 * and cached again if user calls btf__raw_data(), at which point
	 * raw_data will contain a contiguous copy of header, types, and
	 * strings:
	 *
	 * +----------+  +---------+  +-----------+
	 * |  Header  |  |  Types  |  |  Strings  |
	 * +----------+  +---------+  +-----------+
	 * ^             ^            ^
	 * |             |            |
	 * hdr           |            |
	 * types_data----+            |
	 * strset__data(strs_set)-----+
	 *
	 *               +----------+---------+-----------+
	 *               |  Header  |  Types  |  Strings  |
	 * raw_data----->+----------+---------+-----------+
	 */
	struct btf_header *hdr;

	void *types_data;
	size_t types_data_cap; /* used size stored in hdr->type_len */

	/* type ID to `struct btf_type *` lookup index
	 * type_offs[0] corresponds to the first non-VOID type:
	 *   - for base BTF it's type [1];
	 *   - for split BTF it's the first non-base BTF type.
	 */
	__u32 *type_offs;
	size_t type_offs_cap;
	/* number of types in this BTF instance:
	 *   - doesn't include special [0] void type;
	 *   - for split BTF counts number of types added on top of base BTF.
	 */
	__u32 nr_types;
	/* if not NULL, points to the base BTF on top of which the current
	 * split BTF is based
	 */
	struct btf *base_btf;
	/* BTF type ID of the first type in this BTF instance:
	 *   - for base BTF it's equal to 1;
	 *   - for split BTF it's equal to biggest type ID of base BTF plus 1.
	 */
	int start_id;
	/* logical string offset of this BTF instance:
	 *   - for base BTF it's equal to 0;
	 *   - for split BTF it's equal to total size of base BTF's string section size.
	 */
	int start_str_off;

	/* only one of strs_data or strs_set can be non-NULL, depending on
	 * whether BTF is in a modifiable state (strs_set is used) or not
	 * (strs_data points inside raw_data)
	 */
	void *strs_data;
	/* a set of unique strings */
	struct strset *strs_set;
	/* whether strings are already deduplicated */
	bool strs_deduped;

	/* BTF object FD, if loaded into kernel */
	int fd;

	/* Pointer size (in bytes) for a target architecture of this BTF */
	int ptr_sz;
};

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

/* Ensure given dynamically allocated memory region pointed to by *data* with
 * capacity of *cap_cnt* elements each taking *elem_sz* bytes has enough
 * memory to accommodate *add_cnt* new elements, assuming *cur_cnt* elements
 * are already used. At most *max_cnt* elements can be ever allocated.
 * If necessary, memory is reallocated and all existing data is copied over,
 * new pointer to the memory region is stored at *data, new memory region
 * capacity (in number of elements) is stored in *cap.
 * On success, memory pointer to the beginning of unused memory is returned.
 * On error, NULL is returned.
 */
void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt)
{
	size_t new_cnt;
	void *new_data;

	if (cur_cnt + add_cnt <= *cap_cnt)
		return *data + cur_cnt * elem_sz;

	/* requested more than the set limit */
	if (cur_cnt + add_cnt > max_cnt)
		return NULL;

	new_cnt = *cap_cnt;
	new_cnt += new_cnt / 4;		  /* expand by 25% */
	if (new_cnt < 16)		  /* but at least 16 elements */
		new_cnt = 16;
	if (new_cnt > max_cnt)		  /* but not exceeding a set limit */
		new_cnt = max_cnt;
	if (new_cnt < cur_cnt + add_cnt)  /* also ensure we have enough memory */
		new_cnt = cur_cnt + add_cnt;

	new_data = libbpf_reallocarray(*data, new_cnt, elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

/* Ensure given dynamically allocated memory region has enough allocated space
 * to accommodate *need_cnt* elements of size *elem_sz* bytes each
 */
int libbpf_ensure_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t need_cnt)
{
	void *p;

	if (need_cnt <= *cap_cnt)
		return 0;

	p = libbpf_add_mem(data, cap_cnt, elem_sz, *cap_cnt, SIZE_MAX, need_cnt - *cap_cnt);
	if (!p)
		return -ENOMEM;

	return 0;
}

static void *btf_add_type_offs_mem(struct btf *btf, size_t add_cnt)
{
	return libbpf_add_mem((void **)&btf->type_offs, &btf->type_offs_cap, sizeof(__u32),
			      btf->nr_types, BTF_MAX_NR_TYPES, add_cnt);
}

static int btf_add_type_idx_entry(struct btf *btf, __u32 type_off)
{
	__u32 *p;

	p = btf_add_type_offs_mem(btf, 1);
	if (!p)
		return -ENOMEM;

	*p = type_off;
	return 0;
}

static void btf_bswap_hdr(struct btf_header *h)
{
	h->magic = bswap_16(h->magic);
	h->hdr_len = bswap_32(h->hdr_len);
	h->type_off = bswap_32(h->type_off);
	h->type_len = bswap_32(h->type_len);
	h->str_off = bswap_32(h->str_off);
	h->str_len = bswap_32(h->str_len);
}

/**
 * btf_parse_hdr - 解析btf header
 */
static int btf_parse_hdr(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		printf("BTF header not found\n");
		return -EINVAL;
	}

	/**
	 * 判断btf目标字节序是否与本地字节序不同
	 */
	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		/**
		 * 记录目标字节序与本地字节序不同
		 */
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			printf("Can't load BTF with non-native endianness due to unsupported header length %u\n",
				bswap_32(hdr->hdr_len));
			return -ENOTSUP;
		}
		/**
		 * 将btf头部信息的字节序转换为本地字节序
		 */
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		printf("Invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		printf("BTF header len %u larger than data size %u\n",
			 hdr->hdr_len, btf->raw_size);
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		printf("Invalid BTF total size: %u\n", btf->raw_size);
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		printf("Invalid BTF data sections layout: type data at %u + %u, strings data at %u + %u\n",
			 hdr->type_off, hdr->type_len, hdr->str_off, hdr->str_len);
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		printf("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * btf_parse_str_sec - 解析string section
 */
static int btf_parse_str_sec(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	const char *start = btf->strs_data;
	const char *end = start + btf->hdr->str_len;

	if (btf->base_btf && hdr->str_len == 0)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_STR_OFFSET || end[-1]) {
		printf("Invalid BTF string section\n");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		printf("Invalid BTF string section\n");
		return -EINVAL;
	}
	return 0;
}

static int btf_type_size(const struct btf_type *t)
{
	const int base_size = sizeof(struct btf_type);
	__u16 vlen = btf_vlen(t);

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(__u32);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ENUM64:
		return base_size + vlen * sizeof(struct btf_enum64);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	case BTF_KIND_VAR:
		return base_size + sizeof(struct btf_var);
	case BTF_KIND_DATASEC:
		return base_size + vlen * sizeof(struct btf_var_secinfo);
	case BTF_KIND_DECL_TAG:
		return base_size + sizeof(struct btf_decl_tag);
	default:
		printf("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static void btf_bswap_type_base(struct btf_type *t)
{
	t->name_off = bswap_32(t->name_off);
	t->info = bswap_32(t->info);
	t->type = bswap_32(t->type);
}

static int btf_bswap_type_rest(struct btf_type *t)
{
	struct btf_var_secinfo *v;
	struct btf_enum64 *e64;
	struct btf_member *m;
	struct btf_array *a;
	struct btf_param *p;
	struct btf_enum *e;
	__u16 vlen = btf_vlen(t);
	int i;

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return 0;
	case BTF_KIND_INT:
		*(__u32 *)(t + 1) = bswap_32(*(__u32 *)(t + 1));
		return 0;
	case BTF_KIND_ENUM:
		for (i = 0, e = btf_enum(t); i < vlen; i++, e++) {
			e->name_off = bswap_32(e->name_off);
			e->val = bswap_32(e->val);
		}
		return 0;
	case BTF_KIND_ENUM64:
		for (i = 0, e64 = btf_enum64(t); i < vlen; i++, e64++) {
			e64->name_off = bswap_32(e64->name_off);
			e64->val_lo32 = bswap_32(e64->val_lo32);
			e64->val_hi32 = bswap_32(e64->val_hi32);
		}
		return 0;
	case BTF_KIND_ARRAY:
		a = btf_array(t);
		a->type = bswap_32(a->type);
		a->index_type = bswap_32(a->index_type);
		a->nelems = bswap_32(a->nelems);
		return 0;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		for (i = 0, m = btf_members(t); i < vlen; i++, m++) {
			m->name_off = bswap_32(m->name_off);
			m->type = bswap_32(m->type);
			m->offset = bswap_32(m->offset);
		}
		return 0;
	case BTF_KIND_FUNC_PROTO:
		for (i = 0, p = btf_params(t); i < vlen; i++, p++) {
			p->name_off = bswap_32(p->name_off);
			p->type = bswap_32(p->type);
		}
		return 0;
	case BTF_KIND_VAR:
		btf_var(t)->linkage = bswap_32(btf_var(t)->linkage);
		return 0;
	case BTF_KIND_DATASEC:
		for (i = 0, v = btf_var_secinfos(t); i < vlen; i++, v++) {
			v->type = bswap_32(v->type);
			v->offset = bswap_32(v->offset);
			v->size = bswap_32(v->size);
		}
		return 0;
	case BTF_KIND_DECL_TAG:
		btf_decl_tag(t)->component_idx = bswap_32(btf_decl_tag(t)->component_idx);
		return 0;
	default:
		printf("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

/**
 * btf_parse_type_sec - 解析type section
 */
static int btf_parse_type_sec(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	void *next_type = btf->types_data;
	void *end_type = next_type + hdr->type_len;
	int err, type_size;

	/**
	 * 遍历每一个type
	 */
	while (next_type + sizeof(struct btf_type) <= end_type) {
		/**
		 * 若btf与本地字节序不同，则对btf_type进行字节序转换
		 */
		if (btf->swapped_endian)
			btf_bswap_type_base(next_type);

		/**
		 * 获取type大小
		 */
		type_size = btf_type_size(next_type);
		if (type_size < 0)
			return type_size;
		if (next_type + type_size > end_type) {
			printf("BTF type [%d] is malformed\n", btf->start_id + btf->nr_types);
			return -EINVAL;
		}

		/**
		 * 若btf字节序与本地字节序不同，对剩余数据进行字节序转换
		 */
		if (btf->swapped_endian && btf_bswap_type_rest(next_type))
			return -EINVAL;

		err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
		if (err)
			return err;

		next_type += type_size;
		btf->nr_types++;
	}

	if (next_type != end_type) {
		printf("BTF types data is malformed\n");
		return -EINVAL;
	}

	return 0;
}

static int btf_validate_str(const struct btf *btf, __u32 str_off, const char *what, __u32 type_id)
{
	const char *s;

	s = btf__str_by_offset(btf, str_off);
	if (!s) {
		printf("btf: type [%u]: invalid %s (string offset %u)\n", type_id, what, str_off);
		return -EINVAL;
	}

	return 0;
}

static int btf_validate_id(const struct btf *btf, __u32 id, __u32 ctx_id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, id);
	if (!t) {
		printf("btf: type [%u]: invalid referenced type ID %u\n", ctx_id, id);
		return -EINVAL;
	}

	return 0;
}

static int btf_validate_type(const struct btf *btf, const struct btf_type *t, __u32 id)
{
	__u32 kind = btf_kind(t);
	int err, i, n;

	err = btf_validate_str(btf, t->name_off, "type name", id);
	if (err)
		return err;

	switch (kind) {
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FWD:
	case BTF_KIND_FLOAT:
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_VAR:
	case BTF_KIND_DECL_TAG:
	case BTF_KIND_TYPE_TAG:
		err = btf_validate_id(btf, t->type, id);
		if (err)
			return err;
		break;
	case BTF_KIND_ARRAY: {
		const struct btf_array *a = btf_array(t);

		err = btf_validate_id(btf, a->type, id);
		err = err ?: btf_validate_id(btf, a->index_type, id);
		if (err)
			return err;
		break;
	}
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m = btf_members(t);

		n = btf_vlen(t);
		for (i = 0; i < n; i++, m++) {
			err = btf_validate_str(btf, m->name_off, "field name", id);
			err = err ?: btf_validate_id(btf, m->type, id);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM: {
		const struct btf_enum *m = btf_enum(t);

		n = btf_vlen(t);
		for (i = 0; i < n; i++, m++) {
			err = btf_validate_str(btf, m->name_off, "enum name", id);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM64: {
		const struct btf_enum64 *m = btf_enum64(t);

		n = btf_vlen(t);
		for (i = 0; i < n; i++, m++) {
			err = btf_validate_str(btf, m->name_off, "enum name", id);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_FUNC: {
		const struct btf_type *ft;

		err = btf_validate_id(btf, t->type, id);
		if (err)
			return err;
		ft = btf__type_by_id(btf, t->type);
		if (btf_kind(ft) != BTF_KIND_FUNC_PROTO) {
			printf("btf: type [%u]: referenced type [%u] is not FUNC_PROTO\n", id, t->type);
			return -EINVAL;
		}
		break;
	}
	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *m = btf_params(t);

		n = btf_vlen(t);
		for (i = 0; i < n; i++, m++) {
			err = btf_validate_str(btf, m->name_off, "param name", id);
			err = err ?: btf_validate_id(btf, m->type, id);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_DATASEC: {
		const struct btf_var_secinfo *m = btf_var_secinfos(t);

		n = btf_vlen(t);
		for (i = 0; i < n; i++, m++) {
			err = btf_validate_id(btf, m->type, id);
			if (err)
				return err;
		}
		break;
	}
	default:
		printf("btf: type [%u]: unrecognized kind %u\n", id, kind);
		return -EINVAL;
	}
	return 0;
}

/* Validate basic sanity of BTF. It's intentionally less thorough than
 * kernel's validation and validates only properties of BTF that libbpf relies
 * on to be correct (e.g., valid type IDs, valid string offsets, etc)
 */
static int btf_sanity_check(const struct btf *btf)
{
	const struct btf_type *t;
	__u32 i, n = btf__type_cnt(btf);
	int err;

	for (i = 1; i < n; i++) {
		t = btf_type_by_id(btf, i);
		err = btf_validate_type(btf, t, i);
		if (err)
			return err;
	}
	return 0;
}

__u32 btf__type_cnt(const struct btf *btf)
{
	return btf->start_id + btf->nr_types;
}

const struct btf *btf__base_btf(const struct btf *btf)
{
	return btf->base_btf;
}

struct btf_type *btf_type_by_id(const struct btf *btf, __u32 type_id)
{
	if (type_id == 0)
		return &btf_void;
	if (type_id < btf->start_id)
		return btf_type_by_id(btf->base_btf, type_id);
	return btf->types_data + btf->type_offs[type_id - btf->start_id];
}

const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 type_id)
{
	if (type_id >= btf->start_id + btf->nr_types)
		return errno = EINVAL, NULL;
	return btf_type_by_id((struct btf *)btf, type_id);
}

static bool btf_is_modifiable(const struct btf *btf)
{
	return (void *)btf->hdr != btf->raw_data;
}

void btf__free(struct btf *btf)
{
	if (IS_ERR_OR_NULL(btf))
		return;

	if (btf->fd >= 0)
		close(btf->fd);

	if (btf_is_modifiable(btf)) {
		/* if BTF was modified after loading, it will have a split
		 * in-memory representation for header, types, and strings
		 * sections, so we need to free all of them individually. It
		 * might still have a cached contiguous raw data present,
		 * which will be unconditionally freed below.
		 */
		free(btf->hdr);
		free(btf->types_data);
		strset__free(btf->strs_set);
	}
	free(btf->raw_data);
	free(btf->raw_data_swapped);
	free(btf->type_offs);
	free(btf);
}

static struct btf *btf_new_empty(struct btf *base_btf)
{
	struct btf *btf;

	btf = calloc(1, sizeof(*btf));
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;
	btf->ptr_sz = sizeof(void *);
	btf->swapped_endian = false;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	/* +1 for empty string at offset 0 */
	btf->raw_size = sizeof(struct btf_header) + (base_btf ? 0 : 1);
	btf->raw_data = calloc(1, btf->raw_size);
	if (!btf->raw_data) {
		free(btf);
		return ERR_PTR(-ENOMEM);
	}

	btf->hdr = btf->raw_data;
	btf->hdr->hdr_len = sizeof(struct btf_header);
	btf->hdr->magic = BTF_MAGIC;
	btf->hdr->version = BTF_VERSION;

	btf->types_data = btf->raw_data + btf->hdr->hdr_len;
	btf->strs_data = btf->raw_data + btf->hdr->hdr_len;
	btf->hdr->str_len = base_btf ? 0 : 1; /* empty string at offset 0 */

	return btf;
}

struct btf *btf__new_empty(void)
{
	return libbpf_ptr(btf_new_empty(NULL));
}

static struct btf *btf_new(const void *data, __u32 size, struct btf *base_btf)
{
	struct btf *btf;
	int err;

	/**
	 * 申请一个btf结构体
	 */
	btf = calloc(1, sizeof(struct btf));
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	/**
	 * btf->raw_data中保存原始BTF数据，该原始BTF数据采用本机字节序
	 */
	btf->raw_data = malloc(size);
	if (!btf->raw_data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf->raw_data, data, size);
	btf->raw_size = size;

	/**
	 * When BTF is loaded from an ELF or raw memory it is stored
	 * in a contiguous memory block.
	 * +--------------------------------+
	 * |  Header  |  Types  |  Strings  |
	 * +--------------------------------+
	 * ^
	 * |
	 * hdr
	 */
	btf->hdr = btf->raw_data;
	err = btf_parse_hdr(btf);
	if (err)
		goto done;

	btf->strs_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->str_off;
	btf->types_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->type_off;

	err = btf_parse_str_sec(btf);
	err = err ?: btf_parse_type_sec(btf);
	err = err ?: btf_sanity_check(btf);
	if (err)
		goto done;

done:
	if (err) {
		btf__free(btf);
		return ERR_PTR(err);
	}

	return btf;
}

/** 
 * btf__new - 根据btf data和数据大小创建一个btf对象
 * @data: btf数据所在起始地址
 * @size: btf数据大小
 */
struct btf *btf__new(const void *data, __u32 size)
{
	return libbpf_ptr(btf_new(data, size, NULL));
}

static const void *btf_strs_data(const struct btf *btf)
{
	return btf->strs_data ? btf->strs_data : strset__data(btf->strs_set);
}

const char *btf__str_by_offset(const struct btf *btf, __u32 offset)
{
	if (offset < btf->start_str_off)
		return btf__str_by_offset(btf->base_btf, offset);
	else if (offset - btf->start_str_off < btf->hdr->str_len)
		return btf_strs_data(btf) + (offset - btf->start_str_off);
	else
		return errno = EINVAL, NULL;
}

static void btf_invalidate_raw_data(struct btf *btf)
{
	if (btf->raw_data) {
		free(btf->raw_data);
		btf->raw_data = NULL;
	}
	if (btf->raw_data_swapped) {
		free(btf->raw_data_swapped);
		btf->raw_data_swapped = NULL;
	}
}

/* Ensure BTF is ready to be modified (by splitting into a three memory
 * regions for header, types, and strings). Also invalidate cached
 * raw_data, if any.
 */
static int btf_ensure_modifiable(struct btf *btf)
{
	void *hdr, *types;
	struct strset *set = NULL;
	int err = -ENOMEM;

	if (btf_is_modifiable(btf)) {
		/* any BTF modification invalidates raw_data */
		btf_invalidate_raw_data(btf);
		return 0;
	}

	/* split raw data into three memory regions */
	hdr = malloc(btf->hdr->hdr_len);
	types = malloc(btf->hdr->type_len);
	if (!hdr || !types)
		goto err_out;

	memcpy(hdr, btf->hdr, btf->hdr->hdr_len);
	memcpy(types, btf->types_data, btf->hdr->type_len);

	/* build lookup index for all strings */
	set = strset__new(BTF_MAX_STR_OFFSET, btf->strs_data, btf->hdr->str_len);
	if (IS_ERR(set)) {
		err = PTR_ERR(set);
		goto err_out;
	}

	/* only when everything was successful, update internal state */
	btf->hdr = hdr;
	btf->types_data = types;
	btf->types_data_cap = btf->hdr->type_len;
	btf->strs_data = NULL;
	btf->strs_set = set;
	/* if BTF was created from scratch, all strings are guaranteed to be
	 * unique and deduplicated
	 */
	if (btf->hdr->str_len == 0)
		btf->strs_deduped = true;
	if (!btf->base_btf && btf->hdr->str_len == 1)
		btf->strs_deduped = true;

	/* invalidate raw_data representation */
	btf_invalidate_raw_data(btf);

	return 0;

err_out:
	strset__free(set);
	free(hdr);
	free(types);
	return err;
}

/* Find an offset in BTF string section that corresponds to a given string *s*.
 * Returns:
 *   - >0 offset into string section, if string is found;
 *   - -ENOENT, if string is not in the string section;
 *   - <0, on any other error.
 */
int btf__find_str(struct btf *btf, const char *s)
{
	int off;

	if (btf->base_btf) {
		off = btf__find_str(btf->base_btf, s);
		if (off != -ENOENT)
			return off;
	}

	/* BTF needs to be in a modifiable state to build string lookup index */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	off = strset__find_str(btf->strs_set, s);
	if (off < 0)
		return libbpf_err(off);

	return btf->start_str_off + off;
}

/* Add a string s to the BTF string section.
 * Returns:
 *   - > 0 offset into string section, on success;
 *   - < 0, on error.
 */
int btf__add_str(struct btf *btf, const char *s)
{
	int off;

	if (btf->base_btf) {
		off = btf__find_str(btf->base_btf, s);
		if (off != -ENOENT)
			return off;
	}

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	off = strset__add_str(btf->strs_set, s);
	if (off < 0)
		return libbpf_err(off);

	btf->hdr->str_len = strset__data_size(btf->strs_set);

	return btf->start_str_off + off;
}

struct btf_ext_sec_setup_param {
	__u32 off;
	__u32 len;
	__u32 min_rec_size;
	struct btf_ext_info *ext_info;
	const char *desc;
};

static int btf_ext_setup_info(struct btf_ext *btf_ext,
			      struct btf_ext_sec_setup_param *ext_sec)
{
	const struct btf_ext_info_sec *sinfo;
	struct btf_ext_info *ext_info;
	__u32 info_left, record_size;
	size_t sec_cnt = 0;
	/* The start of the info sec (including the __u32 record_size). */
	void *info;

	if (ext_sec->len == 0)
		return 0;

	if (ext_sec->off & 0x03) {
		printf(".BTF.ext %s section is not aligned to 4 bytes\n",
		     ext_sec->desc);
		return -EINVAL;
	}

	info = btf_ext->data + btf_ext->hdr->hdr_len + ext_sec->off;
	info_left = ext_sec->len;

	if (btf_ext->data + btf_ext->data_size < info + ext_sec->len) {
		printf("%s section (off:%u len:%u) is beyond the end of the ELF section .BTF.ext\n",
			 ext_sec->desc, ext_sec->off, ext_sec->len);
		return -EINVAL;
	}

	/* At least a record size */
	if (info_left < sizeof(__u32)) {
		printf(".BTF.ext %s record size not found\n", ext_sec->desc);
		return -EINVAL;
	}

	/* The record size needs to meet the minimum standard */
	record_size = *(__u32 *)info;
	if (record_size < ext_sec->min_rec_size ||
	    record_size & 0x03) {
		printf("%s section in .BTF.ext has invalid record size %u\n",
			 ext_sec->desc, record_size);
		return -EINVAL;
	}

	sinfo = info + sizeof(__u32);
	info_left -= sizeof(__u32);

	/* If no records, return failure now so .BTF.ext won't be used. */
	if (!info_left) {
		printf("%s section in .BTF.ext has no records", ext_sec->desc);
		return -EINVAL;
	}

	while (info_left) {
		unsigned int sec_hdrlen = sizeof(struct btf_ext_info_sec);
		__u64 total_record_size;
		__u32 num_records;

		if (info_left < sec_hdrlen) {
			printf("%s section header is not found in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		num_records = sinfo->num_info;
		if (num_records == 0) {
			printf("%s section has incorrect num_records in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		total_record_size = sec_hdrlen + (__u64)num_records * record_size;
		if (info_left < total_record_size) {
			printf("%s section has incorrect num_records in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		info_left -= total_record_size;
		sinfo = (void *)sinfo + total_record_size;
		sec_cnt++;
	}

	ext_info = ext_sec->ext_info;
	ext_info->len = ext_sec->len - sizeof(__u32);
	ext_info->rec_size = record_size;
	ext_info->info = info + sizeof(__u32);
	ext_info->sec_cnt = sec_cnt;

	return 0;
}

static int btf_ext_setup_func_info(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->func_info_off,
		.len = btf_ext->hdr->func_info_len,
		.min_rec_size = sizeof(struct bpf_func_info_min),
		.ext_info = &btf_ext->func_info,
		.desc = "func_info"
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_line_info(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->line_info_off,
		.len = btf_ext->hdr->line_info_len,
		.min_rec_size = sizeof(struct bpf_line_info_min),
		.ext_info = &btf_ext->line_info,
		.desc = "line_info",
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_core_relos(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->core_relo_off,
		.len = btf_ext->hdr->core_relo_len,
		.min_rec_size = sizeof(struct bpf_core_relo),
		.ext_info = &btf_ext->core_relo_info,
		.desc = "core_relo",
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_parse_hdr(__u8 *data, __u32 data_size)
{
	const struct btf_ext_header *hdr = (struct btf_ext_header *)data;

	if (data_size < offsetofend(struct btf_ext_header, hdr_len) ||
	    data_size < hdr->hdr_len) {
		printf("BTF.ext header not found");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		printf("BTF.ext in non-native endianness is not supported\n");
		return -ENOTSUP;
	} else if (hdr->magic != BTF_MAGIC) {
		printf("Invalid BTF.ext magic:%x\n", hdr->magic);
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		printf("Unsupported BTF.ext version:%u\n", hdr->version);
		return -ENOTSUP;
	}

	if (hdr->flags) {
		printf("Unsupported BTF.ext flags:%x\n", hdr->flags);
		return -ENOTSUP;
	}

	if (data_size == hdr->hdr_len) {
		printf("BTF.ext has no data\n");
		return -EINVAL;
	}

	return 0;
}

void btf_ext__free(struct btf_ext *btf_ext)
{
	if (IS_ERR_OR_NULL(btf_ext))
		return;
	free(btf_ext->func_info.sec_idxs);
	free(btf_ext->line_info.sec_idxs);
	free(btf_ext->core_relo_info.sec_idxs);
	free(btf_ext->data);
	free(btf_ext);
}

struct btf_ext *btf_ext__new(const __u8 *data, __u32 size)
{
	struct btf_ext *btf_ext;
	int err;

	btf_ext = calloc(1, sizeof(struct btf_ext));
	if (!btf_ext)
		return libbpf_err_ptr(-ENOMEM);

	btf_ext->data_size = size;
	btf_ext->data = malloc(size);
	if (!btf_ext->data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf_ext->data, data, size);

	err = btf_ext_parse_hdr(btf_ext->data, size);
	if (err)
		goto done;
	
	if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, line_info_len)) {
		err = -EINVAL;
		goto done;
	}

	err = btf_ext_setup_func_info(btf_ext);
	if (err)
		goto done;
	
	err = btf_ext_setup_line_info(btf_ext);
	if (err)
		goto done;

	if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, core_relo_len))
		goto done; /* skip core relos parsing */

	err = btf_ext_setup_core_relos(btf_ext);
	if (err)
		goto done;
done:
	if (err) {
		btf_ext__free(btf_ext);
		return libbpf_err_ptr(err);
	}

	return btf_ext;
}

int btf_type_visit_type_ids(struct btf_type *t, type_id_visit_fn visit, void *ctx)
{
	int i, n, err;

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		return 0;

	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_VAR:
	case BTF_KIND_DECL_TAG:
	case BTF_KIND_TYPE_TAG:
		return visit(&t->type, ctx);

	case BTF_KIND_ARRAY: {
		struct btf_array *a = btf_array(t);

		err = visit(&a->type, ctx);
		err = err ?: visit(&a->index_type, ctx);
		return err;
	}

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		struct btf_member *m = btf_members(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}

	case BTF_KIND_FUNC_PROTO: {
		struct btf_param *m = btf_params(t);

		err = visit(&t->type, ctx);
		if (err)
			return err;
		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}

	case BTF_KIND_DATASEC: {
		struct btf_var_secinfo *m = btf_var_secinfos(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}

	default:
		return -EINVAL;
	}
}

int btf_type_visit_str_offs(struct btf_type *t, str_off_visit_fn visit, void *ctx)
{
	int i, n, err;

	err = visit(&t->name_off, ctx);
	if (err)
		return err;

	switch (btf_kind(t)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		struct btf_member *m = btf_members(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM: {
		struct btf_enum *m = btf_enum(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM64: {
		struct btf_enum64 *m = btf_enum64(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_FUNC_PROTO: {
		struct btf_param *m = btf_params(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	default:
		break;
	}

	return 0;
}

int btf_ext_visit_type_ids(struct btf_ext *btf_ext, type_id_visit_fn visit, void *ctx)
{
	const struct btf_ext_info *seg;
	struct btf_ext_info_sec *sec;
	int i, err;

	seg = &btf_ext->func_info;
	for_each_btf_ext_sec(seg, sec) {
		struct bpf_func_info_min *rec;

		for_each_btf_ext_rec(seg, sec, i, rec) {
			err = visit(&rec->type_id, ctx);
			if (err < 0)
				return err;
		}
	}

	seg = &btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec) {
		struct bpf_core_relo *rec;

		for_each_btf_ext_rec(seg, sec, i, rec) {
			err = visit(&rec->type_id, ctx);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

int btf_ext_visit_str_offs(struct btf_ext *btf_ext, str_off_visit_fn visit, void *ctx)
{
	const struct btf_ext_info *seg;
	struct btf_ext_info_sec *sec;
	int i, err;

	seg = &btf_ext->func_info;
	for_each_btf_ext_sec(seg, sec) {
		err = visit(&sec->sec_name_off, ctx);
		if (err)
			return err;
	}

	seg = &btf_ext->line_info;
	for_each_btf_ext_sec(seg, sec) {
		struct bpf_line_info_min *rec;

		err = visit(&sec->sec_name_off, ctx);
		if (err)
			return err;

		for_each_btf_ext_rec(seg, sec, i, rec) {
			err = visit(&rec->file_name_off, ctx);
			if (err)
				return err;
			err = visit(&rec->line_off, ctx);
			if (err)
				return err;
		}
	}

	seg = &btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec) {
		struct bpf_core_relo *rec;

		err = visit(&sec->sec_name_off, ctx);
		if (err)
			return err;

		for_each_btf_ext_rec(seg, sec, i, rec) {
			err = visit(&rec->access_str_off, ctx);
			if (err)
				return err;
		}
	}

	return 0;
}
