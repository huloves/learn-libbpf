#include <stdbool.h>
#include <stdlib.h>
#include <linux/btf.h>
#include <linux/errno.h>
#include <linux/err.h>
#include "btf.h"
#include "libbpf_internal.h"

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

__u32 btf__type_cnt(const struct btf *btf)
{
	return btf->start_id + btf->nr_types;
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
