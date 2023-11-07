#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/err.h>
#include <limits.h>
#include "hashmap.h"
#include "strset.h"

struct strset {
	void *strs_data;
	size_t strs_data_len;
	size_t strs_data_cap;
	size_t strs_data_max_len;

	/* lookup index for each unique string in strings set */
	struct hashmap *strs_hash;
};

static size_t strset_hash_fn(long key, void *ctx)
{
	const struct strset *s = ctx;
	const char *str = s->strs_data + key;

	return str_hash(str);
}

static bool strset_equal_fn(long key1, long key2, void *ctx)
{
	const struct strset *s = ctx;
	const char *str1 = s->strs_data + key1;
	const char *str2 = s->strs_data + key2;

	return strcmp(str1, str2) == 0;
}

struct strset *strset_new(size_t max_data_sz, const char *init_data, size_t init_data_sz)
{
	struct strset *set = calloc(1, sizeof(*set));
	struct hashmap *hash;
	int err = -ENOMEM;

	if (!set)
		return ERR_PTR(-ENOMEM);
	
	hash = hashmap__new(strset_hash_fn, strset_equal_fn, set);
	if (IS_ERR(hash))
		goto err_out;

	set->strs_data_max_len = max_data_sz;
	set->strs_hash = hash;

	if (init_data) {
		long off;

		set->strs_data = malloc(init_data_sz);
		if (!set->strs_data)
			goto err_out;

		memcpy(set->strs_data, init_data, init_data_sz);
		set->strs_data_len = init_data_sz;
		set->strs_data_cap = init_data_sz;

		for (off = 0; off < set->strs_data_len; off += strlen(set->strs_data + off) + 1) {
			/* hashmap__add() returns EEXIST if string with the same
			 * content already is in the hash map
			 */
			err = hashmap__add(hash, off, off);
			if (err == -EEXIST)
				continue; /* duplicate */
			if (err)
				goto err_out;
		}
	}

	return set;
err_out:
	strset__free(set);
	return ERR_PTR(err);
}

void strset__free(struct strset *set)
{
	if (IS_ERR_OR_NULL(set))
		return;

	hashmap__free(set->strs_hash);
	free(set->strs_data);
	free(set);
}

size_t strset__data_size(const struct strset *set)
{
	return set->strs_data_len;
}

const char *strset__data(const struct strset *set)
{
	return set->strs_data;
}

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/*
 * Re-implement glibc's reallocarray() for libbpf internal-only use.
 * reallocarray(), unfortunately, is not available in all versions of glibc,
 * so requires extra feature detection and using reallocarray() stub from
 * <tools/libc_compat.h> and COMPAT_NEED_REALLOCARRAY. All this complicates
 * build of libbpf unnecessarily and is just a maintenance burden. Instead,
 * it's trivial to implement libbpf-specific internal version and use it
 * throughout libbpf.
 */
static inline void *analyze_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
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
static void *add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
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

	new_data = analyze_reallocarray(*data, new_cnt, elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

static void *strset_add_str_mem(struct strset *set, size_t add_sz)
{
	return add_mem(&set->strs_data, &set->strs_data_cap, 1,
			      set->strs_data_len, set->strs_data_max_len, add_sz);
}

/* Find string offset that corresponds to a given string *s*.
 * Returns:
 *   - >0 offset into string data, if string is found;
 *   - -ENOENT, if string is not in the string data;
 *   - <0, on any other error.
 */
int strset__find_str(struct strset *set, const char *s)
{
	long old_off, new_off, len;
	void *p;

	/* see strset__add_str() for why we do this */
	len = strlen(s) + 1;
	p = strset_add_str_mem(set, len);
	if (!p)
		return -ENOMEM;

	new_off = set->strs_data_len;
	memcpy(p, s, len);

	if (hashmap__find(set->strs_hash, new_off, &old_off))
		return old_off;

	return -ENOENT;
}

/* Add a string s to the string data. If the string already exists, return its
 * offset within string data.
 * Returns:
 *   - > 0 offset into string data, on success;
 *   - < 0, on error.
 */
int strset__add_str(struct strset *set, const char *s)
{
	long old_off, new_off, len;
	void *p;
	int err;

	/* Hashmap keys are always offsets within set->strs_data, so to even
	 * look up some string from the "outside", we need to first append it
	 * at the end, so that it can be addressed with an offset. Luckily,
	 * until set->strs_data_len is incremented, that string is just a piece
	 * of garbage for the rest of the code, so no harm, no foul. On the
	 * other hand, if the string is unique, it's already appended and
	 * ready to be used, only a simple set->strs_data_len increment away.
	 */
	len = strlen(s) + 1;
	p = strset_add_str_mem(set, len);
	if (!p)
		return -ENOMEM;

	new_off = set->strs_data_len;
	memcpy(p, s, len);

	/* Now attempt to add the string, but only if the string with the same
	 * contents doesn't exist already (HASHMAP_ADD strategy). If such
	 * string exists, we'll get its offset in old_off (that's old_key).
	 */
	err = hashmap__insert(set->strs_hash, new_off, new_off,
			      HASHMAP_ADD, &old_off, NULL);
	if (err == -EEXIST)
		return old_off; /* duplicated string, return existing offset */
	if (err)
		return err;

	set->strs_data_len += len; /* new unique string, adjust data length */
	return new_off;
}
