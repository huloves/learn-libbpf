#include <stdbool.h>
#include <stdlib.h>

#include "libbpf.h"
#include "libbpf_internal.h"

struct usdt_manager {
	struct bpf_map *specs_map;
	struct bpf_map *ip_to_spec_id_map;

	int *free_spec_ids;
	size_t free_spec_cnt;
	size_t next_free_spec_id;

	bool has_bpf_cookie;
	bool has_sema_refcnt;
	bool has_uprobe_multi;
};

void usdt_manager_free(struct usdt_manager *man)
{
	if (IS_ERR_OR_NULL(man))
		return;

	free(man->free_spec_ids);
	free(man);
}
