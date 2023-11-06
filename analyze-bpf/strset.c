#include <stdlib.h>

struct strset {
	void *strs_data;
	size_t strs_data_len;
	size_t strs_data_cap;
	size_t strs_data_max_len;
};