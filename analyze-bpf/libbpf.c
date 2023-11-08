#include <linux/err.h>
#include <errno.h>

long libbpf_get_error(const char *ptr)
{
	if (!IS_ERR_OR_NULL(ptr))
		return 0;

	if (IS_ERR(ptr))
		errno = -PTR_ERR(ptr);

	/* If ptr == NULL, then errno should be already set by the failing
	 * API, because libbpf never returns NULL on success and it now always
	 * sets errno on error. So no extra errno handling for ptr == NULL
	 * case.
	 */
	return -errno;
}
