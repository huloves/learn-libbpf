#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include "libbpf_internal.h"
#include "bpf_helpers.h"

#include "include/uapi/linux/btf.h"

/* On Ubuntu LINUX_VERSION_CODE doesn't correspond to info.release,
 * but Ubuntu provides /proc/version_signature file, as described at
 * https://ubuntu.com/kernel, with an example contents below, which we
 * can use to get a proper LINUX_VERSION_CODE.
 *
 *   Ubuntu 5.4.0-12.15-generic 5.4.8
 *
 * In the above, 5.4.8 is what kernel is actually expecting, while
 * uname() call will return 5.4.0 in info.release.
 */
static __u32 get_ubuntu_kernel_version(void)
{
	const char *ubuntu_kver_file = "/proc/version_signature";
	__u32 major, minor, patch;
	int ret;
	FILE *f;

	if (faccessat(AT_FDCWD, ubuntu_kver_file, R_OK, AT_EACCESS) != 0)
		return 0;

	f = fopen(ubuntu_kver_file, "re");
	if (!f)
		return 0;

	ret = fscanf(f, "%*s %*s %u.%u.%u\n", &major, &minor, &patch);
	fclose(f);
	if (ret != 3)
		return 0;

	pr_debug("ubuntu_kernel_version: %d.%d.%d\n", major, minor, patch);

	return KERNEL_VERSION(major, minor, patch);
}

/* On Debian LINUX_VERSION_CODE doesn't correspond to info.release.
 * Instead, it is provided in info.version. An example content of
 * Debian 10 looks like the below.
 *
 *   utsname::release   4.19.0-22-amd64
 *   utsname::version   #1 SMP Debian 4.19.260-1 (2022-09-29)
 *
 * In the above, 4.19.260 is what kernel is actually expecting, while
 * uname() call will return 4.19.0 in info.release.
 */
static __u32 get_debian_kernel_version(struct utsname *info)
{
	__u32 major, minor, patch;
	char *p;

	p = strstr(info->version, "Debian ");
	if (!p) {
		/* This is not a Debian kernel. */
		return 0;
	}

	if (sscanf(p, "Debian %u.%u.%u", &major, &minor, &patch) != 3)
		return 0;

	return KERNEL_VERSION(major, minor, patch);
}

__u32 get_kernel_version(void)
{
	__u32 major, minor, patch, version;
	struct utsname info;

	/* Check if this is an Ubuntu kernel. */
	version = get_ubuntu_kernel_version();
	if (version != 0)
		return version;

	uname(&info);

	/* Check if this is a Debian kernel. */
	version = get_debian_kernel_version(&info);
	if (version != 0)
		return version;

	if (sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3)
		return 0;

	return KERNEL_VERSION(major, minor, patch);
}
