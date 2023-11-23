#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/kernel.h>

#include "../libbpf.h"
#include "../libbpf_legacy.h"

#include "main.h"

#define MAX_OBJ_NAME_LEN 64

/**
 * bpftool gen skeleton xxx.bpf.o > xxx.skel.h
 */
static int do_skeleton(int argc, char **argv)
{
	char header_guard[MAX_OBJ_NAME_LEN + sizeof("__SKEL_H__")];
	size_t map_cnt = 0, prog_cnt = 0, file_sz, mmap_sz;
	char obj_name[MAX_OBJ_NAME_LEN] = "", *obj_data;
	struct bpf_object *obj = NULL;
	const char *file;
	char ident[256];
	struct bpf_program *prog;
	int fd, err = -1;
	struct bpf_map *map;
	struct btf *btf;
	struct stat st;

	if (!REQ_ARGS(1)) {
		usage();
		return -1;
	}
	file = GET_ARG();

	while (argc) {
		if (!REQ_ARGS(2)) {
			return -1;
		}
		if (is_prefix(*argv, "name")) {
			NEXT_ARG();

			if (obj_name[0] != '\0') {
				printf("object name already specified\n");
				return -1;
			}

			strncpy(obj_name, *argv, MAX_OBJ_NAME_LEN - 1);
			obj_name[MAX_OBJ_NAME_LEN - 1] = '\0';
		} else {
			printf("unknown arg %s\n", *argv);
			return -1;
		}
	}

	if (argc) {
		printf("extra unknown arguments\n");
		return -1;
	}

	if (stat(file, &st)) {
		printf("failed to stat() %s: %s", file, strerror(errno));
	}
	file_sz = st.st_size;
	mmap_sz = roundup(file_sz, sysconf(_SC_PAGE_SIZE));
}

static int do_object(int argc, char **argv)
{
	struct bpf_linker *linker;
	const char *output_file, *file;
	int err = 0;

	if (!REQ_ARGS(2)) {
		usage();
		return -1;
	}

	/**
	 * 获得输出文件名
	 */
	output_file = GET_ARG();

	/**
	 * 创建并初始化一个linker
	 */
	linker = bpf_linker__new(output_file, NULL);
	if (!linker) {
		printf("failed to create BPF linker instance\n");
		return -1;
	}

	/**
	 * 遍历每一个输入文件
	 */
	while (argc) {
		/**
		 * 获得输入文件名
		 */
		file = GET_ARG();

		/**
		 * 在linker中添加输入文件file中的信息
		 */
		err = bpf_linker__add_file(linker, file, NULL);
		if (err) {
			printf("failed to link '%s': %s (%d)", file, strerror(errno), errno);
			goto out;
		}
	}

	err = bpf_linker__finalize(linker);
	if (err) {
		printf("failed to finalize ELF file: %s (%d)", strerror(errno), errno);
		goto out;
	}

	err = 0;
out:
	bpf_linker__free(linker);
	return err;
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %1$s %2$s object OUTPUT_FILE INPUT_FILE [INPUT_FILE...]\n"
		"       %1$s %2$s skeleton FILE [name OBJECT_NAME]\n"
		"       %1$s %2$s subskeleton FILE [name OBJECT_NAME]\n"
		"       %1$s %2$s min_core_btf INPUT OUTPUT OBJECT [OBJECT...]\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-L|--use-loader} }\n"
		"",
		bin_name, "gen");

	return 0;
}

static const struct cmd cmds[] = {
	{ "object",		do_object },
	{ "skeleton",		do_skeleton },
	// { "subskeleton",	do_subskeleton },
	// { "min_core_btf",	do_min_core_btf},
	{ "help",		do_help },
	{ 0 }
};

int do_gen(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
