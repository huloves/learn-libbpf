#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "../libbpf.h"

#include "main.h"

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

out:
	return 0;
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
	// { "skeleton",		do_skeleton },
	// { "subskeleton",	do_subskeleton },
	// { "min_core_btf",	do_min_core_btf},
	{ "help",		do_help },
	{ 0 }
};

int do_gen(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
