#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include "main.h"

#define BATCH_LINE_LEN_MAX 65536
#define BATCH_ARG_NB_MAX 4096

const char *bin_name;
static int last_argc;
static char **last_argv;
static int (*last_do_help)(int argc, char **argv);

void usage(void)
{
	last_do_help(last_argc - 1, last_argv + 1);
	exit(-1);
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] OBJECT { COMMAND | help }\n"
		"       %s batch file FILE\n"
		"       %s version\n"
		"\n"
		"       OBJECT := { prog | map | link | cgroup | perf | net | feature | btf | gen | struct_ops | iter }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-V|--version} }\n"
		"",
		bin_name, bin_name, bin_name);

	return 0;
}

static const struct cmd commands[] = {
	{ "help",	do_help },
	// { "batch",	do_batch },
	// { "prog",	do_prog },
	// { "map",	do_map },
	// { "link",	do_link },
	// { "cgroup",	do_cgroup },
	// { "perf",	do_perf },
	// { "net",	do_net },
	// { "feature",	do_feature },
	// { "btf",	do_btf },
	{ "gen",	do_gen },
	// { "struct_ops",	do_struct_ops },
	// { "iter",	do_iter },
	// { "version",	do_version },
	{ 0 }
};

bool is_prefix(const char *pfx, const char *str)
{
	if (!pfx)
		return false;
	if (strlen(str) < strlen(pfx))
		return false;

	return !memcmp(str, pfx, strlen(pfx));
}

int cmd_select(const struct cmd *cmds, int argc, char **argv,
	       int (*help)(int argc, char **argv))
{
	unsigned int i;

	last_argc = argc;
	last_argv = argv;
	last_do_help = help;

	if (argc < 1 && cmds[0].func)
		return cmds[0].func(argc, argv);

	for (i = 0; cmds[i].cmd; i++) {
		if (is_prefix(*argv, cmds[i].cmd)) {
			if (!cmds[i].func) {
				printf("command '%s' is not supported in bootstrap mode",
				      cmds[i].cmd);
				return -1;
			}
			return cmds[i].func(argc - 1, argv + 1);
		}
	}

	help(argc - 1, argv + 1);

	return -1;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		// { "json",	no_argument,	NULL,	'j' },
		{ "help",	no_argument,	NULL,	'h' },
		// { "pretty",	no_argument,	NULL,	'p' },
		// { "version",	no_argument,	NULL,	'V' },
		// { "bpffs",	no_argument,	NULL,	'f' },
		// { "mapcompat",	no_argument,	NULL,	'm' },
		// { "nomount",	no_argument,	NULL,	'n' },
		// { "debug",	no_argument,	NULL,	'd' },
		// { "use-loader",	no_argument,	NULL,	'L' },
		// { "base-btf",	required_argument, NULL, 'B' },
		{ 0 }
	};
	bool version_requested = false;
	int opt, ret;

	setlinebuf(stdout);

	last_do_help = do_help;
	bin_name = "bpftool";

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "VhpjfLmndB:l",
				  options, NULL)) >= 0) {
		switch (opt) {
		case 'h':
			return do_help(argc, argv);
		default:
			printf("unrecognized option '%s'\n", argv[optind - 1]);
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 0)
		usage();

	ret = cmd_select(commands, argc, argv, do_help);
	
	return ret;
}
