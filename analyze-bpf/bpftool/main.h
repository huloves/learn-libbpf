#ifndef _BPFTOOL_MAIN_H
#define _BPFTOOL_MAIN_H

#include <stdbool.h>

#define NEXT_ARG()	({ argc--; argv++; if (argc < 0) usage(); })
#define NEXT_ARGP()	({ (*argc)--; (*argv)++; if (*argc < 0) usage(); })
#define BAD_ARG()	({ printf("what is '%s'?\n", *argv); -1; })
#define GET_ARG()	({ argc--; *argv++; })
#define REQ_ARGS(cnt)							\
	({								\
		int _cnt = (cnt);					\
		bool _res;						\
									\
		if (argc < _cnt) {					\
			printf("'%s' needs at least %d arguments, %d found\n", \
			      argv[-1], _cnt, argc);			\
			_res = false;					\
		} else {						\
			_res = true;					\
		}							\
		_res;							\
	})

#define HELP_SPEC_PROGRAM						\
	"PROG := { id PROG_ID | pinned FILE | tag PROG_TAG | name PROG_NAME }"
#define HELP_SPEC_OPTIONS						\
	"OPTIONS := { {-j|--json} [{-p|--pretty}] | {-d|--debug}"
#define HELP_SPEC_MAP							\
	"MAP := { id MAP_ID | pinned FILE | name MAP_NAME }"
#define HELP_SPEC_LINK							\
	"LINK := { id LINK_ID | pinned FILE }"

void usage(void);

extern const char *bin_name;

struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};

int cmd_select(const struct cmd *cmds, int argc, char **argv,
	       int (*help)(int argc, char **argv));

int do_gen(int argc, char **argv);

#endif /* _BPFTOOL_MAIN_H */
