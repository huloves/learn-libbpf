#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/kernel.h>

#include "../btf.h"
#include "../libbpf.h"
#include "../libbpf_legacy.h"

#include "main.h"

#define MAX_OBJ_NAME_LEN 64

static void sanitize_identifier(char *name)
{
	int i;
	
	for (i = 0; name[i]; i++)
		if (!isalnum(name[i]) && name[i] != '_')
			name[i] = '_';
}

static bool str_has_prefix(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool str_has_suffix(const char *str, const char *suffix)
{
	size_t i, n1 = strlen(str), n2 = strlen(suffix);

	if (n1 < n2)
		return false;
	
	for (i = 0; i < n2; i++)
		if (str[n1 - i - 1] != suffix[n2 - i - 1])
			return false;

	return true;
}

static void get_obj_name(char *name, const char *file)
{
	/* Using basename() GNU version which doesn't modify arg. */
	strncpy(name, basename(file), MAX_OBJ_NAME_LEN - 1);
	name[MAX_OBJ_NAME_LEN - 1] = '\0';
	if (str_has_suffix(name, ".o"))
		name[strlen(name) - 2] = '\0';
	sanitize_identifier(name);
}

static void get_header_guard(char *guard, const char *obj_name, const char *suffix)
{
	int i;

	sprintf(guard, "__%s_%s__", obj_name, suffix);
	for (i = 0; guard[i]; i++)
		guard[i] = toupper(guard[i]);
}

static bool get_map_ident(const struct bpf_map *map, char *buf, size_t buf_sz)
{
	static const char *sfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	const char *name = bpf_map__name(map);
	int i, n;

	if (!bpf_map__is_internal(map)) {
		snprintf(buf, buf_sz, "%s", name);
		return true;
	}

	for  (i = 0, n = ARRAY_SIZE(sfxs); i < n; i++) {
		const char *sfx = sfxs[i], *p;

		p = strstr(name, sfx);
		if (p) {
			snprintf(buf, buf_sz, "%s", p + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static bool get_datasec_ident(const char *sec_name, char *buf, size_t buf_sz)
{
	static const char *pfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	int i, n;

	for  (i = 0, n = ARRAY_SIZE(pfxs); i < n; i++) {
		const char *pfx = pfxs[i];

		if (str_has_prefix(sec_name, pfx)) {
			snprintf(buf, buf_sz, "%s", sec_name + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static void codegen_btf_dump_printf(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

static int codegen_datasec_def(struct bpf_object *obj,
			       struct btf *btf,
			       struct btf_dump *d,
			       const struct btf_type *sec,
			       const char *obj_name)
{
	const char *sec_name = btf__name_by_offset(btf, sec->name_off);
	const struct btf_var_secinfo *sec_var = btf_var_secinfos(sec);
	int i, err, off = 0, pad_cnt = 0, vlen = btf_vlen(sec);
	char var_ident[256], sec_ident[256];
	bool strip_mods = false;

	if (!get_datasec_ident(sec_name, sec_ident, sizeof(sec_ident)))
		return 0;

	if (strcmp(sec_name, ".kconfig") != 0)
		strip_mods = true;

	printf("	struct %s__%s {\n", obj_name, sec_ident);
	for (i = 0; i < vlen; i++, sec_var++) {
		const struct btf_type *var = btf__type_by_id(btf, sec_var->type);
		const char *var_name = btf__name_by_offset(btf, var->name_off);
		DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts,
			.field_name = var_ident,
			.indent_level = 2,
			.strip_mods = strip_mods,
		);
		int need_off = sec_var->offset, align_off, align;
		__u32 var_type_id = var->type;

		/* static variables are not exposed through BPF skeleton */
		if (btf_var(var)->linkage == BTF_VAR_STATIC)
			continue;

		if (off > need_off) {
			printf("Something is wrong for %s's variable #%d: need offset %d, already at %d.\n",
			      sec_name, i, need_off, off);
			return -EINVAL;
		}

		align = btf__align_of(btf, var->type);
		if (align <= 0) {
			printf("Failed to determine alignment of variable '%s': %d",
			      var_name, align);
			return -EINVAL;
		}
		/* Assume 32-bit architectures when generating data section
		 * struct memory layout. Given bpftool can't know which target
		 * host architecture it's emitting skeleton for, we need to be
		 * conservative and assume 32-bit one to ensure enough padding
		 * bytes are generated for pointer and long types. This will
		 * still work correctly for 64-bit architectures, because in
		 * the worst case we'll generate unnecessary padding field,
		 * which on 64-bit architectures is not strictly necessary and
		 * would be handled by natural 8-byte alignment. But it still
		 * will be a correct memory layout, based on recorded offsets
		 * in BTF.
		 */
		if (align > 4)
			align = 4;

		align_off = (off + align - 1) / align * align;
		if (align_off != need_off) {
			printf("\t\tchar __pad%d[%d];\n",
			       pad_cnt, need_off - off);
			pad_cnt++;
		}

		/* sanitize variable name, e.g., for static vars inside
		 * a function, it's name is '<function name>.<variable name>',
		 * which we'll turn into a '<function name>_<variable name>'
		 */
		var_ident[0] = '\0';
		strncat(var_ident, var_name, sizeof(var_ident) - 1);
		sanitize_identifier(var_ident);

		printf("\t\t");
		// err = btf_dump__emit_type_decl(d, var_type_id, &opts);
		if (err)
			return err;
		printf(";\n");

		off = sec_var->offset + sec_var->size;
	}
	printf("	} *%s;\n", sec_ident);
	return 0;
}

static void codegen(const char *template, ...)
{
	const char *src, *end;
	int skip_tabs = 0, n;
	char *s, *dst;
	va_list args;
	char c;

	n = strlen(template);
	s = malloc(n + 1);
	if (!s)
		exit(-1);
	src = template;
	dst = s;

	/* find out "baseline" indentation to skip */
	while ((c = *src++)) {
		if (c == '\t') {
			skip_tabs++;
		} else if (c == '\n') {
			break;
		} else {
			printf("unrecognized character at pos %td in template '%s': '%c'",
			      src - template - 1, template, c);
			free(s);
			exit(-1);
		}
	}

	while (*src) {
		/* skip baseline indentation tabs */
		for (n = skip_tabs; n > 0; n--, src++) {
			if (*src != '\t') {
				printf("not enough tabs at pos %td in template '%s'",
				      src - template - 1, template);
				free(s);
				exit(-1);
			}
		}
		/* trim trailing whitespace */
		end = strchrnul(src, '\n');
		for (n = end - src; n > 0 && isspace(src[n - 1]); n--)
			;
		memcpy(dst, src, n);
		dst += n;
		if (*end)
			*dst++ = '\n';
		src = *end ? end + 1 : end;
	}
	*dst++ = '\0';

	/* print out using adjusted template */
	va_start(args, template);
	n = vprintf(s, args);
	va_end(args);

	free(s);
}

/**
 * bpftool gen skeleton xxx.bpf.o > xxx.skel.h
 */
static int do_skeleton(int argc, char **argv)
{
	char header_guard[MAX_OBJ_NAME_LEN + sizeof("__SKEL_H__")];
	size_t map_cnt = 0, prog_cnt = 0, file_sz, mmap_sz;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
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
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		printf("failed to open() %s: %s\n", file, strerror(errno));
		return -1;
	}
	obj_data = mmap(NULL, mmap_sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (obj_data == MAP_FAILED) {
		obj_data = NULL;
		printf("failed to mmap() %s: %s\n", file, strerror(errno));
	}
	if (obj_name[0] == '\0') {
		get_obj_name(obj_name, file);
	}
	opts.object_name = obj_name;
	if (verifier_logs) {
		/* log_level1 + log_level2 + stats, but not stable UAPI */
		opts.kernel_log_level = 1 + 2 + 4;
	}
	obj = bpf_object__open_mem(obj_data, file_sz, &opts);
	if (!obj) {
		char err_buf[256];

		err = -errno;
		libbpf_strerror(err, err_buf, sizeof(err_buf));
		printf("failed to open BPF object file: %s", err_buf);
		goto out;
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident))) {
			printf("ignoring unrecognized internal map '%s'...\n",
			      bpf_map__name(map));
			continue;
		}
		map_cnt++;
	}
	bpf_object__for_each_program(prog, obj) {
		prog_cnt++;
	}

	get_header_guard(header_guard, obj_name, "SKEL_H");
	if (use_loader) {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
		/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */		    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <bpf/skel_internal.h>				    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_loader_ctx ctx;			    \n\
		",
		obj_name, header_guard
		);
	} else {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
									    \n\
		/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */		    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <errno.h>					    \n\
		#include <stdlib.h>					    \n\
		#include <bpf/libbpf.h>					    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_object_skeleton *skeleton;		    \n\
			struct bpf_object *obj;				    \n\
		",
		obj_name, header_guard
		);
	}

	if (map_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_map(map, obj) {
			if (!get_map_ident(map, ident, sizeof(ident)))
				continue;
			if (use_loader)
				printf("\t\tstruct bpf_map_desc %s;\n", ident);
			else
				printf("\t\tstruct bpf_map *%s;\n", ident);
		}
		printf("\t} maps;\n");
	}

	if (prog_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tstruct bpf_prog_desc %s;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_program *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} progs;\n");
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tint %s_fd;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_link *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} links;\n");
	}

	btf = bpf_object__btf(obj);
out:
	return err;
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
