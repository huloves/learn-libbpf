#ifndef _LIBBPF_COMMON_H
#define _LIBBPF_COMMON_H

/* Helper macro to declare and initialize libbpf options struct
 *
 * This dance with uninitialized declaration, followed by memset to zero,
 * followed by assignment using compound literal syntax is done to preserve
 * ability to use a nice struct field initialization syntax and **hopefully**
 * have all the padding bytes initialized to zero. It's not guaranteed though,
 * when copying literal, that compiler won't copy garbage in literal's padding
 * bytes, but that's the best way I've found and it seems to work in practice.
 *
 * Macro declares opts struct of given type and name, zero-initializes,
 * including any extra padding, it with memset() and then assigns initial
 * values provided by users in struct initializer-syntax as varargs.
 */
#define LIBBPF_OPTS(TYPE, NAME, ...)					    \
	struct TYPE NAME = ({ 						    \
		memset(&NAME, 0, sizeof(struct TYPE));			    \
		(struct TYPE) {						    \
			.sz = sizeof(struct TYPE),			    \
			__VA_ARGS__					    \
		};							    \
	})

#endif /* _LIBBPF_COMMON_H */
