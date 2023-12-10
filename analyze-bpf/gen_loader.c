#include "bpf_gen_internal.h"

void bpf_gen__free(struct bpf_gen *gen)
{
	if (!gen)
		return;
	free(gen->data_start);
	free(gen->insn_start);
	free(gen);
}
