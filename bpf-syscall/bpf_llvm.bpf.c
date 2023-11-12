//clang -target bpf -c ./bpf_llvm.bpf.c -o ./bpf_llvm.bpf.o
unsigned long prog(void)
{
	unsigned long a = 0x123;
	unsigned long b = 0x456;
	return a + b;
}
