// #include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, long);
} cnt SEC(".maps");

// struct bpf_map_def {
// 	unsigned int type;
// 	unsigned int key_size;
// 	unsigned int value_size;
// 	unsigned int max_entries;
// 	unsigned int map_flags;
// };

// struct bpf_map_def SEC("maps") cnt = {
//         .type = BPF_MAP_TYPE_ARRAY,
//         .key_size = sizeof(__u32),
//         .value_size = sizeof(long),
//         .max_entries = 2,
// };

SEC("xdp_count_btf")
int xdp_count_prog(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u32 ipv6_key = 0;
        __u32 ipv4_key = 1;
        long *value;
        __u16 h_proto;
        struct ethhdr *eth = data;
        if (data + sizeof(struct ethhdr) > data_end) // This check is necessary to pass verification
                return XDP_DROP;
        
        h_proto = eth->h_proto;
        if (h_proto == htons(ETH_P_IPV6)) { // Check if IPv6 packet
                value = bpf_map_lookup_elem(&cnt, &ipv6_key);
                if (value)
                        *value += 1;
                return XDP_PASS;
        }
        value = bpf_map_lookup_elem(&cnt, &ipv4_key);
        if (value)
            *value += 1;
        return XDP_PASS;

}

char _license[] SEC("license") = "GPL";

