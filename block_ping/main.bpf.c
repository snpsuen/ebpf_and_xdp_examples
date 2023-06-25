

#include "vmlinux.h"
#include "main.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define htons(x) ((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))
#define htonl(x) (((uint32_t) ((((x) & 0x000000ff) << 24) | \
                                 (((x) & 0x0000ff00) << 8)  | \
                                 (((x) & 0x00ff0000) >> 8)  | \
                                 (((x) & 0xff000000) >> 24))))



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint32_t);
} ping_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int detect_ping(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct data_t *msg = NULL;
    int ret = XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

    
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end) {
        return  XDP_PASS;

    }

    
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }


    if (ip->protocol == 1) {
        bpf_printk("----------");
        bpf_printk("Hello ping");

        if (bpf_map_lookup_elem(&ping_hash, &ip->daddr) || bpf_map_lookup_elem(&ping_hash, &ip->saddr)) {
            bpf_printk("found element in hash %d", ip->daddr);
            return XDP_DROP;
        } 
        bpf_printk("not found element in hash %d", ip->daddr);
        bpf_printk("not found element in hash %d", ip->saddr);
    }

    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
