

#include "vmlinux.h"
#include "main.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define htons(x) ((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} ping_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int detect_ping(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct data_t msg = { 0 };
    int ret;

    return XDP_DROP;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

    
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end) {
        ret =  XDP_PASS;
        goto xdp_out;
    }

    
    if (eth->h_proto != htons(ETH_P_IP)) {
        ret = XDP_PASS;  // not an IPv4 packet
        goto xdp_out;
    }

    
    msg.dst = ip->daddr; // Extracting the destination IP
    //bpf_probe_read(&msg.dst, sizeof(msg.dst), &ip->daddr);


    xdp_out:
    bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);
    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
