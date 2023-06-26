#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>





#include "main.h"
#include "main.skel.h"


void handle_sigint(int sig) {
    printf("Terminating\n");
    exit(0);
}


static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}


int handle_event(void *ctx, void *data, size_t len)  {
    printf("got ping?\n");
    return 0;
}


int main(int argc, char *argv[]) {
    int err;

    if (argc != 2) {
       printf("Provide interface name\n"); 
    }



    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    // Initialize libbpf
    libbpf_set_print(libbpf_print);

    // Load and verify BPF application
    struct main_bpf *skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    /* Attach BPF to network interface */
    unsigned int ifindex = if_nametoindex(argv[1]);
    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.detect_ping, ifindex);
    if (!link) {
        fprintf(stderr, "bpf_program__attach_xdp\n");
        return 1;
    }


    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "ringbuf");
    if (!map) {
        fprintf(stderr, "Failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");


    struct bpf_map *map_hash = bpf_object__find_map_by_name(skel->obj, "ping_hash");
    if (!map_hash) {
        fprintf(stderr, "!map_hash\n");
        return 1;
    }

    uint32_t ip = htonl(0x08080808);
    uint32_t ip2 = 134744072;
    uint32_t ip3 = 0x08080808;
    uint32_t ip4 = 167880896;


    const char* ip_host_str = "192.168.1.10";
    uint32_t ip_host;
    inet_pton(AF_INET, ip_host_str, &ip_host);

    const char* ip_server_str = "8.8.8.8";
    uint32_t ip_server;
    inet_pton(AF_INET, ip_server_str, &ip_server);

    printf("ip_server: %d\n", ip_server);
    printf("ip_host: %d\n", ip_host);

    /*
    err = bpf_map__update_elem(map_hash, &ip_host, sizeof(uint32_t), &ip_host, sizeof(uint32_t), BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update element in ping_hash\n");
        return 1;
    }
    */
    err = bpf_map__update_elem(map_hash, &ip_server, sizeof(uint32_t), &ip_server, sizeof(uint32_t), BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update element in ping_hash\n");
        return 1;
    }
    
    
    



    // Poll the ring buffer
    while (1)
    {
        if (ring_buffer__poll(rb, 1000 /* timeout, ms */) < 0)
        {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
