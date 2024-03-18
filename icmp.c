#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "icmp.skel.h"

typedef unsigned int u32;
typedef unsigned long long u64;

static int my_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    struct icmp_bpf *skel;
    struct bpf_link *link = NULL;

    libbpf_set_print(my_libbpf_print_fn);

    skel = icmp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(skel->obj, "ping");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        icmp_bpf__destroy(skel);
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        link = NULL;
        icmp_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully attached BPF program to %s\n", ifname);

    printf("Monitoring ICMP echo requests. Press Ctrl+C to stop.\n");
    while (1) {
        u32 key, next_key;
        u64 value;
        int fd = bpf_map__fd(skel->maps.ping_counter);
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
                printf("IP: %d.%d.%d.%d - Count: %llu\n",
                       (next_key & 0xFF), (next_key >> 8) & 0xFF,
                       (next_key >> 16) & 0xFF, next_key >> 24, value);
            }
            key = next_key;
        }
        sleep(1);
    }

    // Cleanup
    bpf_link__destroy(link);
    icmp_bpf__destroy(skel);

    return 0;
}