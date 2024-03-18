#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#define PIN_BASE_DIR "/sys/fs/bpf"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ifname> <ebpf_program_path>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];
    char *ebpf_program_path = argv[2];
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: could not find interface '%s'\n", ifname);
        return -1;
    }

    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, err;
    char pin_path[256];

    snprintf(pin_path, sizeof(pin_path), "%s/%s", PIN_BASE_DIR, "xdp/pinned_prog");

    // Open and load the eBPF object file
    obj = bpf_object__open_file(ebpf_program_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object file: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load eBPF object: %s\n", strerror(errno));
        return -1;
    }

    // Pinning the program
    prog = bpf_object__find_program_by_name(obj, "ping");
    if (!prog) {
        fprintf(stderr, "Failed to find eBPF program in object\n");
        return -1;
    }

    err = bpf_program__pin(prog, pin_path);
    if (err) {
        fprintf(stderr, "Failed to pin BPF program: %s\n", strerror(-err));
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    
    // Attach the program
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program to interface %s: %s\n", ifname, strerror(-err));
        bpf_object__unpin_programs(obj, PIN_BASE_DIR); // Cleanup if attachment fails
        return -1;
    }

    printf("eBPF program attached and pinned to interface %s at %s\n", ifname, pin_path);
    return 0;
}