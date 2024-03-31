#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif


typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); 
    __type(key, u32); 
    __type(value, u64); 
} ping_counter SEC(".maps");


static __always_inline u16 csum_fold_helper(u32 csum) {
    u32 r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;
    return (u16)(csum >> 16);
}

static __always_inline u16 csum_update(u16 old_csum, u16 old_field, u16 new_field) {
    u32 csum = ~((u32)old_csum) & 0xFFFF;
    csum += ~((u32)old_field) & 0xFFFF;
    csum += new_field;
    return csum_fold_helper(csum);
}

static __always_inline void swap_mac_addresses(struct ethhdr *eth) {
    u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);
}

static __always_inline void swap_ip_addresses(struct iphdr *iph) {
    u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;
}

static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void*)iph + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

SEC("xdp")
int ping(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    long protocol = lookup_protocol(ctx);

    if (protocol == IPPROTO_ICMP) {
        struct ethhdr *eth = data;
        struct iphdr *iph = data + sizeof(struct ethhdr);
        struct icmphdr *icmph = (void *)(iph + 1);

        u32 src_ip = iph->saddr;
        u64 *counter;
        u64 new_count = 0;

        counter = bpf_map_lookup_elem(&ping_counter, &src_ip);
        if (counter) {
            new_count = *counter + 1;
        } else {
            new_count = 1;
        }

        // Update the map with the new count
        bpf_map_update_elem(&ping_counter, &src_ip, &new_count, BPF_ANY);
        // bpf_printk("Updating counter for IP: %x, new count: %d\n", src_ip, new_count);
        
        if ((void *)icmph + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;

        if (icmph->type == ICMP_ECHO) {
            swap_mac_addresses(eth);
            swap_ip_addresses(iph);
            icmph->checksum = csum_update(icmph->checksum, icmph->type, ICMP_ECHOREPLY);
            icmph->type = ICMP_ECHOREPLY;
            // bpf_printk("Hello ping request");
 
            return XDP_TX;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
