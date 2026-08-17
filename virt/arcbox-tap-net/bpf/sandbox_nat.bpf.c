/* Sandbox invariant-NAT TCX programs (CORE-83).
 *
 * Every sandbox guest owns the fixed link-local identity 169.254.100.2
 * (CORE-81); its external pool IP exists only host-side, as a property of
 * the sandbox's TAP.  These two programs apply that identity translation on
 * the TAP itself, replacing the per-TAP iptables mark/DNAT/SNAT chain and
 * the fwmark policy-routing machinery:
 *
 * - `sandbox_nat_ingress` (TCX ingress, packets FROM the guest): drops
 *   sandbox-to-sandbox pool traffic (isolation), then rewrites the invariant
 *   source address to the TAP's pool IP.  Runs before netfilter and routing,
 *   so conntrack and rp_filter only ever see the pool identity.
 * - `sandbox_nat_egress` (TCX egress, packets TO the guest, post-routing):
 *   rewrites the pool destination back to the invariant guest address.
 *   Steering is done by the main routing table alone (a per-TAP
 *   `pool_ip via 169.254.100.2 dev tapX onlink` route).
 *
 * IPv4 only — IPv6 and ARP pass through untouched, matching the iptables
 * rule set this replaces.  Checksum discipline: incremental L3 fixup always;
 * L4 pseudo-header fixup for TCP/UDP on first fragments only (non-first
 * fragments carry no L4 header, ICMP's checksum has no pseudo-header, and a
 * zero UDP checksum means "uncomputed" and stays zero).
 *
 * The object is compiled offline (`cargo xtask dev bpf`) and committed next
 * to this source; `src/network/ebpf.rs` embeds and loads it.  No kernel or
 * libbpf headers are used so the program builds with any clang that has the
 * BPF backend — the few UAPI shapes needed are declared below and are
 * stable kernel ABI.  Requires only classic maps and helpers (no BTF/CO-RE).
 *
 * Map contract with the loader (src/network/ebpf.rs):
 * - SANDBOX_NAT:      HASH  ifindex (host order) -> pool IP (network order)
 * - SANDBOX_NAT_POOL: ARRAY [0] pool network, [1] pool netmask,
 *                           [2] pool gateway (all network order); written
 *                           once before any attach.  A zero netmask disables
 *                           the isolation check (unconfigured).
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

/* Leading fields of the UAPI `struct __sk_buff` context (linux/bpf.h).
 * Only `protocol` (offset 16) and `ifindex` (offset 40) are read; the
 * verifier checks ctx offsets, not the declared struct size. */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
};

struct iphdr {
    __u8 ver_ihl;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

/* Legacy (pre-BTF) map definition, parsed from the `maps` section. */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

/* BPF helpers by UAPI id (bpf_helper_defs.h equivalents). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
                                   const void *from, __u32 len,
                                   __u64 flags) = (void *)9;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to,
                                   __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to,
                                   __u64 flags) = (void *)11;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
                                  void *to, __u32 len) = (void *)26;

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BPF_F_PSEUDO_HDR 0x10
#define BPF_F_MARK_MANGLED_0 0x20
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_F_NO_PREALLOC 1
#define IP_FRAG_OFFSET_MASK 0x1fff

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#endif

/* 169.254.100.2 — arcbox_vm::network::invariant::GUEST_IP. */
#define GUEST_IP_BE bpf_htonl(0xa9fe6402)

/* Indices into SANDBOX_NAT_POOL. */
#define POOL_NET 0
#define POOL_MASK 1
#define POOL_GATEWAY 2

__attribute__((section("maps"), used)) struct bpf_map_def SANDBOX_NAT = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 65536,
    .map_flags = BPF_F_NO_PREALLOC,
};

__attribute__((section("maps"), used)) struct bpf_map_def SANDBOX_NAT_POOL = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 3,
};

/* Rewrite one IP address (saddr or daddr, selected by `addr_off`) from `old`
 * to `new`, keeping the L3 header checksum and — where one exists and covers
 * the pseudo-header — the L4 checksum incrementally correct.  Returns
 * nonzero on helper failure; the callers drop such packets rather than emit
 * a half-rewritten one. */
static __attribute__((always_inline)) int
rewrite_addr(struct __sk_buff *skb, const struct iphdr *iph, __u32 addr_off,
             __u32 old, __u32 new)
{
    __u32 l4_off = ETH_HLEN + (__u32)(iph->ver_ihl & 0x0f) * 4;

    /* Non-first fragments carry no L4 header. */
    if ((bpf_ntohs(iph->frag_off) & IP_FRAG_OFFSET_MASK) == 0) {
        if (iph->protocol == IPPROTO_TCP) {
            if (bpf_l4_csum_replace(skb, l4_off + 16, old, new,
                                    BPF_F_PSEUDO_HDR | sizeof(new)))
                return -1;
        } else if (iph->protocol == IPPROTO_UDP) {
            __u16 csum = 0;
            if (bpf_skb_load_bytes(skb, l4_off + 6, &csum, sizeof(csum)))
                return -1;
            /* Zero means "no checksum computed"; leave it zero. */
            if (csum != 0 &&
                bpf_l4_csum_replace(skb, l4_off + 6, old, new,
                                    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 |
                                        sizeof(new)))
                return -1;
        }
        /* ICMP: its checksum does not cover the pseudo-header. */
    }
    if (bpf_l3_csum_replace(skb, ETH_HLEN + 10, old, new, sizeof(new)))
        return -1;
    if (bpf_skb_store_bytes(skb, addr_off, &new, sizeof(new), 0))
        return -1;
    return 0;
}

/* Packets FROM the guest: isolation, then invariant source -> pool IP. */
__attribute__((section("classifier"), used)) int
sandbox_nat_ingress(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)))
        return TC_ACT_OK;
    /* This program only attaches to invariant TAPs, where the guest's one
     * legitimate IPv4 source is the fixed address. Anything else is forged
     * by construction — passing it through would skip both the map-miss
     * drop and the pool isolation below, and with onlink steering a forged
     * source could reach another sandbox's TAP. */
    if (iph.saddr != GUEST_IP_BE)
        return TC_ACT_SHOT;

    __u32 ifindex = skb->ifindex;
    __u32 *pool_ip = bpf_map_lookup_elem(&SANDBOX_NAT, &ifindex);
    /* The invariant source on a TAP without a translation entry is a
     * misconfiguration; never let the fixed address leak off the link. */
    if (!pool_ip)
        return TC_ACT_SHOT;

    /* Sandbox-to-sandbox isolation: the pool is reachable only at the TAP's
     * own external identity and the pool gateway (legacy DNS). */
    __u32 net_key = POOL_NET, mask_key = POOL_MASK, gw_key = POOL_GATEWAY;
    __u32 *net = bpf_map_lookup_elem(&SANDBOX_NAT_POOL, &net_key);
    __u32 *mask = bpf_map_lookup_elem(&SANDBOX_NAT_POOL, &mask_key);
    __u32 *gateway = bpf_map_lookup_elem(&SANDBOX_NAT_POOL, &gw_key);
    if (net && mask && gateway && *mask != 0 &&
        (iph.daddr & *mask) == *net && iph.daddr != *pool_ip &&
        iph.daddr != *gateway)
        return TC_ACT_SHOT;

    if (rewrite_addr(skb, &iph, ETH_HLEN + 12, iph.saddr, *pool_ip))
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

/* Packets TO the guest (post-routing): pool IP -> invariant destination. */
__attribute__((section("classifier"), used)) int
sandbox_nat_egress(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)))
        return TC_ACT_OK;

    __u32 ifindex = skb->ifindex;
    __u32 *pool_ip = bpf_map_lookup_elem(&SANDBOX_NAT, &ifindex);
    if (!pool_ip || iph.daddr != *pool_ip)
        return TC_ACT_OK;

    if (rewrite_addr(skb, &iph, ETH_HLEN + 16, iph.daddr, GUEST_IP_BE))
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

__attribute__((section("license"), used)) char _license[] = "Dual MIT/GPL";
