// This code is taken from:
// https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright 2016 Netflix, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#define KBUILD_MODNAME "rust-bcc-xdp-drop"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <uapi/linux/bpf.h>

// parse the ip layer header
static __always_inline u32 parse_ipv4(struct xdp_md* ctx, u64 l3_offset) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct iphdr* iph = data + l3_offset;
  u64* value;
  u32 ip_src; /* type need to match map */

  /* Hint: +1 is sizeof(struct iphdr), because pointer also has it's type */
  if (iph + 1 > data_end) {
    bpf_trace_printk("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
    return XDP_ABORTED;
  }
  /* Extract key */
  ip_src = iph->saddr;
  bpf_trace_printk("Valid IPv4 packet: raw saddr:0x%x\n", ip_src);

  // BLACKLIST FILTER

  return XDP_PASS;
}

// parse ethernet header, which is also the start of data, get the following items:
// 1. specified protocol type of ip layer (ipv4? ipv6? icmp?)
// 2. the offset of ip header
static __always_inline bool parse_eth(struct ethhdr* eth, void* data_end,
                                      u16* eth_proto, u64* l3_offset) {
  u16 eth_type;
  u64 offset;

  offset = sizeof(struct ethhdr);
  if ((void*)eth + offset > data_end) return false;

  eth_type = eth->h_proto;
  // bpf_trace_printk("Debug: eth_type:0x%x\n", ntohs(eth_type));

  /* Skip non 802.3 Ethertypes */
  if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN)) return false;

  void* data = (void*)eth;

  /* handle Double VLAN tagged packet */
  bpf_trace_printk("parse double vlan header");
  for (int i = 0; i < 2; i++) {
    if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
      struct vlan_hdr* vhdr;
      vhdr = data + offset;
      offset += sizeof(struct vlan_hdr);
      if (data + offset > data_end) return XDP_PASS;
      eth_type = vhdr->h_vlan_encapsulated_proto;
    }
  }

  *eth_proto = ntohs(eth_type);
  *l3_offset = offset;
  return true;
}

// handle ethernet protocol
static __always_inline u32 handle_eth_protocol(struct xdp_md* ctx,
                                               u16 eth_proto, u64 l3_offset) {
  switch (eth_proto) {
    case ETH_P_IP:
      return parse_ipv4(ctx, l3_offset);
    case ETH_P_IPV6: /* Not handler for IPv6 yet*/
    case ETH_P_ARP: /* Let OS handle ARP */
                    /* Fall-through */
    default:
      bpf_trace_printk("Not handling eth_proto:0x%x\n", eth_proto);
      return XDP_PASS;
  }
  return XDP_PASS;
}

int xdp_raw_parser(struct CTXTYPE* ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr* eth = data;
  u16 eth_proto = 0;
  u64 l3_offset = 0;
  u32 action;

  if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
    // bpf_trace_printk("Cannot parse L2: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);
    return XDP_PASS; /* Skip */
  }
  // bpf_trace_printk("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

  action = handle_eth_protocol(ctx, eth_proto, l3_offset);

  return XDP_PASS;
}
