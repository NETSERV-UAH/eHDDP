/* SPDX-License-Identifier: GPL-2.0 
 *
 *
 * Modified archive of the xdp-project (github.com/xdp-project) repository
 * for purely academic purposes.
 *
 *	Author: Joaquin Alvarez <j.alvare@gmail.com>
 *	Date:   29 Jan 2020
 */

#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define NUM_MAC_MAC 256

struct bpf_map_def SEC("maps") list_mac_addr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = sizeof(__u32),
	.max_entries = NUM_MAC_MAC,
};

SEC("xdp_filter_packet")
int xdp_filter_packet_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int *do_action;

	__u32 action = XDP_DROP;

	
	//bpf_trace_printk("Paso 1 -> action: %d\n", action);

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;
	if (parse_ethhdr(&nh, data_end, &eth) == -1)
		goto out;

	//bpf_trace_printk("paso 2 -> ETH: %d\n", eth->h_source[3]);
	
	/* Do we know where to redirect this packet? */
	do_action = bpf_map_lookup_elem(&list_mac_addr, eth->h_source);
	if (!do_action)
		action = XDP_DROP;
	else
		action = (__u32)(* do_action);
	
	//bpf_trace_printk("paso 3 -> action: %d\n", action);

	goto out;

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass") // to debug
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
