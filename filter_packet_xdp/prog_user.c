/* SPDX-License-Identifier: GPL-2.0 
 *
 *
 * Modified archive of the xdp-project (github.com/xdp-project) repository
 * for purely academic purposes.
 *
 *	Author: Joaquin Alvarez <j.alvarez.horcajo@gmail.com>
 *	Date:   02 Abr 2020
 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/if_xdp.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

#define NUM_MAC_MAC 256

struct configure_uah {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char mac_list_accept[(18+1)*NUM_MAC_MAC];
	char mac_list_drop[(18+1)*NUM_MAC_MAC];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
};

static const struct option_wrapper long_options[] = {

	{{"help", no_argument, NULL, 'h' },
	 "Show help", false},

	{{"dev",required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"mac-list-accept",optional_argument, NULL, 'L' },
	 "MAC List accepted -> <MACS_Accetps>,<MACS_Accetps>,...<MACS_Accetps>", "<MACS_Accetps>", true},

	{{"mac-list-drop",optional_argument, NULL, 'R' },
	 "MAC List accepted -> <MACS_drops>,<MACS_drops>,...<MACS_drops>", "<MACS_drops>", true},

	{{0, 0, NULL, 0}, NULL, false}
};

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int write_macs_params(int map_fd, unsigned char *src, __u32 action)
{
	//BPF_ANY = 0
	if (bpf_map_update_elem(map_fd, src, &action, 0) < 0) {
		fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x -> ACTION: %d\n",
			src[0], src[1], src[2], src[3], src[4], src[5], action
	      );

	return 0;
}


void parse_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct configure_uah *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	int opt;

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:r:L:R:ASNFUMQ:czpq",long_options, &longindex)) != -1) {
		switch (opt) {
		case 'h':
			full_help = true;
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'r':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
						"ERR: --redirect-dev name unknown err(%d):%s\n",
						errno, strerror(errno));
				goto error;
			}
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 3: /* --offload-mode */
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_HW_MODE;   /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'M':
			cfg->reuse_maps = true;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'p':
			cfg->xsk_poll_mode = true;
			break;
		case 'q':
			verbose = false;
			break;
		case 'Q':
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 'L': /* --lista de mac accept */
			dest  = (char *)&cfg->mac_list_accept;
			strncpy(dest, optarg, sizeof(cfg->mac_list_accept));
			break;
		case 'R': /* --lista de mac drop */
			dest  = (char *)&cfg->mac_list_drop;
			strncpy(dest, optarg, sizeof(cfg->mac_list_drop));
		case 'c':
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'z':
			cfg->xsk_bind_flags &= XDP_COPY;
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;
			break;

			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len, map_fd, num_mac_accept = 0, num_mac_drop = 0, pos = 0; //, value = 0;
	char *mac_aux;
	char pin_dir[PATH_MAX];
	char delim[] = ",";
	unsigned char mac_list[256][ETH_ALEN];

	struct configure_uah cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (!cfg.mac_list_accept && !cfg.mac_list_drop){
		fprintf(stderr, "ERR: you must include almost a mac accept list or a mac drop list\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = open_bpf_map_file(pin_dir, "list_mac_addr", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	
	printf("map dir: %s\n", pin_dir);

	if (cfg.mac_list_accept){
		mac_aux = strtok(cfg.mac_list_accept, delim);
		while(mac_aux != NULL)
		{
			printf("MAC ACCEPT ->'%s'\n", mac_aux);
			if (parse_mac(mac_aux, mac_list[pos])< 0) {
				fprintf(stderr, "ERR: can't parse mac address %s\n", mac_aux);
				return EXIT_FAIL_OPTION;
			}
			mac_aux = strtok(NULL, delim);
			num_mac_accept++;
			pos++;
		}
		if (num_mac_accept > 0){
			for (pos = 0; pos < num_mac_accept; pos ++){
				/* Setup the mapping containing MAC addresses */
				/*if (bpf_map_lookup_elem(map_fd, mac_list[pos], &value) == 0)
					printf("MAC ->%02x:%02x:%02x:%02x:%02x:%02x and value -> %d\n", 
						mac_list[pos][0], mac_list[pos][1], mac_list[pos][2], mac_list[pos][3], mac_list[pos][4], mac_list[pos][5], value);*/

				if (write_macs_params(map_fd, mac_list[pos], XDP_PASS) < 0) {
					fprintf(stderr, "can't write iface params\n");
					return EXIT_FAIL;
				}
				/*if (bpf_map_lookup_elem(map_fd, mac_list[pos], &value) == 0)
					printf("MAC ->%02x:%02x:%02x:%02x:%02x:%02x and value -> %d\n", 
						mac_list[pos][0], mac_list[pos][1], mac_list[pos][2], mac_list[pos][3], mac_list[pos][4], mac_list[pos][5], value);*/
			}
		}
	}

	if (cfg.mac_list_drop){
		mac_aux = strtok(cfg.mac_list_drop, delim);
		pos = 0;
		while(mac_aux != NULL)
		{
			printf("MAC DROP ->'%s'\n", mac_aux);
			if (parse_mac(mac_aux, mac_list[pos])< 0) {
				fprintf(stderr, "ERR: can't parse mac address %s\n", mac_aux);
				return EXIT_FAIL_OPTION;
			}
			mac_aux = strtok(NULL, delim);
			num_mac_drop++;
			pos++;
		}
		if (num_mac_drop > 0){
			for (pos = 0; pos < num_mac_drop; pos ++){
				/*if (bpf_map_lookup_elem(map_fd, mac_list[pos], &value) == 0)
					printf("MAC ->%02x:%02x:%02x:%02x:%02x:%02x and value -> %d\n", 
						mac_list[pos][0], mac_list[pos][1], mac_list[pos][2], mac_list[pos][3], mac_list[pos][4], mac_list[pos][5], value);*/
				/* Setup the mapping containing MAC addresses */
				if (write_macs_params(map_fd, mac_list[pos], XDP_DROP) < 0) {
					fprintf(stderr, "can't write iface params\n");
					return EXIT_FAIL;
				}
				/*if (bpf_map_lookup_elem(map_fd, mac_list[pos], &value) == 0)
					printf("MAC ->%02x:%02x:%02x:%02x:%02x:%02x and value -> %d\n", 
					mac_list[pos][0], mac_list[pos][1], mac_list[pos][2], mac_list[pos][3], mac_list[pos][4], mac_list[pos][5], value);*/
			}
		}
	}
	
	return EXIT_OK;
}
