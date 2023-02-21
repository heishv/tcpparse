/***************************************************************
  Copyright (c) 2019 ShenZhen Heishv Technology, Inc.

  The right to copy, distribute, modify or otherwise make use
  of this software may be licensed only pursuant to the terms
  of an applicable ShenZhen Heishv license agreement.
***************************************************************/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include "tcpparse.h"
#include "crc.h"

CAP_SWAP_2 swap2 = NULL;
CAP_SWAP_4 swap4 = NULL;

uint16_t force_swap2(uint16_t input)
{
    return ((((unsigned short)(input) & 0x000000FF)<<8) | \
            (((unsigned short)(input) & 0x0000FF00)>>8));
}
uint16_t no_swap2(uint16_t input)
{
    return input;
}

uint32_t force_swap4(uint32_t input)
{
    return ((((unsigned int)(input) & 0x000000FF)<<24) | \
            (((unsigned int)(input) & 0x0000FF00)<<8)  | \
            (((unsigned int)(input) & 0x00FF0000)>>8)  | \
            (((unsigned int)(input) & 0xFF000000)>>24));
}
uint32_t no_swap4(uint32_t input)
{
    return input;
}

static void print_usage(char *progname)
{
    /** Get rid of path in filename - only for unix-type paths using '/' */
    #define NO_PATH(file_name) (strrchr((file_name), '/') ? \
                     strrchr((file_name), '/') + 1 : (file_name))
    printf("\n"
            "Parse pcap file to extract ip, port, checksum, payload, etc.\n"
            "\n"
            "Usage: %s [OPTIONS] filename\n"
            "\n"
            "OPTIONS:\n"
            "  -h, --help     Display help and exit.\n"
            "  -i, --index    Target packet index in pcap file, default is 1.\n"
            "  -l, --length   Length of whole packet.\n"
            "      --sm       Source mac.\n"
            "      --dm       Destination mac.\n"
            "  -t, --ethtype  Ethernet type.\n"
            "  -s, --sip      Source ip.\n"
            "  -d, --dip      Destination ip.\n"
            "  -p, --proto    Protocol in ip header.\n"
            "      --sp       Source port if tcp and udp, return 0 for other protocol.\n"
            "      --dp       Destination port if tcp and udp, return 0 for other protocol.\n"
            "      --checkl3  Verify ip header checksum, return 0 if success, or return 1.\n"
            "      --checkl4  Verify udp/tcp checksum, return 0 if success, or return 1.\n"
            "      --pl       Print payload.\n"
            "\n", NO_PATH(progname)
         );
}

static void parse_args(int argc, char *argv[], uint32_t *index, uint32_t *field, char *filename)
{
    int                 opt;
    int                 long_index;
    int                 tmp;

    static struct option longopts[] = {
        {"help",      no_argument,       NULL, 'h'},
        {"index",     required_argument, NULL, 'i'},
        {"length",    no_argument,       NULL, 'l'},
        {"proto",     no_argument,       NULL, 'p'},
        {"sm",        no_argument,       NULL, CAP_OPTION_SM},
        {"dm",        no_argument,       NULL, CAP_OPTION_DM},
        {"ethtype",   no_argument,       NULL, 't'},
        {"si",        no_argument,       NULL, 's'},
        {"di",        no_argument,       NULL, 'd'},
        {"sp",        no_argument,       NULL, CAP_OPTION_SP},
        {"dp",        no_argument,       NULL, CAP_OPTION_DP},
        {"checkl3",   no_argument,       NULL, CAP_OPTION_CHECKL3},
        {"checkl4",   no_argument,       NULL, CAP_OPTION_CHECKL4},
        {"pl",        no_argument,       NULL, CAP_OPTION_PL},
        {NULL,        0,                 NULL, 0}
    };

    while (optind < argc) {
        /* x   No parameter */
        /* x:  Follow a parameter */
        if ((opt = getopt_long(argc, argv, "hi:ltsdp1234567", longopts, &long_index)) != -1) {
            switch (opt) {
                case 'h':
                    print_usage(argv[0]);
                    exit(EXIT_SUCCESS);

                /* parse tcp port for command line access */
                case 'i':
                    tmp = atoi(optarg);
                    if (tmp < 1) {
                        printf("Index start from 1, please fill correct index number.\n");
                        exit(EXIT_SUCCESS);
                    }
                    else {
                        *index = tmp;
                    }
                    break;

                case 'l':
                    if (*field == CAP_OPTION_NONE) {
                        *field = CAP_OPTION_LEN;
                    }
                    break;

                case 't':
                    if (*field == CAP_OPTION_NONE) {
                        *field = CAP_OPTION_ETH_TYPE;
                    }
                    break;

                case 'p':
                    if (*field == CAP_OPTION_NONE) {
                        *field = CAP_OPTION_PROTO;
                    }
                    break;

                case 's':
                    if (*field == CAP_OPTION_NONE) {
                        *field = CAP_OPTION_SI;
                    }
                    break;

                case 'd':
                    if (*field == CAP_OPTION_NONE) {
                        *field = CAP_OPTION_DI;
                    }
                    break;

                case CAP_OPTION_SM:
                case CAP_OPTION_DM:
                case CAP_OPTION_SI:
                case CAP_OPTION_DI:
                case CAP_OPTION_SP:
                case CAP_OPTION_DP:
                case CAP_OPTION_CHECKL3:
                case CAP_OPTION_CHECKL4:
                case CAP_OPTION_PL:
                    if (*field == CAP_OPTION_NONE) {
                        *field = opt;
                    }
                    break;

                default:
                    goto out;
                    break;
            }
        }
        else {
            strcpy(filename, argv[optind]);
            optind++;
        }
    }

    optind = 1;     /* reset 'extern optind' from the getopt lib */
    return;

out:
    exit(EXIT_FAILURE);
}

/* dissect ipv4 packets ip header */
static struct pro_ipv4_hdr *pkt_get_l3_header(uint8_t *buf, int len)
{
    struct pro_eth_hdr *eth;
    uint16_t eth_type;

    /* dissect from ethernet */
    /* eth header */
    eth = (struct pro_eth_hdr *)buf;
    eth_type = ntohs(eth->eth_type);

    if (ETH_PRO_IP == eth_type) {
        return (struct pro_ipv4_hdr *)(eth + 1);
    }
    /* if vlan exsit, max two vlan header supported */
    /* we don't need save vlan info, it will be found in PDR */
    else if ((ETH_PRO_8021Q == eth_type)||(ETH_PRO_8021AD == eth_type))  {
        /* outer vlan */
        struct pro_vlan_hdr *outer_vlan;

        outer_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN);
        eth_type = ntohs(outer_vlan->eth_type);

        if (ETH_PRO_IP == eth_type) {
            return (struct pro_ipv4_hdr *)(outer_vlan + 1);
        }
        /* inner vlan */
        else if ((ETH_PRO_8021Q == eth_type)||(ETH_PRO_8021AD == eth_type)) {
            struct pro_vlan_hdr *inner_vlan;

            inner_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN + ETH_HLEN);

            if (ETH_PRO_IP == ntohs(inner_vlan->eth_type)) {
                return (struct pro_ipv4_hdr *)(inner_vlan + 1);
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    uint32_t            index = 1;
    uint32_t            field = CAP_OPTION_NONE;
    char                filename[256];
    int                 fcap;
    int                 len;
    int                 left;
    int                 read_len;
    int                 ret = OK;
    uint32_t            cur_id;
    uint32_t            ip_tmp;
    uint8_t             pkt[12000];
    cap_global_hdr      glb_hdr;
    cap_packet_hdr      pkt_hdr;
    struct pro_ipv4_hdr *ip_header;
    struct pro_eth_hdr  *eth_header;
    struct pro_udp_hdr  *udp_header;
    struct pro_tcp_hdr  *tcp_header;

    /* Parse args */
    filename[0] = 0;
    parse_args(argc, argv, &index, &field, filename);

    /* Open file */
    if (filename[0] != 0) {
        fcap = open(filename, O_RDONLY);
        if (fcap < 0) {
            printf("Open %s failed.\n", filename);
            ret = ERROR;
            goto out;
        }
    }
    else {
        printf("File %s not exist.\n", filename);
        ret = ERROR;
        goto out;
    }

    /* Read global header */
    len = read(fcap, &glb_hdr, sizeof(cap_global_hdr));
    if (len != sizeof(cap_global_hdr)) {
        printf("File %s is too short, read global header failed.\n", filename);
        ret = ERROR;
        goto out;
    }

    /* Check order */
    if (glb_hdr.magic == CAP_MAGIC) {
        swap2 = no_swap2;
        swap4 = no_swap4;
    }
    else if (htonl(glb_hdr.magic) == CAP_MAGIC) {
        swap2 = force_swap2;
        swap4 = force_swap4;
    }
    else {
        printf("File %s is not in pcap format.\n", filename);
        ret = ERROR;
        goto out;
    }

    cur_id = 1;
    left = swap4(glb_hdr.snaplen) - sizeof(cap_global_hdr);
    while(left > 0) {
        /* 1. Read packet header */
        len = read(fcap, &pkt_hdr, sizeof(cap_packet_hdr));
        if (len != sizeof(cap_packet_hdr)) {
            printf("Reach end.\n");
            ret = ERROR;
            goto out;
        }
        if (cur_id != index) {
            if (left >= swap4(pkt_hdr.caplen)) {
                left -= len;
                lseek(fcap, swap4(pkt_hdr.caplen), SEEK_CUR);
                left -= swap4(pkt_hdr.caplen);
                cur_id++;
            }
            else {
                left = 0;
            }
            continue;
        }

        /* Get length */
        if (field == CAP_OPTION_LEN) {
            printf("%d\n", swap4(pkt_hdr.caplen));
            goto out;
        }

        left -= len;
        if (left <= 0) {
            break;
        }

        /* 2. Read packet */
        memset(pkt, 0, sizeof(pkt));
        read_len = min(swap4(pkt_hdr.caplen), sizeof(pkt));
        read_len = min(read_len, left);
        len = read(fcap, pkt, read_len);
        if (len != read_len) {
            printf("Read file %s failed.\n", filename);
            ret = ERROR;
            goto out;
        }

        /* Parse mac */
        eth_header = (struct pro_eth_hdr *)pkt;
        if (field == CAP_OPTION_SM) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_header->source[0], eth_header->source[1],
                eth_header->source[2], eth_header->source[3],
                eth_header->source[4], eth_header->source[5]);
            goto out;
        }
        if (field == CAP_OPTION_DM) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_header->dest[0], eth_header->dest[1],
                eth_header->dest[2], eth_header->dest[3],
                eth_header->dest[4], eth_header->dest[5]);
            goto out;
        }
        if (field == CAP_OPTION_ETH_TYPE) {
            printf("%04x\n", ntohs(eth_header->eth_type));
            goto out;
        }

        /* Parse packet */
        ip_header = pkt_get_l3_header(pkt, len);
        if (!ip_header) {
            printf("Can't find ip header.\n");
            ret = ERROR;
            goto out;
        }
        if (field == CAP_OPTION_SI) {
            ip_tmp = ntohl(ip_header->src_addr);
            printf("%d.%d.%d.%d\n", ip_tmp>>24, (ip_tmp>>16)&0xff, (ip_tmp>>8)&0xff, ip_tmp&0xff);
            goto out;
        }
        if (field == CAP_OPTION_DI) {
            ip_tmp = ntohl(ip_header->dst_addr);
            printf("%d.%d.%d.%d\n", ip_tmp>>24, (ip_tmp>>16)&0xff, (ip_tmp>>8)&0xff, ip_tmp&0xff);
            goto out;
        }
        if (field == CAP_OPTION_PROTO) {
            printf("%d\n", ip_header->proto);
            goto out;
        }
        if (field == CAP_OPTION_CHECKL3) {
            uint16_t checksum;
            uint16_t old_sum;

            old_sum = ip_header->check;
            ip_header->check = 0;
            checksum = calc_crc_ip(ip_header);
            ip_header->check = old_sum;
            if (checksum == old_sum) {
                printf("0\n");
            }
            else {
                printf("1\n");
            }
            goto out;
        }

        /* Parse L4 */
        if (ip_header->proto == IP_PRO_TCP) {
            tcp_header = (struct pro_tcp_hdr *)((uint8_t *)ip_header + (ip_header->ver_ihl << 2));
            if (field == CAP_OPTION_SP) {
                printf("%d\n", ntohs(tcp_header->source));
                goto out;
            }
            if (field == CAP_OPTION_DP) {
                printf("%d\n", ntohs(tcp_header->dest));
                goto out;
            }
            if (field == CAP_OPTION_CHECKL4) {
                uint16_t checksum;
                uint16_t old_l4_sum;

                old_l4_sum = tcp_header->check;
                tcp_header->check = 0;
                checksum = calc_crc_tcp(tcp_header, ip_header);
                tcp_header->check = old_l4_sum;
                if (checksum == old_l4_sum) {
                    printf("0\n");
                }
                else {
                    printf("1\n");
                }
                goto out;
            }
            if (field == CAP_OPTION_PL) {
                uint8_t *p = (uint8_t *)((uint8_t *)tcp_header + (tcp_header->doff << 2));
                uint16_t loop;
                uint16_t pl_len;

                pl_len = ntohs(ip_header->tot_len) - (ip_header->ver_ihl << 2) - (tcp_header->doff << 2);
                for (loop = 0; loop < pl_len; loop++) {
                    printf("%02x ", p[loop]);
                }
                printf("\n");
                goto out;
            }
        }
        if (ip_header->proto == IP_PRO_UDP) {
            udp_header = (struct pro_udp_hdr *)((uint8_t *)ip_header + (ip_header->ver_ihl << 2));
            if (field == CAP_OPTION_SP) {
                printf("%d\n", ntohs(udp_header->source));
                goto out;
            }
            if (field == CAP_OPTION_DP) {
                printf("%d\n", ntohs(udp_header->dest));
                goto out;
            }
            if (field == CAP_OPTION_CHECKL4) {
                uint16_t checksum;
                uint16_t old_l4_sum;

                old_l4_sum = udp_header->check;
                udp_header->check = 0;
                checksum = calc_crc_udp(udp_header, ip_header);
                udp_header->check = old_l4_sum;
                if (checksum == old_l4_sum) {
                    printf("0\n");
                }
                else {
                    printf("1\n");
                }
                goto out;
            }

            if (field == CAP_OPTION_PL) {
                uint8_t *p = (uint8_t *)(udp_header + 1);
                uint16_t loop;

                for (loop = 0; loop < ntohs(udp_header->len) - sizeof(udp_header); loop++) {
                    printf("%02x ", p[loop]);
                }
                printf("\n");
                goto out;
            }
        }

        left -= len;
        if (left <= 0) {
            break;
        }
    }

out:
    close(fcap);

    return ret;
}

