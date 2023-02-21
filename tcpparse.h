/***************************************************************
  Copyright (c) 2019 ShenZhen Heishv Technology, Inc.

  The right to copy, distribute, modify or otherwise make use
  of this software may be licensed only pursuant to the terms
  of an applicable ShenZhen Heishv license agreement.
 ***************************************************************/
#ifndef __TCPPARSE_H__
#define __TCPPARSE_H__

//#define CAP_MAGIC                   0xD4C3B2A1
#define CAP_MAGIC                   0xA1B2C3D4
#define CAP_MAJOR_VERSION           0x0002
#define CAP_MINOR_VERSION           0x0004

#define min(a,b)                    (((a) < (b)) ? (a) : (b))

#ifndef ERROR
#define ERROR                       (-1)
#endif
#ifndef OK
#define OK                          0
#endif
#ifndef ETH_HLEN
#define ETH_HLEN                    14      /* Total octets in header. */
#endif
#ifndef ETH_ALEN
#define ETH_ALEN                    6       /* Octets in one ethernet addr   */
#endif
#ifndef IPV6_ALEN
#define IPV6_ALEN                   16
#endif

#define ETH_PRO_IP                  0x0800  /* Internet Protocol packet     */
#define ETH_PRO_ARP                 0x0806  /* Address Resolution packet    */
#define ETH_PRO_8021Q               0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_PRO_IPV6                0x86DD  /* IPv6 over bluebook           */
#define ETH_PRO_PPP_DISC            0x8863  /* PPPoE discovery messages     */
#define ETH_PRO_PPP_SES             0x8864  /* PPPoE session messages       */
#define ETH_PRO_MPLS_UC             0x8847  /* MPLS Unicast traffic         */
#define ETH_PRO_MPLS_MC             0x8848  /* MPLS Multicast traffic       */
#define ETH_PRO_8021AD              0x88A8  /* 802.1ad Service VLAN         */

#define IP_PRO_ICMP                 1       /* Internet Control Message Protocol    */
#define IP_PRO_IGMP                 2       /* Internet Group Management Protocol   */
#define IP_PRO_TCP                  6       /* Transmission Control Protocol    */
#define IP_PRO_UDP                  17      /* User Datagram Protocol       */
#define IP_PRO_GRE                  47      /* Internet Control Message Protocol    */
#define IP_PRO_ESP                  50      /* Encapsulation Security Payload protocol */
#define IP_PRO_AH                   51      /* Authentication Header protocol       */
#define IP_PRO_ICMPV6               58      /* Internet Control Message Protocol V6   */
#define IP_PRO_OSPF                 89      /* OSPF  */
#define IP_PRO_COMP                 108     /* Compression Header protocol */
#define IP_PRO_SCTP                 132     /* Stream Control Transport Protocol    */

typedef uint16_t (*CAP_SWAP_2)(uint16_t);
typedef uint32_t (*CAP_SWAP_4)(uint32_t);

enum {
    CAP_OPTION_NONE,
    CAP_OPTION_SM,
    CAP_OPTION_DM,
    CAP_OPTION_SP,
    CAP_OPTION_DP,
    CAP_OPTION_CHECKL3,
    CAP_OPTION_CHECKL4,
    CAP_OPTION_PL,
    CAP_OPTION_ETH_TYPE,
    CAP_OPTION_PROTO,
    CAP_OPTION_SI,
    CAP_OPTION_DI,
    CAP_OPTION_LEN,
};

/* CAP file header */
typedef struct tag_cap_global_hdr
{
    uint32_t magic;                         /* magic number */
    uint16_t major_ver;                     /* major version number */
    uint16_t minor_ver;                     /* minor version number */
    int32_t  this_zone;                     /* GMT to local correction */
    uint32_t sigfigs;                       /* accuracy of timestamps */
    uint32_t snaplen;                       /* max length of captured packets, in octets */
    uint32_t linktype;                      /* data link type */
}cap_global_hdr;

/* CAP file packet header */
typedef struct tag_cap_packet_hdr
{
    uint32_t timestamp_h;                   /* timestamp seconds */
    uint32_t timestamp_l;                   /* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
    uint32_t caplen;                        /* number of octets of packet saved in file */
    uint32_t origlen;                       /* actual length of packet */
}cap_packet_hdr;

union vlan_tci {
    unsigned short  data;
    struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned short vid : 12;
        unsigned short dei : 1;
        unsigned short pri : 3;
#else
        unsigned short pri : 3;
        unsigned short dei : 1;
        unsigned short vid : 12;
#endif
    } s;
};

#pragma pack (1)
struct pro_vlan_hdr {
    union vlan_tci  tci;
    unsigned short  eth_type;
};
#pragma pack ()

#pragma pack (1)
struct pro_eth_hdr {
    unsigned char   dest[ETH_ALEN];
    unsigned char   source[ETH_ALEN];
    unsigned short  eth_type;
};
#pragma pack ()

#pragma pack (1)
struct pro_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char   ver_ihl  : 4;
    unsigned char   version  : 4;
#else
    unsigned char   version  : 4;
    unsigned char   ver_ihl  : 4;
#endif
    unsigned char   tos;
    unsigned short  tot_len;
    unsigned short  id;
    unsigned short  frag_off;
    unsigned char   ttl;
    unsigned char   proto;
    unsigned short  check;
    unsigned int    src_addr;
    unsigned int    dst_addr;
};
#pragma pack ()

#pragma pack (1)
struct pro_ipv6_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	priority : 4;
	unsigned char	version  : 4;
#else
	unsigned char	version  : 4;
	unsigned char	priority : 4;
#endif
	unsigned char	flow_lbl[3];

	unsigned short  payload_len;
	unsigned char	nexthdr;
	unsigned char	hop_limit;

	unsigned char   saddr[IPV6_ALEN];
	unsigned char   daddr[IPV6_ALEN];
};
#pragma pack ()

#pragma pack (1)
struct pro_udp_hdr {
    unsigned short  source;
    unsigned short  dest;
    unsigned short  len;
    unsigned short  check;
};
#pragma pack ()

#pragma pack (1)
struct pro_tcp_hdr {
    unsigned short  source;
    unsigned short  dest;
    unsigned int    seq;
    unsigned int    ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short  res1 : 4;
    unsigned short  doff : 4;
    unsigned short  fin  : 1;
    unsigned short  syn  : 1;
    unsigned short  rst  : 1;
    unsigned short  psh  : 1;
    unsigned short  ack  : 1;
    unsigned short  urg  : 1;
    unsigned short  ece  : 1;
    unsigned short  cwr  : 1;
#else
    unsigned short  doff : 4;
    unsigned short  res1 : 4;
    unsigned short  cwr  : 1;
    unsigned short  ece  : 1;
    unsigned short  urg  : 1;
    unsigned short  ack  : 1;
    unsigned short  psh  : 1;
    unsigned short  rst  : 1;
    unsigned short  syn  : 1;
    unsigned short  fin  : 1;
#endif
    unsigned short  window;
    unsigned short  check;
    unsigned short  urg_ptr;
};
#pragma pack ()

#endif


