/***************************************************************
  Copyright (c) 2019 ShenZhen HSTech Technology, Inc.

  The right to copy, distribute, modify or otherwise make use
  of this software may be licensed only pursuant to the terms
  of an applicable ShenZhen HSTech license agreement.
 ***************************************************************/
#ifndef __CRC_H__
#define __CRC_H__

#ifdef __cplusplus
extern "C" {
#endif
typedef struct udp_check_subhdr {
    int check_srcIp;
    int check_dstIp;
    char check_rsv;
    char checkprotocol;
    short check_udp_len;
}pro_udp_subhdr;

typedef struct ipv4_psd_header {
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint8_t  zero;     /* zero. */
	uint8_t  proto;    /* L4 protocol type. */
	uint16_t len;      /* L4 length. */
} psd_hdr;

uint16_t calc_crc_tcp(void *tcp_hdr, void *ip_hdr);
uint16_t calc_crc_tcp6(void *tcp_hdr, void *ip6_hdr);
uint16_t calc_crc_udp(void *udp_hdr, void *ip_hdr);
uint16_t calc_crc_udp6(void *udp_hdr, void *ip6_hdr);
uint16_t calc_crc_ip(void *ip_hdr);
void calc_fix_sum (uint8_t *pCheckSum, uint8_t *pOldData, uint16_t usOldLen, uint8_t *pNewData, uint16_t usNewLen);

#ifdef __cplusplus
}
#endif

#endif /* __CRC_H__ */

