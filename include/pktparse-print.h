/*
 * Author: Ian Rose
 * Date Created: Feb 25, 2008
 *
 * Declares methods to print packets in human-readable string format.
 */

#ifndef _PKTPARSE_PRINT_H_
#define _PKTPARSE_PRINT_H_

#include "pktparse.h"

#ifdef __cplusplus
extern "C" {
#endif 

/***************/
/*  Constants  */
/***************/

#define PKTPARSE_PRINT_VERBOSE 1
#define PKTPARSE_PRINT_FCS 2


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int pktparse_print_ethernet(char *buf, int len, const struct ether_header *header, int flags);
int pktparse_print_full(char *buf, int len, const struct packet *p, int flags);
int pktparse_print_wifi(char *buf, int len, const struct ieee80211_frame *frame, const struct mgmt_body_t *mgmt, int flags);
int pktparse_print_ip(char *buf, int len, const struct ip *iph, int plen, int flags);
int pktparse_print_ip_proto(char *buf, int len, const struct ip *iph, u_char ipproto, int plen, int flags);
int pktparse_print_ip6(char *buf, int len, const struct ip6_hdr *iph, int plen, int flags);
int pktparse_print_ip6_proto(char *buf, int len, const struct ip6_hdr *iph, u_char ipproto, int plen, int flags);
int pktparse_print_tcp(char *buf, int len, const struct tcphdr *tcph, int plen, int flags);
int pktparse_print_tcpip(char *buf, int len, const struct ip *iph, const struct tcphdr *tcph, int plen, int flags);
int pktparse_print_tcpip6(char *buf, int len, const struct ip6_hdr *iph, const struct tcphdr *tcph, int plen, int flags);
int pktparse_print_udp(char *buf, int len, const struct udphdr *updh, int plen, int flags);
int pktparse_print_udpip(char *buf, int len, const struct ip *iph, const struct udphdr *updh, int plen, int flags);
int pktparse_print_udpip6(char *buf, int len, const struct ip6_hdr *iph, const struct udphdr *udph, int plen, int flags);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _PKTPARSE_PRINT_H_  */
