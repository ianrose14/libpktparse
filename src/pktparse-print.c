/*
 * Author: Ian Rose
 * Date Created: Feb 25, 2008
 *
 * Defines methods to print packets in human-readable string format.
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>     /* for AF_INET, AF_INET6 */
#include <arpa/inet.h>  /* for inet_ntop, constants */
#include "extract.h"
#include "ieee802_11.h"
#include "pktparse-print.h"



/********************/
/*  STATIC METHODS  */
/********************/

static int
print_ipproto(char *buf, int len, u_char ipproto)
{
    switch (ipproto) {
    case IPPROTO_ICMP:
        return snprintf(buf, len, "ICMP ");
    case IPPROTO_IGMP:
        return snprintf(buf, len, "IGMP ");
    case IPPROTO_IPV4:
        return snprintf(buf, len, "IPv4 (encapsulation) ");
    case IPPROTO_TCP:
        return snprintf(buf, len, "TCP ");
    case IPPROTO_UDP:
        return snprintf(buf, len, "UDP ");
    case IPPROTO_IPV6:
        return snprintf(buf, len, "IPv6 (encapsulation) ");
    case IPPROTO_ICMPV6:
        return snprintf(buf, len, "ICMP6 ");
    case IPPROTO_NONE:     /* IP6 no next header */
        return 0;
    default:
        return snprintf(buf, len, "ipproto 0x%02X ", ipproto);
    }
}

/********************/
/*  PUBLIC METHODS  */
/********************/

int pktparse_print_ethernet(char *buf, int len,
    const struct ether_header *header, int flags)
{
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        return snprintf(buf, len, "Eth10 " MACADDR_FORMAT " > " MACADDR_FORMAT " ",
            MACADDR_EXPLODE(header->ether_shost), MACADDR_EXPLODE(header->ether_dhost));
    } else {
        return snprintf(buf, len, "Eth10 ");
    }
}

int pktparse_print_full(char *buf, int len, const struct packet *p, int flags)
{
    int offset = 0;
    int n = 0;

    /* MAC (datalink) layer */
    if (p->ether_hdr) {
        n = pktparse_print_ethernet(buf + offset, len - offset, p->ether_hdr, flags);
    } else if (p->wifi_hdr) {
        n = pktparse_print_wifi(buf + offset, len - offset, p->wifi_hdr, p->mgmt_body,
            flags);
    }

    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if enabled, also include the FCS field at the end */
    if ((n > 0) && (flags & PKTPARSE_PRINT_FCS)) {
        /* if packet was truncated at all, then we lost the FCS at the end */
        if ((p->caplen == p->wirelen) && (p->caplen >= 4)) {
            uint32_t index = p->caplen - 4;
            uint32_t fcs = EXTRACT_LE_32BITS(p->raw_packet + index);
            n = snprintf(buf + offset, len - offset, "FCS %08x ", fcs);
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }
    }

    /* if there are no higher layers, then just quit */
    if (p->ethertype < 0) return offset;

    if (n > 0) {
        n = snprintf(buf + offset, len - offset, "~ ");
        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    /* LLC (sub)layer (nothing printed) */

    /* network and transport layers get combined... */
    switch (p->ethertype) {
    case -1:
        /* no ethertype parsed from packet */
        break;
    case ETHERTYPE_IP:
        if (p->ip_hdr) {
            if (p->tcp_hdr)
                n = pktparse_print_tcpip(buf + offset, len - offset, p->ip_hdr, p->tcp_hdr, p->trans_len, flags);
            else if (p->udp_hdr)
                n = pktparse_print_udpip(buf + offset, len - offset, p->ip_hdr, p->udp_hdr, p->trans_len, flags);
            else
                n = pktparse_print_ip_proto(buf + offset, len - offset, p->ip_hdr, p->ipproto, p->trans_len, flags);
        }
        else
            n = snprintf(buf + offset, len - offset, "IP ");
        break;
        
    case ETHERTYPE_IPV6:
        if (p->ip6_hdr) {
            if (p->tcp_hdr)
                n = pktparse_print_tcpip6(buf + offset, len - offset, p->ip6_hdr, p->tcp_hdr, p->trans_len, flags);
            else if (p->udp_hdr)
                n = pktparse_print_udpip6(buf + offset, len - offset, p->ip6_hdr, p->udp_hdr, p->trans_len, flags);
            else if (p->ipproto != -1)
                n = pktparse_print_ip6_proto(buf + offset, len - offset, p->ip6_hdr, (u_char)p->ipproto, p->trans_len, flags);
            else
                n = pktparse_print_ip6(buf + offset, len - offset, p->ip6_hdr, p->trans_len, flags);
        }
        else
            n = snprintf(buf + offset, len - offset, "IPv6 ");
        break;
        
    case ETHERTYPE_ARP:
        n = snprintf(buf + offset, len - offset, "ARP ");
        break;
        
    default:
        n = snprintf(buf + offset, len - offset, "ethertype 0x%04X ",
            p->ethertype);
        break;
    }

    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* application layer */
    /* (unimplemented) */

    return offset;
}

int pktparse_print_ip(char *buf, int len, const struct ip *iph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &iph->ip_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET, &iph->ip_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "%s > %s", saddr, daddr);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    if ((flags & PKTPARSE_PRINT_VERBOSE) && (iph->ip_off & htons(IP_MF | IP_OFFMASK)) != 0) {
        n = snprintf(buf + offset, len - offset, "(fragmented) ");
        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_ip_proto(char *buf, int len, const struct ip *iph, u_char ipproto, int plen, int flags)
{
    int n, offset = 0;

    n = print_ipproto(buf, len, ipproto);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    n = pktparse_print_ip(buf + offset, len - offset, iph, plen, flags);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    return offset;
}

int pktparse_print_ip6(char *buf, int len, const struct ip6_hdr *iph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET6_ADDRSTRLEN];
    char daddr[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, &iph->ip6_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET6, &iph->ip6_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "%s > %s ", saddr, daddr);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    return offset;
}

int pktparse_print_ip6_proto(char *buf, int len, const struct ip6_hdr *iph, u_char ipproto, int plen, int flags)
{
    int n, offset = 0;

    if (ipproto != IPPROTO_FRAGMENT) {
        n = print_ipproto(buf, len, ipproto);
        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    n = pktparse_print_ip6(buf + offset, len - offset, iph, plen, flags);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    if ((flags & PKTPARSE_PRINT_VERBOSE) && (ipproto == IPPROTO_FRAGMENT)) {
        n = snprintf(buf + offset, len - offset, "(fragmented) ");
        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}


int pktparse_print_tcp(char *buf, int len, const struct tcphdr *tcph, int plen, int flags)
{
    int n, offset = 0;

    n = snprintf(buf, len, "TCP %u > %u ", ntohs(tcph->th_sport),
        ntohs(tcph->th_dport));
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if verbose, also print present TCP flags and data len */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        if (tcph->th_flags & TH_FLAGS) {
            n = snprintf(buf + offset, len - offset, "[%s%s%s%s%s%s%s%s] ",
                tcph->th_flags & TH_FIN ? "F" : "",
                tcph->th_flags & TH_SYN ? "S" : "",
                tcph->th_flags & TH_RST ? "R" : "",
                tcph->th_flags & TH_PUSH ? "P" : "",
                tcph->th_flags & TH_ACK ? "A" : "",
                tcph->th_flags & TH_URG ? "U" : "",
                tcph->th_flags & TH_ECE ? "E" : "",
                tcph->th_flags & TH_CWR ? "C" : "");

            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        n = snprintf(buf + offset, len - offset, "dlen=%d ", plen - tcph->th_off*4);

        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_tcpip(char *buf, int len, const struct ip *iph,
    const struct tcphdr *tcph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];
    uint16_t sport = ntohs(tcph->th_sport);
    uint16_t dport = ntohs(tcph->th_dport);

    if (inet_ntop(AF_INET, &iph->ip_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET, &iph->ip_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "TCP %s:%u > %s:%u ", saddr, sport, daddr, dport);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if verbose, also print present TCP flags and data len */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        if (tcph->th_flags & TH_FLAGS) {
            n = snprintf(buf + offset, len - offset, "[%s%s%s%s%s%s%s%s] ",
                tcph->th_flags & TH_FIN ? "F" : "",
                tcph->th_flags & TH_SYN ? "S" : "",
                tcph->th_flags & TH_RST ? "R" : "",
                tcph->th_flags & TH_PUSH ? "P" : "",
                tcph->th_flags & TH_ACK ? "A" : "",
                tcph->th_flags & TH_URG ? "U" : "",
                tcph->th_flags & TH_ECE ? "E" : "",
                tcph->th_flags & TH_CWR ? "C" : "");

            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        n = snprintf(buf + offset, len - offset, "dlen=%d ", plen - tcph->th_off*4);

        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_tcpip6(char *buf, int len, const struct ip6_hdr *iph,
    const struct tcphdr *tcph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET6_ADDRSTRLEN];
    char daddr[INET6_ADDRSTRLEN];
    uint16_t sport = ntohs(tcph->th_sport);
    uint16_t dport = ntohs(tcph->th_dport);

    if (inet_ntop(AF_INET6, &iph->ip6_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET6, &iph->ip6_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "TCP %s %u -> %s %u", saddr, sport, daddr, dport);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if verbose, also print present TCP flags and data len */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        if (tcph->th_flags & TH_FLAGS) {
            n = snprintf(buf + offset, len - offset, "[%s%s%s%s%s%s%s%s] ",
                tcph->th_flags & TH_FIN ? "F" : "",
                tcph->th_flags & TH_SYN ? "S" : "",
                tcph->th_flags & TH_RST ? "R" : "",
                tcph->th_flags & TH_PUSH ? "P" : "",
                tcph->th_flags & TH_ACK ? "A" : "",
                tcph->th_flags & TH_URG ? "U" : "",
                tcph->th_flags & TH_ECE ? "E" : "",
                tcph->th_flags & TH_CWR ? "C" : "");

            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        n = snprintf(buf + offset, len - offset, "dlen=%d ", plen - tcph->th_off*4);

        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_udp(char *buf, int len, const struct udphdr *udph, int plen, int flags)
{
    return snprintf(buf, len, "UDP %u > %u ", ntohs(udph->uh_sport),
        ntohs(udph->uh_dport));
}

int pktparse_print_udpip(char *buf, int len, const struct ip *iph,
    const struct udphdr *udph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];
    uint16_t sport = ntohs(udph->uh_sport);
    uint16_t dport = ntohs(udph->uh_dport);

    if (inet_ntop(AF_INET, &iph->ip_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET, &iph->ip_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "UDP %s:%u > %s:%u ", saddr, sport, daddr, dport);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if verbose, also print data len */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        n = snprintf(buf + offset, len - offset, "dlen=%d ", plen - UDP_HDR_LEN);

        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_udpip6(char *buf, int len, const struct ip6_hdr *iph,
    const struct udphdr *udph, int plen, int flags)
{
    int n, offset = 0;
    char saddr[INET6_ADDRSTRLEN];
    char daddr[INET6_ADDRSTRLEN];
    uint16_t sport = ntohs(udph->uh_sport);
    uint16_t dport = ntohs(udph->uh_dport);

    if (inet_ntop(AF_INET6, &iph->ip6_src, saddr, sizeof(saddr)) == NULL)
        return -1;

    if (inet_ntop(AF_INET6, &iph->ip6_dst, daddr, sizeof(daddr)) == NULL)
        return -1;

    n = snprintf(buf, len, "UDP %s %u > %s %u ", saddr, sport, daddr, dport);
    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    /* if verbose, also print data len */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        n = snprintf(buf + offset, len - offset, "dlen=%d ", plen - UDP_HDR_LEN);

        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    return offset;
}

int pktparse_print_wifi(char *buf, int len,
    const struct ieee80211_frame *frame, const struct mgmt_body_t *mgmt,
    int flags)
{
        int n, offset = 0;
    uint16_t fc = EXTRACT_LE_16BITS(frame->i_fc);
    uint16_t type = FC_TYPE(fc);
    uint16_t subtype = FC_SUBTYPE(fc);

    switch (type) {
    case T_MGMT:
        if (subtype == ST_ASSOC_REQUEST) {
            n = snprintf(buf, len, "Wifi AssocReq ");
        } else if (subtype == ST_ASSOC_RESPONSE) {
            n = snprintf(buf, len, "Wifi AssocResp ");
        } else if (subtype == ST_REASSOC_REQUEST) {
            n = snprintf(buf, len, "Wifi ReassocReq ");
        } else if (subtype == ST_REASSOC_RESPONSE) {
            n = snprintf(buf, len, "Wifi ReassocResp ");
        } else if (subtype == ST_PROBE_REQUEST) {
            n = snprintf(buf, len, "Wifi ProbeReq ");
        } else if (subtype == ST_PROBE_RESPONSE) {
            n = snprintf(buf, len, "Wifi ProbeResp ");
        } else if (subtype == ST_BEACON) {
            n = snprintf(buf, len, "Wifi Beacon ");
        } else if (subtype == ST_ATIM) {
            n = snprintf(buf, len, "Wifi ATIM ");
        } else if (subtype == ST_DISASSOC) {
            n = snprintf(buf, len, "Wifi Disassoc ");
        } else if (subtype == ST_AUTH) {
            n = snprintf(buf, len, "Wifi Auth ");
        } else if (subtype == ST_DEAUTH) {
            n = snprintf(buf, len, "Wifi Deauth ");
        } else if (subtype == ST_ACTION) {
            n = snprintf(buf, len, "Wifi Action ");
        } else {
            n = snprintf(buf, len, "Wifi mgmt ??? ");
        }
        break;

    case T_CTRL:
        if (subtype == CTRL_BAR) {
            n = snprintf(buf, len, "Wifi BlockAckReq ");
        } else if (subtype == CTRL_BA) {
            n = snprintf(buf, len, "Wifi BlockAck ");
        } else if (subtype == CTRL_PS_POLL) {
            n = snprintf(buf, len, "Wifi PS-Poll ");
        } else if (subtype == CTRL_RTS) {
            n = snprintf(buf, len, "Wifi RTS ");
        } else if (subtype == CTRL_CTS) {
            n = snprintf(buf, len, "Wifi CTS ");
        } else if (subtype == CTRL_ACK) {
            n = snprintf(buf, len, "Wifi ACK ");
        } else if (subtype == CTRL_CF_END) {
            n = snprintf(buf, len, "Wifi CF-End ");
        } else if (subtype == CTRL_CTS) {
            n = snprintf(buf, len, "Wifi CF-End+ACK ");
        } else {
            n = snprintf(buf, len, "Wifi ctrl ??? ");
        }
        break;

    case T_DATA: {
        const char *desc = DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)) ? "QoS data" : "data";

        if (DATA_FRAME_IS_NULL(subtype)) {
            n = snprintf(buf, len, "Wifi %s [null] ", desc);
        } else {
            n = snprintf(buf, len, "Wifi %s ", desc);
        }
        break;
    }

    default:
        n = snprintf(buf, len, "??? ");
        break;
    }

    if (n == -1) return -1;
    offset += n;
    if (offset >= len) return offset;

    if (FC_WEP(fc)) {
        n = snprintf(buf + offset, len - offset, "[encrypted] ");
        if (n == -1) return -1;
        offset += n;
        if (offset >= len) return offset;
    }

    if ((type == T_MGMT) && (mgmt != NULL)) {
        if (mgmt->ssid_status == PRESENT) {
            /* replace all non-printable characters in the SSID with ' ' */
            char ssid[SSID_MAXLEN+1];
            strlcpy(ssid, (char*)mgmt->ssid.ssid, sizeof(ssid));
            for (int i=0; i < strlen(ssid); i++) {
                if (!isprint(ssid[i]))
                    ssid[i] = ' ';
            }

            n = snprintf(buf + offset, len - offset, "\"%s\" ", ssid);
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }
    }

    /* if verbose, also print address fields, seq-ctrl field, and FCS field */
    if (flags & PKTPARSE_PRINT_VERBOSE) {
        if ((type == T_MGMT) && (mgmt != NULL)) {
            if (mgmt->ds_status == PRESENT) {
                n = snprintf(buf + offset, len - offset, "Chan %d ", mgmt->ds.channel);
                if (n == -1) return -1;
                offset += n;
                if (offset >= len) return offset;
            }
        }

        const u_char *sa = NULL, *da = NULL, *ta = NULL, *ra = NULL, *bssid = NULL;
        if (pktparse_extract_wifi_addrs(frame, &sa, &da, &ta, &ra, &bssid) != 0)
            return -1;

        if (ra != NULL) {
            n = snprintf(buf + offset, len - offset, "RA " MACADDR_FORMAT " ",
                MACADDR_EXPLODE(ra));
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        if (ta != NULL) {
            n = snprintf(buf + offset, len - offset, "TA " MACADDR_FORMAT " ",
                MACADDR_EXPLODE(ta));
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        if (ta != NULL) {
            n = snprintf(buf + offset, len - offset, "DA " MACADDR_FORMAT " ",
                MACADDR_EXPLODE(da));
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        if (sa != NULL) {
            n = snprintf(buf + offset, len - offset, "SA " MACADDR_FORMAT " ",
                MACADDR_EXPLODE(sa));
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }

        if (bssid != NULL) {
            n = snprintf(buf + offset, len - offset, "BSSID "
                MACADDR_FORMAT " ", MACADDR_EXPLODE(bssid));
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        } else {
            if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
                n = snprintf(buf + offset, len - offset,
                    "TA " MACADDR_FORMAT " RA " MACADDR_FORMAT " [WDS] ",
                    MACADDR_EXPLODE(ta), MACADDR_EXPLODE(ra));
                if (n == -1) return -1;
                offset += n;
                if (offset >= len) return offset;
            }
        }

        /* control frames do not carry the SeqCtrl field */
        if (type != T_CTRL) {
            uint16_t seqctrl = EXTRACT_LE_16BITS(frame->i_seq);
            n = snprintf(buf + offset, len - offset, "SC %04x|%x ", seqctrl >> 4,
                seqctrl & 0xF);
            if (n == -1) return -1;
            offset += n;
            if (offset >= len) return offset;
        }
    }

    return offset;
}
