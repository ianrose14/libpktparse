/*
 * Author: Ian Rose
 * Date Created: Feb 24, 2008
 *
 * Declares methods to parse out various packet formats from raw bytes.
 */

#ifndef _PKTPARSE_H_
#define _PKTPARSE_H_

#include <sys/types.h>
#include <net/ethernet.h>      /* struct ether_header */
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_radiotap.h>  /* struct ieee80211_radiotap_header */
#include <netinet/in.h>        /* needed for netinet/ip.h */
#include <netinet/in_systm.h>  /* needed for netinet/ip.h */
#include <netinet/ip.h>        /* struct ip */
#include <netinet/ip6.h>       /* struct ip6_hdr */
#include <netinet/tcp.h>       /* struct tcphdr */
#include <netinet/udp.h>       /* struct udphdr */
#include <pcap/pcap.h>         /* struct pcap_pkthdr */

/*
 * Some mojo is required here; the header file net/if_lcc.h very unfortunately
 * uses 'class' as a variable name and even more unfortunately 'extern "C"'
 * apparently doesn't protect the C++ compiler from freaking out when it sees
 * that (since 'class' is a reserved keyword in C++ but not C).  So since we
 * can't edit this file ourselves, we use the preprocessor to mangle the word
 * into something else that the C++ compiler won't mind.
 */
#ifdef __cplusplus
#define class xxx_myclass_xxx
#endif
#include <net/if_llc.h>        /* struct llc */
#ifdef __cplusplus
#undef class
#endif

#include "ieee802_11.h"

#ifdef __cplusplus
extern "C" {
#endif 

/***************/
/*  Constants  */
/***************/

/* Important constants not defined in their respective header files */
#define IP_HDR_LEN 20
#define IP6_HDR_LEN 40
#define TCP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define RADIOTAP_HDR_LEN sizeof(struct ieee80211_radiotap_header)

/* length of statically allocated error-message field in struct packet */
#define PKTPARSE_ERRMSG_LEN 128

/* flags that can be passed to pktparse_parse() */
#define PKTPARSE_IGNORE_BADLLC      0x01
#define PKTPARSE_HAS_FCS            0x02
#define PKTPARSE_HAS_80211_PADDING  0x04


/***********************/
/*  Type Declarations  */
/***********************/

struct http_request {
    /* required fields (always present) */
    char method[8];         /* current max method length is 7 */
    char version[8];        /* current max version length is 3 */
    /* (plus 'resource', which must be at the end of the struct) */

    /* optional fields */
    char *user_agent;
    char *host;
    char user_agent_alloc[1024];  /* size limit is an estimate */
    char host_alloc[256];         /* size limit is an estimate */

    /* required field, but must be at the end of the struct */
    char resource[];        /* allocated by over-allocating when calling malloc */
};

struct packet {
    /* this is the literal number of bytes that were captured */
    uint32_t caplen;
    uint32_t wirelen;
    struct timeval ts;
    const u_char *raw_packet;

    const struct ether_header *ether_hdr;
    const struct ieee80211_frame *wifi_hdr;
    uint16_t wifi_fc;  /* for easy access (host byte-ordered) */
    const struct ieee80211_radiotap_header *radiotap_hdr;
    const u_char *radiotap_fields;
    struct mgmt_body_t *mgmt_body;
    const struct llc *llc_hdr;
    int ethertype;     /* host byte-ordered; -1 if not applicable */
    int ipproto;       /* -1 if not applicable */
    int trans_len;     /* length of transport-level data, -1 if not applicable */
    const struct ip *ip_hdr;
    const struct ip6_hdr *ip6_hdr;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;
    const u_char *unparsed;
    int unparsed_len;

    /* static storage allocation for structs that do not directly
       map byte-for-byte into the original packet */
    struct mgmt_body_t mgmt_body_field;

    /* place to write error messages */
    char errmsg[PKTPARSE_ERRMSG_LEN];
};


/**********************************/
/*  External Method Declarations  */
/**********************************/

/*
 * returns 0 is successful (assigning to *snr) or -1 if an error occurs (setting
 * errno)
 */
int pktparse_extract_snr(const struct ieee80211_radiotap_header *rh,
    const u_char *radiotap_fields, int *snr);

/*
 * returns 0 is successful (assigning to all of *src, *dst, and *bssid, unless
 * they are NULL) or -1 if an error occurs (setting errno)
 */
int pktparse_extract_wifi_addrs(const struct ieee80211_frame *wifi_hdr,
    const u_char **src, const u_char **dst, const u_char **tx,
    const u_char **rx, const u_char **bssid);

/*
 * returns 0 is successful or -1 if an error occurs (possibly writing an error
 *  message to the errmsg field of the packet struct)
 */
int pktparse_parse(const struct pcap_pkthdr *h, const u_char *p, int dlt,
    struct packet *packet, int flags);

/*
 * Returns a pointer to a (dynamically-allocated) http_request struct if
 * successful, or NULL if an HTTP request could not be parsed (this could be
 * because the HTTP request was malformed, or because the packet data was not an
 * HTTP request at all).
 */
struct http_request *pktparse_parse_http_request(const char *data, size_t len);

/*
 * Returns a pointer to the data of a specified radiotap field, or NULL if the
 * field is not present.
 */
const u_char *pktparse_radiotap_field(int field,
    const struct ieee80211_radiotap_header *header, const u_char *fields);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _PKTPARSE_H_  */
