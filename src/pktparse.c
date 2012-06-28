/*
 * Author: Ian Rose
 * Date Created: Feb 24, 2008
 *
 * Implements methods to parse out various packet formats from raw bytes.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* must be included before netipx/ipx.h */
#include <netipx/ipx.h>
#include "pktparse.h"
#include "extract.h"
#include "ieee802_11.h"
#include "llc.h"


/************/
/*  Macros  */
/************/

#define SET_PKT_ERR(pkt, ...) snprintf(pkt->errmsg, sizeof(pkt->errmsg), __VA_ARGS__);

/********************************/
/*  Static Method Declarations  */
/********************************/

static const char *my_strnchr(const char *b, size_t len, char c);

static int parse_ethernet(struct packet * restrict packet);

static int parse_ieee80211(struct packet * restrict packet, u_char has_datapad,
    u_char has_fcs);

static int parse_ieee80211_radiotap(struct packet * restrict packet);

static int parse_ip(struct packet * restrict packet);

static int parse_ip6(struct packet * restrict packet);

static int parse_llc(struct packet * restrict packet, uint16_t *ethertype);

static int parse_tcp(struct packet * restrict packet);

static int parse_udp(struct packet * restrict packet);

static int parse_wifi_mgmt(struct packet * restrict packet);

static int wifi_min_hdrlen(uint16_t fc);


/*************************************/
/*  External Method Implementations  */
/*************************************/

int pktparse_extract_snr(const struct ieee80211_radiotap_header *rh,
    const u_char *radiotap_fields, int *snr)
{
    const u_char *antsignalp =
        pktparse_radiotap_field(IEEE80211_RADIOTAP_DBM_ANTSIGNAL,
            rh, radiotap_fields);

    const u_char *antnoisep =
        pktparse_radiotap_field(IEEE80211_RADIOTAP_DBM_ANTNOISE,
            rh, radiotap_fields);

    if ((antsignalp == NULL) || (antnoisep == NULL)) {
        errno = EINVAL;
        return -1;
    }

    int8_t antsig = *((int8_t*)antsignalp);
    int8_t antnoise = *((int8_t*)antnoisep);
    *snr = (int)antsig - (int)antnoise;
    return 0;
}

int pktparse_extract_wifi_addrs(const struct ieee80211_frame *wifi_hdr,
    const u_char **src, const u_char **dst, const u_char **tx,
    const u_char **rx, const u_char **bssid)
{
    uint16_t fc = EXTRACT_LE_16BITS((uint16_t*)wifi_hdr->i_fc);

    switch (FC_TYPE(fc)) {
    case T_DATA:
        if (FC_TO_DS(fc)) {
            if (FC_FROM_DS(fc)) {
                /* 
                 * WDS (bridge) frame (to-DS == 1 and from-DS == 1) have:
                 * addr1 = receiver address
                 * addr2 = transmitter address
                 * addr3 = destination address ( = final receiver)
                 * addr4 = source address ( = original transmitter)
                 */
                if (FC_QOS(fc)) {
                    const struct ieee80211_qosframe_addr4 *wds =
                        (const struct ieee80211_qosframe_addr4*)wifi_hdr;
                    if (src != NULL) *src = wds->i_addr4;
                    if (dst != NULL) *dst = wds->i_addr3;
                    if (tx != NULL) *tx = wds->i_addr2;
                    if (rx != NULL) *rx = wds->i_addr1;
                    if (bssid != NULL) *bssid = NULL;
                } else {
                    const struct ieee80211_frame_addr4 *wds =
                        (const struct ieee80211_frame_addr4*)wifi_hdr;
                    if (src != NULL) *src = wds->i_addr4;
                    if (dst != NULL) *dst = wds->i_addr3;
                    if (tx != NULL) *tx = wds->i_addr2;
                    if (rx != NULL) *rx = wds->i_addr1;
                    if (bssid != NULL) *bssid = NULL;
                }
            } else {  /* FC_FROM_DC(fc) == 0 */
                /* 
                 * data frames from a station to an AP (to-DS == 1 and
                 * from-DS == 0) have:
                 * addr1 = receiver address ( = BSSID)
                 * addr2 = transmitter address ( = source address)
                 * addr3 = destination address
                 */
                if (src != NULL) *src = wifi_hdr->i_addr2;
                if (dst != NULL) *dst = wifi_hdr->i_addr3;
                if (tx != NULL) *tx = wifi_hdr->i_addr2;
                if (rx != NULL) *rx = wifi_hdr->i_addr1;
                if (bssid != NULL) *bssid = wifi_hdr->i_addr1;
            }
        } else {  /* FC_TO_DS(fc) == 0 */
            if (FC_FROM_DS(fc)) {
                /*
                 * data frames from an AP to a station (to-DS == 0 and
                 * from-DS == 1) have:
                 * addr1 = receiver address ( = destination address)
                 * addr2 = transmitter address ( = BSSID)
                 * addr3 = source address
                 */
                if (src != NULL) *src = wifi_hdr->i_addr3;
                if (dst != NULL) *dst = wifi_hdr->i_addr1;
                if (tx != NULL) *tx = wifi_hdr->i_addr2;
                if (rx != NULL) *rx = wifi_hdr->i_addr1;
                if (bssid != NULL) *bssid = wifi_hdr->i_addr2;
            } else {  /* FC_FROM_DS(fc) == 0 */
                /*
                 * IBSS data frames (to-DS == 0 and from-DS == 0) have:
                 * addr1 = receiver address ( = destination address)
                 * addr2 = transmitter address ( = source address)
                 * addr3 = BSSID
                 */
                if (src != NULL) *src = wifi_hdr->i_addr2;
                if (dst != NULL) *dst = wifi_hdr->i_addr1;
                if (tx != NULL) *tx = wifi_hdr->i_addr2;
                if (rx != NULL) *rx = wifi_hdr->i_addr1;
                if (bssid != NULL) *bssid = wifi_hdr->i_addr3;
            }
        }
        break;

    case T_CTRL:
        /*
         * RTS control frames have:
         * addr1 = receiver address ( = destination address)
         * addr2 = transmitter address ( = source address)
         * addr3 (not present)
         *
         * ACK and CTS control frames have:
         * addr1 = receiver address ( = destination address)
         * addr2 (not present)
         * addr3 (not present)
         */
        if (src != NULL) *src = NULL;
        if (dst != NULL) *dst = wifi_hdr->i_addr1;
        if (rx != NULL) *rx = wifi_hdr->i_addr1;
        if (bssid != NULL) *bssid = NULL;

        if (FC_SUBTYPE(fc) == CTRL_RTS) {
            if (src != NULL) *src = wifi_hdr->i_addr2;
            if (tx != NULL) *tx = wifi_hdr->i_addr2;
        }
        break;
            
    case T_MGMT:
        /* 
         * all management frames have:
         * addr1 = receiver address ( = destination address)
         * addr2 = transmitter address ( = source address)
         * addr3 = BSSID
         */
        if (src != NULL) *src = wifi_hdr->i_addr2;
        if (dst != NULL) *dst = wifi_hdr->i_addr1;
        if (tx != NULL) *tx = wifi_hdr->i_addr2;
        if (rx != NULL) *rx = wifi_hdr->i_addr1;
        if (bssid != NULL) *bssid = wifi_hdr->i_addr3;
        break;
    default:
        /* invalid frame type (corrupted frame?) */
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int pktparse_parse(const struct pcap_pkthdr *h, const u_char *p, int dlt,
    struct packet *packet, int flags)
{
    int n;

    bzero(packet, sizeof(struct packet));
    packet->caplen = h->caplen;
    packet->wirelen = h->len;
    memcpy(&packet->ts, &h->ts, sizeof(packet->ts));
    packet->raw_packet = p;
    packet->ethertype = -1;
    packet->ipproto = -1;
    packet->trans_len = -1;
    packet->unparsed = p;
    packet->unparsed_len = h->caplen;
    packet->errmsg[0] = '\0';

    /* handle MAC header (depends on data-link type) */
    while (1) {
        switch (dlt) {
        case DLT_EN10MB:
            if (flags & PKTPARSE_HAS_FCS) {
                SET_PKT_ERR(packet, "FCS parsing not supported for ETHER dlt");
                return -1;
            }

            n = parse_ethernet(packet);
            if (n == -1) return -1; /* invalid header (bad value somewhere) */
            if (n == 0) return 0;   /* caplen too short (incomplete header) */
            break;

        case DLT_RAW:
            /* do nothing */
            break;

        case DLT_IEEE802_11_RADIO:
            n = parse_ieee80211_radiotap(packet);
            if (n == -1) return -1; /* invalid header (bad value somewhere) */
            if (n == 0) return 0;   /* caplen too short (incomplete header) */
            dlt = DLT_IEEE802_11;
            continue;

        case DLT_IEEE802_11: {
            /*
             * if we stripped a radiotap header, check for some flags that
             * affect how we parse out the 802.11 header
             */
            uint8_t has_datapad = 0;
            uint8_t has_fcs = 0;

            if (packet->radiotap_hdr) {
                const u_char *field_value =
                    pktparse_radiotap_field(IEEE80211_RADIOTAP_FLAGS,
                    packet->radiotap_hdr, packet->radiotap_fields);

                if (field_value != NULL) {
                    /* the radiotap header has a "flags" field... */

                    /* check for "datapad" flag */
                    has_datapad = (*field_value) & IEEE80211_RADIOTAP_F_DATAPAD;

                    /* check for "fcs" flag */
                    has_fcs = (*field_value) & IEEE80211_RADIOTAP_F_FCS;
                }
            }

            /*
             * Even if there is no radiotap header, we can still learn about
             * 802.11 padding and FCSes if the appropriate flags are passed as
             * arguments when the function is called.
             */
            if (flags & PKTPARSE_HAS_80211_PADDING) has_datapad = 1;
            if (flags & PKTPARSE_HAS_FCS) has_fcs = 1;

            n = parse_ieee80211(packet, has_datapad, has_fcs);
            if (n == -1) return -1; /* invalid header (bad value somewhere) */
            if (n == 0) return 0;   /* caplen too short (incomplete header) */

            if (n > 0) {
		if (FC_TYPE(packet->wifi_fc) == T_DATA) {
                    /*
                     * if its a data-frame, but of subtype 'null data', there is no
                     * MAC payload
                     */
                    if (DATA_FRAME_IS_NULL(FC_SUBTYPE(packet->wifi_fc)))
                        return 0;

                    /* 
                     * if the frame is fragmented, don't try to parse the
                     * payload
                     */
                    if (FC_MORE_FLAG(packet->wifi_fc))
                        return 0;
                }
                else {
                    /* if its not a data-frame, there is no MAC payload */
                    return 0;
                }
            }
            break;
        }

        default:
            SET_PKT_ERR(packet, "unsupported DLT (%d)", dlt);
            return -1;
        }
        break;
    }

    /* done with all MAC (link) headers */
    n = 0;
    
    /* parse out LLC header (if present, there may not be one) and ether-type */
    if (packet->ether_hdr) {
        packet->ethertype = ntohs(packet->ether_hdr->ether_type);

        if (packet->ethertype <= ETHERMTU) {
            /* ethertype field is the length field of an 802.2 header */
            uint16_t ethertype;
            n = parse_llc(packet, &ethertype);
            if (n == 0) return 0;   /* caplen too short (incomplete header) */
            packet->ethertype = ethertype;
        }
    }
    else if (dlt == DLT_RAW) {
        packet->ethertype = ETHERTYPE_IP;
    }
    else if ((dlt == DLT_IEEE802_11) || (dlt == DLT_IEEE802_11_RADIO)) {
        /* assume all wifi (data) packets have an LLC header */
        uint16_t ethertype;
        n = parse_llc(packet, &ethertype);
        if (n > 0) packet->ethertype = ethertype;
        if (n == 0) return 0;   /* caplen too short (incomplete header) */
    }

    /* invalid LLC header (some field had a bad value) */
    if (n == -1) {
        /*
         * This is expected if the packet was encrypted (if the Protected bit is
         * set in an 802.11 header, that means that the packet was encrypted,
         * but we don't know whether or not the capturing interface decrypted it
         * for us or not, which is why we optimistically assume so and go ahead
         * and try to parse the LLC header).
         */
        if (packet->wifi_hdr && FC_WEP(packet->wifi_fc)) {
            /* packet was encrypted; failure of parse_llc() is not an error */ 
            packet->errmsg[0] = '\0';
            return 0;
        } else if (flags & PKTPARSE_IGNORE_BADLLC) {
            /* blindly ignore LLC errors */
            return 0;
        } else {
            /* nope, packet wasn't encrypted; this really is an error */
            return -1;
        }
    }

    /* done with LLC header */

    /* parse out network header (based on parsed ethertype) */

    /* don't know how to extract ethertype from this type of LLC header */
    if (packet->ethertype < 0) return 0;

    switch (packet->ethertype) {
    case ETHERTYPE_IP:
        n = parse_ip(packet);
        if (n == -1) return -1; /* invalid header (bad value somewhere) */
        if (n == 0) return 0;   /* caplen too short (incomplete header) */
        break;
    case ETHERTYPE_IPV6:
        n = parse_ip6(packet);
        if (n == -1) return -1; /* invalid header (bad value somewhere) */
        if (n == 0) return 0;   /* caplen too short (incomplete header) */
        break;
    default:
        /* don't know how to parse this kind of header */
        return 0;
    }
    
    /* done with network header */
    if (packet->ip_hdr) {
        packet->ipproto = packet->ip_hdr->ip_p;
        packet->trans_len = ntohs(packet->ip_hdr->ip_len) - packet->ip_hdr->ip_hl*4;

        /* If IP datagram is fragmented, then quit here */
        if ((packet->ip_hdr->ip_off & htons(IP_MF | IP_OFFMASK)) != 0)
            return 0;
    }
    else if (packet->ip6_hdr) {
        /* walk the extension header until we get to an upper-level protocol */
        packet->ipproto = packet->ip6_hdr->ip6_nxt;
        packet->trans_len = packet->ip6_hdr->ip6_plen;
        while ((packet->ipproto != IPPROTO_TCP) && (packet->ipproto != IPPROTO_UDP)) {
            const struct ip6_ext *ext = (const struct ip6_ext*)(packet->unparsed);
            size_t extlen;

            switch (packet->ipproto) {
            case IPPROTO_HOPOPTS:  /* IP6 hop-by-hop options */
                if (packet->unparsed_len < 8) return 0;
                extlen = 8 + ext->ip6e_len*8;
                break;
            case IPPROTO_ROUTING:  /* IP6 routing header */
                if (packet->unparsed_len < 8) return 0;
                extlen = 8 + ext->ip6e_len*8;
                break;
            case IPPROTO_FRAGMENT: /* IP6 fragmentation header */
                return 0;  /* cannot parse fragmented payloads */
            case IPPROTO_ESP:      /* IP6 Encap Sec. Payload */
                return 0;  /* parsing not implemented */
            case IPPROTO_AH:       /* IP6 Auth Header */
                return 0;  /* parsing not implemented */
            case IPPROTO_NONE:     /* IP6 no next header */
                return 0;
            case IPPROTO_DSTOPTS:  /* IP6 destination option */
                if (packet->unparsed_len < 8) return 0;
                extlen = 8 + ext->ip6e_len*8;
                break;
            default:
                return 0;  /* don't know how to parse this header type */
            }

            if (extlen > packet->unparsed_len) return 0;
            if (extlen > packet->trans_len) {
                SET_PKT_ERR(packet, "IPv6 options exceed payload length");
                return -1;
            }
            packet->unparsed += extlen;
            packet->unparsed_len -= extlen;
            packet->trans_len -= extlen;
            packet->ipproto = ext->ip6e_nxt;
        }
    }
    else {
        /* don't know how to extract protocol id from this type of header */
        return 0;
    }

    /* parse out transport header (based on parsed protocol id) */

    switch (packet->ipproto) {
    case IPPROTO_IP:
        /* nothing to do (?) */
        return 0;
    case IPPROTO_TCP:
        n = parse_tcp(packet);
        if (n == -1) return -1; /* invalid header (bad value somewhere) */
        if (n == 0) return 0;   /* caplen too short (incomplete header) */
        break;
    case IPPROTO_UDP:
        n = parse_udp(packet);
        if (n == -1) return -1; /* invalid header (bad value somewhere) */
        if (n == 0) return 0;   /* caplen too short (incomplete header) */
        break;
    default:
        /* don't know how to parse this kind of header */
        return 0;
    }
    
    /* done with transport header */

    /* no application-level parsing currently supported */

    return 0;
}

struct http_request *
pktparse_parse_http_request(const char *data, size_t len)
{
    /* HTTP requests are of the form: {METHOD} {RESOURCE} HTTP/{VERSION} */
    const char *sep = my_strnchr(data, len, ' ');
    if (sep == NULL) return NULL;

    const char *method = data;
    size_t method_len = sep - data;
    data = sep + 1;  /* +1 for the space character after the method */
    len -= method_len + 1;

    /*
     * check that method is a valid HTTP request method (in rough order of
     * frequency for efficiency)
     */
    if ((strncmp(method, "GET", method_len) == 0) ||
        (strncmp(method, "POST", method_len) == 0) ||
        (strncmp(method, "HEAD", method_len) == 0) ||
        (strncmp(method, "OPTIONS", method_len) == 0) ||
        (strncmp(method, "CONNECT", method_len) == 0) ||
        (strncmp(method, "PUT", method_len) == 0) ||
        (strncmp(method, "DELETE", method_len) == 0) ||
        (strncmp(method, "TRACE", method_len) == 0)) {
        /* ok - method is legal */
    } else {
        /* invalid method */
        return NULL;
    }

    sep = my_strnchr(data, len, ' ');
    if (sep == NULL) return NULL;

    const char *resource = data;
    size_t resource_len = sep - data;
    data = sep + 1;  /* +1 for the space character after the resource */
    len -= resource_len + 1;

    sep = my_strnchr(data, len, '\r');
    if (sep == NULL) return NULL;

    /*
     * \r should occur at least 5 characters into the remaining data because
     * the current token should start with 'HTTP/'
     */
    size_t tok_len = sep - data;
    if (tok_len < 5) return NULL;

    /* make sure we can peek at the next char to check for a \n */
    if (tok_len == len-1) return NULL;
    if (sep[1] != '\n') return NULL;

    /* check that version token starts with "HTTP/" */
    if (strncmp(data, "HTTP/", 5) != 0) return NULL;

    const char *version = data + 5;
    size_t version_len = tok_len - 5;
    data = sep + 2;  /* +2 for the CRLF after the request line */
    len -= tok_len + 2;

    /* now parse header fields (full lines) */
    const char *user_agent = NULL;
    size_t user_agent_len = 0;
    const char *host = NULL;
    size_t host_len = 0;

    while ((user_agent == NULL) || (host == NULL)) {
        sep = my_strnchr(data, len, '\r');
        if (sep == NULL) break;
        size_t line_len = sep - data;

        /* make sure we can peek at the next char to check for a \n */
        if (line_len == len-1) break;
        if (sep[1] != '\n') break;

        /* check for 'Host' field */
        if ((line_len >= 5) && (strncmp(data, "Host:", 5) == 0)) {
            host = data + 5;
            host_len = line_len - 5;
            while ((host_len > 0) && isspace(host[0])) {
                host++;
                host_len--;
            }
            while ((host_len > 0) && isspace(host[host_len-1]))
                host_len--;
        }
        /* check for 'User-Agent' field */
        else if ((line_len >= 11) && (strncmp(data, "User-Agent:", 11) == 0)) {
            user_agent = data + 11;
            user_agent_len = line_len - 11;
            while ((user_agent_len > 0) && isspace(user_agent[0])) {
                user_agent++;
                user_agent_len--;
            }
            while ((user_agent_len > 0) && isspace(user_agent[user_agent_len-1]))
                user_agent_len--;
        }

        data = sep + 2;  /* +2 for the CRLF after the header line */
        len -= line_len + 2;
    }

    size_t resource_alloc_len = resource_len + host_len + 1;
    struct http_request *req = malloc(sizeof(struct http_request) + resource_alloc_len);
    if (req == NULL) return NULL;

    snprintf(req->method, sizeof(req->method), "%.*s", method_len, method);
    snprintf(req->version, sizeof(req->version), "%.*s", version_len, version);
    snprintf(req->resource, resource_alloc_len, "%.*s", resource_len, resource);

    if (host == NULL) {
        req->host = NULL;
    } else {
        req->host = req->host_alloc;
        snprintf(req->host_alloc, sizeof(req->host_alloc), "%.*s", host_len, host);
    }

    if (user_agent == NULL) {
        req->user_agent = NULL;
    } else {
        req->user_agent = req->user_agent_alloc;
        snprintf(req->user_agent_alloc, sizeof(req->user_agent_alloc), "%.*s",
            user_agent_len, user_agent);
    }
    return req;
}

const u_char *pktparse_radiotap_field(int field,
    const struct ieee80211_radiotap_header *header, const u_char *fields)
{
    uint32_t mask;
    int offset = 0;

    mask = (field == 0) ? 1 : 1 << field;
    if ((header->it_present & mask) == 0)  /* field is not present */ 
        return NULL;

    for (int i=0; i < field; i++) {
        mask = (i == 0) ? 1 : 1 << i;
        if (header->it_present & mask) {
            switch (i) {
            /* 64 bit fields */
            case IEEE80211_RADIOTAP_TSFT:
                offset += 8;
                break;

            /* 32 bit fields */
            case IEEE80211_RADIOTAP_CHANNEL:
                offset += 4;
                break;

            /* 16 bit fields */
            case IEEE80211_RADIOTAP_FHSS:
            case IEEE80211_RADIOTAP_LOCK_QUALITY:
            case IEEE80211_RADIOTAP_TX_ATTENUATION:
            case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
                offset += 2;
                break;

            /* 8 bit fields */
            case IEEE80211_RADIOTAP_FLAGS:
            case IEEE80211_RADIOTAP_RATE:
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            case IEEE80211_RADIOTAP_DBM_TX_POWER:
            case IEEE80211_RADIOTAP_ANTENNA:
            case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            case IEEE80211_RADIOTAP_DB_ANTNOISE:
                offset += 1;
                break;

            default:
                /* unsupported field - error */
                warnx("unsupported radiotap field: %u", i);
                return NULL;
            }
        }
    }

    return fields + offset;
}

/***********************************/
/*  Static Method Implementations  */
/***********************************/

static
const char *my_strnchr(const char *b, size_t len, char c)
{
    for (int i=0; i < len; i++) {
        if (b[i] == '\0')
            return NULL;
        if (b[i] == c)
            return b + i;
    }
    return NULL;
}

static
int parse_ethernet(struct packet * restrict packet)
{
    if (ETHER_HDR_LEN > packet->unparsed_len) return 0;
    packet->ether_hdr = (const struct ether_header*)(packet->unparsed);
    packet->unparsed += ETHER_HDR_LEN;
    packet->unparsed_len -= ETHER_HDR_LEN;
    return ETHER_HDR_LEN;
}

static
int parse_ieee80211(struct packet * restrict packet, u_char has_datapad,
    u_char has_fcs)
{
    if (IEEE802_11_FC_LEN > packet->unparsed_len) return 0;

    uint16_t fc = EXTRACT_LE_16BITS(packet->unparsed);
    uint hdrlen = wifi_min_hdrlen(fc);
    if (hdrlen == -1) {  /* failed to parse out header length */
        SET_PKT_ERR(packet, "invalid WIFI fc (x%04x)", fc);
        return -1;
    }

    if (hdrlen > packet->unparsed_len) return 0;

    packet->wifi_hdr = (struct ieee80211_frame*)(packet->unparsed);
    packet->wifi_fc = fc;
    packet->unparsed += hdrlen;
    packet->unparsed_len -= hdrlen;
    assert(packet->unparsed_len >= 0);

    /*
     * It appears that radiotap padding can only occur in data frames (possibly
     * also in management frames, before the management fields, but I have never
     * seen a management frame whose base 802.11 header was not already
     * 32bit-aligned).  Padding definitely does not occur in control frames.
     */

    /* radiotap padding comes AFTER the 802.11 header, but BEFORE mgmt fields */
    int padlen = 0;
    if (has_datapad && (FC_TYPE(fc) == T_DATA) && (hdrlen & 3))
        padlen = 4 - (hdrlen & 3);

    if (padlen) {
        if (packet->unparsed_len >= padlen) {
            hdrlen += padlen;
            packet->unparsed += padlen;
            packet->unparsed_len -= padlen;
        } else {
            hdrlen += packet->unparsed_len;
            packet->unparsed_len = 0;
        }
    }

    assert(packet->unparsed_len >= 0);

    /* FCS comes at the very end of the packet, after all other layers */
    if (has_fcs) {
        int trunc = 0;
        if (packet->caplen < packet->wirelen)
            trunc = packet->wirelen - packet->caplen;

        if (trunc < 4) {
            packet->unparsed_len -= (4 - trunc);
        } /* else, none of the FCS was captured, so we can ignore it */
    }

    assert(packet->unparsed_len >= 0);

    if (FC_WEP(fc)) {
        /* 
         * skip over the IV header; the original WEP header consisted of an
         * Initialization Vector followed by 1 byte for the key ID.  TKIP and
         * CCMP use an extended IV; we detect their usage by checking if the
         * key-ID byte has the EXTIV bytes set (which WEP will never set).
         */
        uint32_t crypto_header_len = IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
        if (packet->unparsed[IEEE80211_WEP_IVLEN] & IEEE80211_WEP_EXTIV)
            crypto_header_len += IEEE80211_WEP_EXTIVLEN;

        if ((hdrlen + crypto_header_len) > packet->unparsed_len)
            return hdrlen;

        hdrlen += crypto_header_len;
        packet->unparsed += crypto_header_len;
        packet->unparsed_len -= crypto_header_len;
        assert(packet->unparsed_len >= 0);
    }

    /* rarely, the payloads of management frames can be encrypted */
    if ((FC_TYPE(fc) == T_MGMT) && (!FC_WEP(fc))) {
        int n = parse_wifi_mgmt(packet);
        if (n < 0) return n;
        hdrlen += n;
    }

    return hdrlen;
}

static
int parse_ieee80211_radiotap(struct packet * restrict packet)
{
    if (RADIOTAP_HDR_LEN > packet->unparsed_len) return 0;
    packet->radiotap_hdr = (struct ieee80211_radiotap_header*)(packet->unparsed);

    uint32_t hdrlen = packet->radiotap_hdr->it_len;
    if (hdrlen > packet->unparsed_len) return 0;
    packet->radiotap_fields = packet->unparsed + RADIOTAP_HDR_LEN;
    packet->unparsed += hdrlen;
    packet->unparsed_len -= hdrlen;
    return hdrlen;
}

static
int parse_ip(struct packet * restrict packet)
{
    if (IP_HDR_LEN > packet->unparsed_len) return 0;
    packet->ip_hdr = (const struct ip*)(packet->unparsed);
    uint hdrlen = packet->ip_hdr->ip_hl*4;  /* units of ip_hl is 32 bit words */

    if (hdrlen > packet->unparsed_len) return 0;
    packet->unparsed += hdrlen;
    packet->unparsed_len -= hdrlen;
    return hdrlen;
}

static
int parse_ip6(struct packet * restrict packet)
{
    /*
     * ipv6 uses a fixed-length header plus optional "additional headers"
     * instead of IP option fields
     */
    if (IP6_HDR_LEN > packet->unparsed_len) return 0;
    packet->ip6_hdr = (const struct ip6_hdr*)(packet->unparsed);
    packet->unparsed += IP6_HDR_LEN;
    packet->unparsed_len -= IP6_HDR_LEN;
    return IP6_HDR_LEN;
}

static
int parse_llc(struct packet * restrict packet,
    uint16_t *ethertype)
{
    /* all LLCs start with llc_dsap, llc_ssap */
    if (2 > packet->unparsed_len) return 0;

    uint8_t dsap_field = packet->unparsed[0];
    uint8_t dsap = dsap_field & ~LLC_IG;
    uint8_t ssap_field = packet->unparsed[1];
    uint8_t ssap = ssap_field & ~LLC_GSAP;

    if (ssap == LLCSAP_SNAP && dsap == LLCSAP_SNAP) {
        if (LLC_SNAPFRAMELEN > packet->unparsed_len) return 0;
        uint8_t control = packet->unparsed[2];

        if (control == LLC_UI) {
	    packet->llc_hdr = (const struct llc*)(packet->unparsed);
            *ethertype = ntohs(packet->llc_hdr->llc_un.type_snap.ether_type);
            packet->unparsed += LLC_SNAPFRAMELEN;
            packet->unparsed_len -= LLC_SNAPFRAMELEN;
            return LLC_SNAPFRAMELEN;
        } else {  /* unrecognized LLC_UI */
            SET_PKT_ERR(packet, "unrecognized UI field for SNAP LLC header");
            return -1;
        }
    } else if (ssap == LLCSAP_IPX && dsap == LLCSAP_IPX) {
        /*
         * looks like an 802.2 (Novell) IPX header...  reference:
         * http://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_over_Ethernet
         */
        if (3 > packet->unparsed_len) return 0;
        uint8_t control = packet->unparsed[2];

        if (control == LLC_UI) {
	    packet->llc_hdr = (const struct llc*)(packet->unparsed);
            packet->unparsed += 3;
            packet->unparsed_len -= 3;
            return 3;
        } else {  /* unrecognized LLC_UI */
            SET_PKT_ERR(packet, "unrecognized UI field for IPX LLC header");
            return -1;
        }
    } else if (ssap_field == LLCSAP_GLOBAL && dsap_field == LLCSAP_GLOBAL) {
        /*
         * looks like an 802.3 (raw) IPX header... reference:
         * http://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_over_Ethernet
         *
         * comments copied from tcpdump/print-llc.c:
         *
         * This is an Ethernet_802.3 IPX frame; it has an
         * 802.3 header (i.e., an Ethernet header where the
         * type/length field is <= ETHERMTU, i.e. it's a length
         * field, not a type field), but has no 802.2 header -
         * the IPX packet starts right after the Ethernet header,
         * with a signature of two bytes of 0xFF (which is
         * LLCSAP_GLOBAL).
         * 
         * (It might also have been an Ethernet_802.3 IPX at
         * one time, but got bridged onto another network,
         * such as an 802.11 network; this has appeared in at
         * least one capture file.)
         */
        int ipxlen = sizeof(struct ipx);
        if (ipxlen > packet->unparsed_len) return 0;
        packet->unparsed += ipxlen;
        packet->unparsed_len -= ipxlen;
        return ipxlen;
    } else if (ssap_field == LLCSAP_NETBEUI && dsap_field == LLCSAP_NETBEUI) {
        /* looks like an NetBIOS / NetBEUI over LLC */
        if (3 > packet->unparsed_len) return 0;
        uint8_t control = packet->unparsed[2];

        if (control == LLC_UI) {
	    packet->llc_hdr = (const struct llc*)(packet->unparsed);
            packet->unparsed += 3;
            packet->unparsed_len -= 3;
            return 3;
        } else {  /* unrecognized LLC_UI */
            SET_PKT_ERR(packet, "unrecognized UI field for NetBIOS header");
            return -1;
        }
    } else {
        /* unsupported LLC header type */
        SET_PKT_ERR(packet, "unsupported LLC header type"
            " (dsap=0x%02x ssap=0x%02x)", dsap_field, ssap_field);
        return -1;
    }
}

static
int parse_tcp(struct packet * restrict packet)
{
    if (TCP_HDR_LEN > packet->unparsed_len) return 0;
    packet->tcp_hdr = (const struct tcphdr*)(packet->unparsed);

    uint hdrlen = packet->tcp_hdr->th_off*4;  /* units are 32 bit words */
    if (hdrlen > packet->unparsed_len) return 0;
    packet->unparsed += hdrlen;
    packet->unparsed_len -= hdrlen;
    return 1;
}

static
int parse_udp(struct packet * restrict packet)
{
    if (UDP_HDR_LEN > packet->unparsed_len) return 0;
    packet->udp_hdr = (const struct udphdr*)(packet->unparsed);
    packet->unparsed += UDP_HDR_LEN;
    packet->unparsed_len -= UDP_HDR_LEN;
    return 1;
}

/*
 * ripped (and modified) from tcpdump (parse_elements() in print-802_11.c)
 */
static
int parse_wifi_mgmt(struct packet * restrict packet)
{
    struct mgmt_body_t *mgmtp;
    int initial_unparsed_len = packet->unparsed_len;

    /*
     * 'Action' mgmt frames (subtype 13) have a special structure (parsing of
     * which is not currently supported)
     */
    if (FC_SUBTYPE(packet->wifi_fc) == ST_ACTION) return 0;

    /*
     * the mgmt_body field in the packet struct doesn't map 1-to-1 with a chunk
     * of bytes in the packet, so it has its own static storage allocation;
     * make the mgmt_body pointer point to that now (instead of being NULL).
     */
    packet->mgmt_body = &(packet->mgmt_body_field);
    mgmtp = packet->mgmt_body;
    
    /* first handle fixed parameters (order of checking these is important!)*/
#define DO_FIELD_CHECK(abbr, dst)                                       \
    if (MGMT_FRAME_HAS_ ## abbr (packet->wifi_fc)) {                    \
        if (IEEE802_11_ ## abbr ## _LEN > packet->unparsed_len) return 0; \
        memcpy(dst, packet->unparsed, IEEE802_11_ ## abbr ## _LEN);     \
        packet->unparsed += IEEE802_11_ ## abbr ## _LEN;                \
        packet->unparsed_len -= IEEE802_11_ ## abbr ## _LEN;            \
    }                                                                   \
    
    DO_FIELD_CHECK(AUTHALG, &mgmtp->auth_alg);
    DO_FIELD_CHECK(AUTHTRXN, &mgmtp->auth_trans_seq_num);
    DO_FIELD_CHECK(TSTAMP, mgmtp->timestamp);
    DO_FIELD_CHECK(BCNINT, &mgmtp->beacon_interval);
    DO_FIELD_CHECK(CAPINFO, &mgmtp->capability_info);
    DO_FIELD_CHECK(LISTENINT, &mgmtp->listen_interval);
    DO_FIELD_CHECK(AP, mgmtp->ap);
    DO_FIELD_CHECK(REASON, &mgmtp->reason_code);
    DO_FIELD_CHECK(STATUS, &mgmtp->status_code);
    DO_FIELD_CHECK(AID, &mgmtp->aid);

#undef DO_FIELD_CHECK

    /*
     * It appears that the 'challenge text' field doesn't always conform to the
     * specification (this might be because of WEP-encryption?).  So just don't
     * try to parse any variable-length information elements from Authentication
     * frames. 
     */
    if (FC_SUBTYPE(packet->wifi_fc) == ST_AUTH) goto finished;

    /* We haven't seen any elements yet. */
    mgmtp->challenge_status = NOT_PRESENT;
    mgmtp->ssid_status = NOT_PRESENT;
    mgmtp->rates_status = NOT_PRESENT;
    mgmtp->ds_status = NOT_PRESENT;
    mgmtp->cf_status = NOT_PRESENT;
    mgmtp->tim_status = NOT_PRESENT;

    while (packet->unparsed_len) {
        if (2 > packet->unparsed_len) return 0;
        elem_status_t *statusp;
        void *field;
        int maxlen = 0;

        switch (packet->unparsed[0]) {
        case E_SSID:
            statusp = &(mgmtp->ssid_status);
            field = (void*)&(mgmtp->ssid);
            maxlen = sizeof(struct ssid_t) - 1;
            memset(&mgmtp->ssid, '\0', sizeof(struct ssid_t));
            break;
        case E_CHALLENGE:
            statusp = &(mgmtp->challenge_status);
            field = (void*)&(mgmtp->challenge);
            maxlen = sizeof(struct challenge_t) - 1;
            memset(&mgmtp->challenge, '\0', sizeof(struct challenge_t));
            break;
        case E_RATES:
            statusp = &(mgmtp->rates_status);
            field = (void*)&(mgmtp->rates);
            maxlen = sizeof(struct rates_t);
            break;
        case E_DS:
            statusp = &(mgmtp->ds_status);
            field = (void*)&(mgmtp->ds);
            maxlen = sizeof(struct ds_t);
            break;
        case E_CF:
            statusp = &(mgmtp->cf_status);
            field = (void*)&(mgmtp->cf);
            maxlen = sizeof(struct cf_t);
            break;
        case E_TIM:
            statusp = &(mgmtp->tim_status);
            field = (void*)&(mgmtp->tim);
            maxlen = sizeof(struct tim_t);
            break;
        default:
            statusp = NULL;
            field = NULL;
            break;
        }

        int len = packet->unparsed[1];
        if (statusp != NULL) *statusp = TRUNCATED;
        if ((2 + len) > packet->unparsed_len) return 0;

        /* make sure that field isn't longer than spec (and struct) allows */
        if (field != NULL) {
            if (len > maxlen) {
                SET_PKT_ERR(packet, "mgmt field %d too large (len=%u, max=%u)",
                    packet->unparsed[0], len, maxlen);
                return -1;
            }
            memcpy(field, packet->unparsed, 2 + len);
            if (statusp != NULL) *statusp = PRESENT;
        }

        packet->unparsed += 2 + len;
        packet->unparsed_len -= 2 + len;
    }

 finished:
    return initial_unparsed_len - packet->unparsed_len;
}

static
int wifi_min_hdrlen(uint16_t fc)
{
    switch (FC_TYPE(fc)) {
    case T_MGMT:
        return MGMT_HDRLEN;
    case T_CTRL:
        switch (FC_SUBTYPE(fc)) {
        case CTRL_BAR:
            return CTRL_BAR_HDRLEN;
        case CTRL_BA:
            return CTRL_BA_HDRLEN;
        case CTRL_PS_POLL:
            return CTRL_PS_POLL_HDRLEN;
        case CTRL_RTS:
            return CTRL_RTS_HDRLEN;
        case CTRL_CTS:
            return CTRL_CTS_HDRLEN;
        case CTRL_ACK:
            return CTRL_ACK_HDRLEN;
        case CTRL_CF_END:
            return CTRL_END_HDRLEN;
        case CTRL_END_ACK:
            return CTRL_END_ACK_HDRLEN;
        default:
            return -1;
        }
    case T_DATA:
        return ((FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24) +
            (FC_QOS(fc) ? 2 : 0);
    default:
        return -1;
    }
}
