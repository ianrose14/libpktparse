/*
 * Author: Ian Rose
 * Date Created: Feb 25, 2008
 *
 * Prints text descriptions of packets read from a pcap file (similar in spirit
 * to tcpdump in offline mode).  This also serves as a nice test for the
 * pktparse library routines.
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/bpf.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#undef PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <netinet/in.h> /* for IPPROTO_* constants */
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <pktparse-print.h>
#include <ieee802_11.h>
#include "extract.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

/* defaults for command line arguments */
#define PCAPPRINT_DEF_IFNAME "ath0"
#define PCAPPRINT_DEF_SNAPLEN 256
#define PCAPPRINT_DEF_DLTNAME "IEEE802_11_RADIO"
#define PCAPPRINT_DEF_TIMESTAMP TS_NONE

/* hard-coded values */
#define PCAPPRINT_BPF_BUFSIZE (128*1024)  /* 128 KB*/
#define PCAPPRINT_READ_TIMEOUT 100        /* ms */

enum timestamp_fmt { TS_NONE, TS_ABS, TS_REL, TS_CTIME };


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* handle to pcap oject */
static pcap_t *pcap_h = NULL;

/* number of packets processed so far */
static uint32_t pkt_count = 0;

/* datalink type */
static int dlt;

/* how to print packet timestamps (if at all) */
static enum timestamp_fmt tsfmt = PCAPPRINT_DEF_TIMESTAMP;

/* network layers: datalink, network, transport, application */
static u_char enabled_layers[] = { 0, 0, 0, 0 };

/* whether to number packets as they are printed */
static u_char use_numbering = 0;

/* whether to print the FCS of mac headers */
static u_char print_fcs = 0;

/* be quiet? */
static u_char quiet = 0;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

static void signal_handler(int signum);


/**********/
/*  MAIN  */
/**********/

int main(int argc, char **argv)
{
    /* default values for command line arguments (see also static variables) */
    const char *if_name = PCAPPRINT_DEF_IFNAME;
    int snaplen = PCAPPRINT_DEF_SNAPLEN;
    const char *dlt_name = PCAPPRINT_DEF_DLTNAME;
    int num_pkts = -1;
    const char *pcap_filename = NULL;
    const char *bpf_expr = NULL;
    int rfmon = 0;

    /* process command line options */
    const char *usage = "usage: pcap-print [options]\n";

    int c;
    while ((c = getopt(argc, argv, ":1234ab:c:dfhi:mNqr:s:tVy:")) != -1) {
        switch (c) {
        case '1':
        case '2':
        case '3':
        case '4':
            enabled_layers[c-'0'-1]++;
            break;
        case 'a':
            /* arbitrary "big" number */
            enabled_layers[0] = 100;
            enabled_layers[1] = 100;
            enabled_layers[2] = 100;
            enabled_layers[3] = 100;
            break;
        case 'b':
            bpf_expr = optarg;
            break;
        case 'c':
            num_pkts = atoi(optarg);
            break;
        case 'd':
            tsfmt = TS_CTIME;
            break;
        case 'f':
            print_fcs = 1;
            break;
        case 'h':
            printf(usage);
            printf(
                "    -1  print data-link header (e.g. Ethernet)\n"
                "    -2  print network header (e.g. IP)\n"
                "    -3  print transport header (e.g. TCP)\n"
                "    -4  print application header (e.g. HTTP)\n"
                "    -a  print ALL headers, with maximum verbosity\n"
                "    -b  specify a BPF filter\n"
                "    -c  print only first N packets\n"
                "    -d  print absolute timestamp in date format\n"
                "    -f  print FCS for MAC headers\n"
                "    -h  print usage information and quit\n"
                "    -i  network interface on which to capture packets"
                " (default: %s)\n"
                "    -m  set rfmon mode on interface\n"
                "    -N  number packets as they are printed\n"
                "    -q  suppress printing of packet-parsing errors\n"
                "    -r  read from pcap file instead of live capture\n"
                "    -s  capture size in bytes (default: %d)\n"
                "    -t  print absolute timestamp\n"
                "    -V  print pcap version and quit\n"
                "    -y  datalink type for capturing interface (default: %s)\n",
                PCAPPRINT_DEF_IFNAME, PCAPPRINT_DEF_SNAPLEN, PCAPPRINT_DEF_DLTNAME);
            exit(0);
            break;
        case 'i':
            if_name = optarg;
            break;
        case 'm':
            rfmon = 1;
            break;
        case 'N':
            use_numbering = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'r':
            pcap_filename = optarg;
            break;
        case 's':
            snaplen = (int)strtol(optarg, (char **)NULL, 10);
            break;
        case 't':
            tsfmt = TS_ABS;
            break;
        case 'V':
            printf("%s\n", pcap_lib_version());
            exit(0);
            break;
        case 'y':
            dlt_name = optarg;
            break;
        case ':':
            errx(1, "option -%c requires an operand", optopt);
            break;
        case '?':
            errx(1, "unrecognized option: -%c", optopt);
            break;
        default:
            /* unhandled option indicates programming error */
            assert(0);
        }
    }

    /* if no layers we specified, use defaults (hard-coded) */
    if (! (enabled_layers[0] || enabled_layers[1] || enabled_layers[2] ||
            enabled_layers[3])) {
        enabled_layers[1] = 1;
        enabled_layers[2] = 1;
    }

    /* create pcap handle (either from file or from live capture) */
    char ebuf[PCAP_ERRBUF_SIZE];
    *ebuf = '\0';

    /* used only if a BPF program (filter) is specified */
    bpf_u_int32 netnum = 0, netmask = 0;

    if (pcap_filename != NULL) {
        /* "capture" from file */
        if (strcmp(if_name, PCAPPRINT_DEF_IFNAME) != 0)
            warnx("warning: -i option ignored when -f option is present");

        if (snaplen != PCAPPRINT_DEF_SNAPLEN)
            warnx("warning: -s option ignored when -f option is present");

        if (strcmp(dlt_name, PCAPPRINT_DEF_DLTNAME) != 0)
            warnx("warning: -y option ignored when -f option is present");

        pcap_h = pcap_open_offline(pcap_filename, ebuf);
        if (pcap_h == NULL)
            errx(1, "pcap_open_offline: %s", ebuf);
        else if (*ebuf)
            warnx("pcap_open_offline: %s", ebuf);

        /* read dlt from file */
        dlt = pcap_datalink(pcap_h);
    } else {
        /* live capture */
        dlt = pcap_datalink_name_to_val(dlt_name);
        if (dlt < 0)
            err(1, "invalid data link type %s", dlt_name);

        pcap_h = pcap_create(if_name, ebuf);
        if (pcap_h == NULL)
            errx(1, "pcap_create: %s", ebuf);

        if (pcap_set_snaplen(pcap_h, snaplen) != 0)
            errx(1, "pcap_set_snaplen: %s", pcap_geterr(pcap_h));

        if (pcap_set_promisc(pcap_h, 1) != 0)
            errx(1, "pcap_set_promisc: %s", pcap_geterr(pcap_h));

        if (rfmon) {
            if (pcap_can_set_rfmon(pcap_h) == 0)
                errx(1, "cannot set rfmon mode on device %s", if_name);

            if (pcap_set_rfmon(pcap_h, 1) != 0)
                errx(1, "pcap_set_rfmon: %s", pcap_geterr(pcap_h));
        }

        if (pcap_set_buffer_size(pcap_h, PCAPPRINT_BPF_BUFSIZE) != 0)
            errx(1, "pcap_set_buffer_size: %s", pcap_geterr(pcap_h));

        if (pcap_set_timeout(pcap_h, PCAPPRINT_READ_TIMEOUT) != 0)
            errx(1, "pcap_set_timeout: %s", pcap_geterr(pcap_h));

        if (pcap_lookupnet(if_name, &netnum, &netmask, ebuf) == -1)
            errx(1, "pcap_lookupnet: %s", ebuf);

        if (pcap_activate(pcap_h) != 0)
            errx(1, "pcap_activate: %s", pcap_geterr(pcap_h));

        /*
         * the following calls must be done AFTER pcap_activate():
         * pcap_setfilter
         * pcap_setdirection
         * pcap_set_datalink
         * pcap_getnonblock
         * pcap_setnonblock
         * pcap_stats
         * all reads/writes
         */

        if (pcap_set_datalink(pcap_h, dlt) == -1)
            errx(1, "pcap_set_datalink: %s", pcap_geterr(pcap_h));

        int r, yes = 1;
        int pcap_fd = pcap_get_selectable_fd(pcap_h);
        if ((r = ioctl(pcap_fd, BIOCIMMEDIATE, &yes)) == -1)
            err(1, "BIOCIMMEDIATE");
        else if (r != 0)
            warnx("BIOCIMMEDIATE returned %d", r);

        /* set up signal handlers */
        if (signal(SIGINT, SIG_IGN) != SIG_IGN)
            signal(SIGINT, signal_handler);
        if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
            signal(SIGTERM, signal_handler);
    }

    /* apply BPF filter (if one was specified) */
    if (bpf_expr != NULL) {
        struct bpf_program bpf;
        if (pcap_compile(pcap_h, &bpf, bpf_expr, 1 /*optimize*/, netmask) == -1)
            errx(1, "pcap_compile: %s", pcap_geterr(pcap_h));

        if (pcap_setfilter(pcap_h, &bpf) == -1)
            errx(1, "pcap_setfilter: %s", pcap_geterr(pcap_h));
    }

    /* start reading packets */
    if (pcap_loop(pcap_h, num_pkts, handle_packet, NULL) == -1)
        errx(1, "pcap_loop: %s", pcap_geterr(pcap_h));

    if (pcap_filename == NULL) { /* if live capture.. */
        printf("%u packets captured\n", pkt_count);
        struct pcap_stat stats;
        if (pcap_stats(pcap_h, &stats) != 0) {
            warnx("pcap_stats: %s", pcap_geterr(pcap_h));
        } else {
            printf("%u packets received by filter\n"
                "%u packets dropped by kernel\n", stats.ps_recv, stats.ps_drop);
        }
    }

    pcap_close(pcap_h);
    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

/*
 * Called by pcap_loop; prints a text description of the packet.
 */
static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp)
{
    /*
     * note; there is lots of double writing in this function (first stuff is
     * written to tmpbuf, then its copied from there to buf) but the code is
     * "safer" this way (no need to keep track of buffer offsets, etc.) and so
     * far performance isn't an issue.
     */
    char buf[1024] = "", tmpbuf[1024] = "";
    int buflen = sizeof(buf);
    int tmpbuflen = sizeof(tmpbuf);

    ++pkt_count;

    if (use_numbering)
        snprintf(buf, buflen, "%u: ", pkt_count);

    switch (tsfmt) {
    case TS_NONE:
        /* do nothing */
        break;

    case TS_ABS:
        snprintf(tmpbuf, tmpbuflen, "[%u.%06ld] ", h->ts.tv_sec, h->ts.tv_usec);
        break;

    case TS_REL: {
        static struct timeval last_ts = {0, 0};
        assert(h->ts.tv_sec >= last_ts.tv_sec);

        if (last_ts.tv_sec == 0) {
            snprintf(tmpbuf, tmpbuflen, "[%u.%06ld] ", 0, 0l);
        } else if (h->ts.tv_usec >= last_ts.tv_usec) {
            snprintf(tmpbuf, tmpbuflen, "[%u.%06ld] ",
                h->ts.tv_sec - last_ts.tv_sec, h->ts.tv_usec - last_ts.tv_usec);
        } else {  /* h->ts.tv_usec < last_ts.tv_usec */
            assert(h->ts.tv_sec > last_ts.tv_sec);
            snprintf(tmpbuf, tmpbuflen, "[%u.%06ld] ",
                h->ts.tv_sec - last_ts.tv_sec - 1,
                1000000l + h->ts.tv_usec - last_ts.tv_usec);
        }
        last_ts = h->ts;
    }
    case TS_CTIME: {
        char datebuf[32];
        time_t t = h->ts.tv_sec;
        ctime_r(&t, datebuf + 1);
        /* move the year to the front, overwriting the day-of-week */
        memcpy(datebuf, datebuf + 21, 4);
        datebuf[4] = ' ';
        datebuf[20] = '\0';  /* chop the trailing year and newline */
        snprintf(tmpbuf, tmpbuflen, "[%s.%06ld] ", datebuf, h->ts.tv_usec);
        break;
    }
    default:
        assert(0);  /* bad value for tsfmt */
    }

    if (strlcat(buf, tmpbuf, buflen) >= buflen)
        return;

    int start_buflen = strlen(buf);

    int flags = 0;
    if ((enabled_layers[1] + enabled_layers[2] + enabled_layers[3]) == 0) {
        /* if only layer 0 (MAC) is enabled, then ignore bad LLC values */
        flags |= PKTPARSE_IGNORE_BADLLC;
    }

    struct packet pkt;
    if (pktparse_parse(h, sp, dlt, &pkt, flags) == -1) {
        if (quiet) return;
        snprintf(tmpbuf, tmpbuflen, "bad packet: %s", pkt.errmsg);
        strlcat(buf, tmpbuf, buflen);
        goto finish;
    }

    u_char print_sep = 0;

    /* datalink layer */
    if (enabled_layers[0] && ((pkt.ether_hdr != NULL) || (pkt.wifi_hdr != NULL))) {
        int flags = (enabled_layers[0] > 1) ? PKTPARSE_PRINT_VERBOSE : 0;

        if (pkt.ether_hdr) {
            pktparse_print_ethernet(tmpbuf, tmpbuflen, pkt.ether_hdr, flags);
        } else if (pkt.wifi_hdr) {
            pktparse_print_wifi(tmpbuf, tmpbuflen, pkt.wifi_hdr, pkt.mgmt_body,
                flags);
        }

        if (strlcat(buf, tmpbuf, buflen) >= buflen)
            goto finish;

        /* if enabled, also include the FCS field at the end */
        if (print_fcs) {
            /* if packet was truncated at all, then we lost the FCS at the end */
            if ((pkt.caplen == pkt.wirelen) && (pkt.caplen >= 4)) {
                uint32_t index = pkt.caplen - 4;
                uint32_t fcs = EXTRACT_LE_32BITS(pkt.raw_packet + index);
                snprintf(tmpbuf, tmpbuflen, "FCS %08x ", fcs);
                
                if (strlcat(buf, tmpbuf, buflen) >= buflen)
                    goto finish;
            }
        }

        print_sep = 1;
    }

    /* if both network and transport layers are enabled, print them together */
    if (enabled_layers[1] && enabled_layers[2]) {
        int flags = 0;
        if ((enabled_layers[1] > 1) || (enabled_layers[2] > 1))
            flags |= PKTPARSE_PRINT_VERBOSE;

        tmpbuf[0] = '\0';
        switch (pkt.ethertype) {
        case -1:
            /* no ethertype parsed from packet */
            break;
        case ETHERTYPE_IP:
            if (pkt.ip_hdr) {
                if (pkt.tcp_hdr)
                    pktparse_print_tcpip(tmpbuf, tmpbuflen, pkt.ip_hdr, pkt.tcp_hdr, pkt.trans_len, flags);
                else if (pkt.udp_hdr)
                    pktparse_print_udpip(tmpbuf, tmpbuflen, pkt.ip_hdr, pkt.udp_hdr, pkt.trans_len, flags);
                else
                    pktparse_print_ip_proto(tmpbuf, tmpbuflen, pkt.ip_hdr, pkt.ipproto, pkt.trans_len, flags);
            }
            else
                snprintf(tmpbuf, tmpbuflen, "IP ");
            break;
        case ETHERTYPE_IPV6:
            if (pkt.ip6_hdr) {
                if (pkt.tcp_hdr)
                    pktparse_print_tcpip6(tmpbuf, tmpbuflen, pkt.ip6_hdr, pkt.tcp_hdr, pkt.trans_len, flags);
                else if (pkt.udp_hdr)
                    pktparse_print_udpip6(tmpbuf, tmpbuflen, pkt.ip6_hdr, pkt.udp_hdr, pkt.trans_len, flags);
                else
                    pktparse_print_ip6_proto(tmpbuf, tmpbuflen, pkt.ip6_hdr, pkt.ipproto, pkt.trans_len, flags);
            }
            else
                snprintf(tmpbuf, tmpbuflen, "IPv6 ");
            break;
        case ETHERTYPE_ARP:
            snprintf(tmpbuf, tmpbuflen, "ARP ");
            break;
        default:
            snprintf(tmpbuf, tmpbuflen, "ethertype 0x%04X ", pkt.ethertype);
            break;
        }

        if (strlen(tmpbuf) > 0) {
            if (print_sep) {
                if (strlcat(buf, "~ ", buflen) >= buflen)
                    goto finish;
                print_sep = 0;
            }
            if (strlcat(buf, tmpbuf, buflen) >= buflen)
                goto finish;
        }
    }
    else {
        /* if we can't merge network and transport layers, print whichever is enabled */
        tmpbuf[0] = '\0';

        if (enabled_layers[1]) {
            int flags = (enabled_layers[1] > 1) ? PKTPARSE_PRINT_VERBOSE : 0;

            switch (pkt.ethertype) {
            case -1:
                /* no ethertype parsed from packet */
                break;
            case ETHERTYPE_IP:
                if (pkt.ip_hdr)
                    pktparse_print_ip(tmpbuf, tmpbuflen, pkt.ip_hdr, pkt.trans_len, flags);
                break;
            case ETHERTYPE_IPV6:
                if (pkt.ip6_hdr)
                    pktparse_print_ip6(tmpbuf, tmpbuflen, pkt.ip6_hdr, pkt.trans_len, flags);
                break;
            case ETHERTYPE_ARP:
                snprintf(tmpbuf, tmpbuflen, "ARP ");
                break;
            default:
                snprintf(tmpbuf, tmpbuflen, "ethertype 0x%04X ", pkt.ethertype);
                break;
            }
        }
        else if (enabled_layers[2]) {
            int flags = (enabled_layers[2] > 1) ? PKTPARSE_PRINT_VERBOSE : 0;

            switch (pkt.ipproto) {
            case -1:
                /* no ip-proto parsed from packet */
                break;
            case IPPROTO_IP:
                snprintf(tmpbuf, tmpbuflen, "IP (encapsulation) ");
                break;
            case IPPROTO_ICMP:
                snprintf(tmpbuf, tmpbuflen, "ICMP ");
                break;
            case IPPROTO_IGMP:
                snprintf(tmpbuf, tmpbuflen, "IGMP ");
                break;
            case IPPROTO_TCP:
                if (pkt.tcp_hdr)
                    pktparse_print_tcp(tmpbuf, tmpbuflen, pkt.tcp_hdr, pkt.trans_len, flags);
                else
                    snprintf(tmpbuf, tmpbuflen, "TCP ");
                break;
            case IPPROTO_UDP:
                if (pkt.udp_hdr)
                    pktparse_print_udp(tmpbuf, tmpbuflen, pkt.udp_hdr, pkt.trans_len, flags);
                else
                    snprintf(tmpbuf, tmpbuflen, "UDP ");
                break;
            default:
                snprintf(tmpbuf, tmpbuflen, "ipproto 0x%02X  ", pkt.ipproto);
                break;
            }
        }

        if (strlen(tmpbuf) > 0) {
            if (print_sep) {
                if (strlcat(buf, "~ ", buflen) >= buflen)
                    goto finish;
                print_sep = 0;
            }
            if (strlcat(buf, tmpbuf, buflen) >= buflen)
                goto finish;
        }
    }
    
    /* application layer */
    if (enabled_layers[3]) {
        /* only HTTP request parsing is implemented so far */
        struct http_request *req = NULL;

        if (pkt.tcp_hdr != NULL) {
            req = pktparse_parse_http_request((char*)pkt.unparsed,
                pkt.unparsed_len);
        }

        if (req != NULL) {
            if (req->resource[0] == '/')
                snprintf(tmpbuf, tmpbuflen, "%s %s%s ", req->method, req->host,
                    req->resource);
            else
                snprintf(tmpbuf, tmpbuflen, "%s %s/%s ", req->method, req->host,
                    req->resource);
            if (strlcat(buf, tmpbuf, buflen) >= buflen)
                goto finish;

            /* if verbose printing is enabled, include the User-Agent string */
            if (enabled_layers[3] > 1) {
                snprintf(tmpbuf, tmpbuflen, "User-Agent: %s", req->user_agent);
                if (strlcat(buf, tmpbuf, buflen) >= buflen)
                    goto finish;
            }

            free(req);
        }
    }

 finish:
    if (strlen(buf) > start_buflen)
        printf("%s\n", buf);
}

static void
signal_handler(int signum)
{
    pcap_breakloop(pcap_h);
}
