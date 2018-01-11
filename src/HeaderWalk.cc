/*
 * This file is part of libwdcap
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libwdcap is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libwdcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwdcap. If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <string.h>
#include <libtrace.h>
#include <libpacketdump.h>
#include <assert.h>

#include "HeaderWalk.h"

static uint32_t walkIPv6(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip6_t *ip6, uint32_t rem, libtrace_direction_t dir);
static uint32_t walkIPv4(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip_t *ip, uint32_t rem, libtrace_direction_t dir);

static inline bool mustAnonSource(WdcapProcessingConfig *conf,
        libtrace_direction_t dir, WdcapAnonymiser *anon) {

    if (!anon)
        return false;

    switch(conf->getAnonymise()) {
    case WDCAP_ANON_BOTH:
        return true;
    case WDCAP_ANON_LOCAL:
        if (dir == TRACE_DIR_OUTGOING)
            return true;
        return false;
    case WDCAP_ANON_EXTERNAL:
        if (dir == TRACE_DIR_INCOMING)
            return true;
        return false;
    }

    return false;
}

static inline bool mustAnonDest(WdcapProcessingConfig *conf,
        libtrace_direction_t dir, WdcapAnonymiser *anon) {

    if (!anon)
        return false;

    switch(conf->getAnonymise()) {
    case WDCAP_ANON_BOTH:
        return true;
    case WDCAP_ANON_LOCAL:
        if (dir == TRACE_DIR_INCOMING)
            return true;
        return false;
    case WDCAP_ANON_EXTERNAL:
        if (dir == TRACE_DIR_OUTGOING)
            return true;
        return false;
    }

    return false;
}

static uint64_t addChecksum(uint16_t *buf, uint16_t size, uint64_t sum) {

    uint64_t *b = (uint64_t *)buf;

    while (size >= 8) {
        uint64_t s = *b++;
        sum += s;
        if (sum < s) sum++;
        size -= 8;
    }

    buf = (uint16_t *)b;
    if (size & 4) {
        uint32_t s = *(uint32_t *)buf;
        sum += s;
        if (sum < s) sum++;
        buf += 2;
    }

    if (size & 2) {
        uint16_t s = *buf;
        sum += s;
        if (sum < s) sum++;
        buf++;
    }

    if (size & 1) {
        uint8_t s = *(uint8_t *)buf;
        sum += s;
        if (sum < s) sum ++;
    }

    return sum;
}

static inline uint16_t finishChecksum(uint64_t sum) {

    uint32_t a,b;
    uint16_t c,d;

    a = (uint32_t)(sum & 0xffffffff);
    b = (sum >> 32);

    a += b;
    if (a < b) a++;
    c = (uint16_t)(a & 0xffff);
    d = (a >> 16);
    c += d;
    if (c < d) c++;

    return ~c;

}


static void anonymiseIPv6(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip6_t *ip6, libtrace_direction_t dir) {

    uint8_t encrypted[16];

    /* Anonymise IPs that require anonymisation */
    if (mustAnonSource(conf, dir, anon)) {
        anon->anonIPv6((uint8_t *) &ip6->ip_src.s6_addr, encrypted);
        memcpy(&ip6->ip_src.s6_addr, encrypted, 16);
    }

    if (mustAnonDest(conf, dir, anon)) {
        anon->anonIPv6((uint8_t *) &ip6->ip_dst.s6_addr, encrypted);
        memcpy(&ip6->ip_dst.s6_addr, encrypted, 16);
    }

}

static inline void updateChecksum16(uint16_t *csum, uint16_t old, 
        uint16_t repl) {
    uint32_t sum = (~htons(*csum) & 0xFFFF) + (~htons(old) & 0xFFFF) + 
            htons(repl);
    sum = (sum & 0xFFFF) + (sum >> 16);
    *csum = htons(~(sum + (sum >> 16)));

}

static uint16_t updateIPv4Checksum(uint16_t prev, uint32_t oldaddr, 
        uint32_t newaddr) {

    updateChecksum16(&prev, (uint16_t)(oldaddr >> 16), 
            (uint16_t)(newaddr >> 16));
    updateChecksum16(&prev, (uint16_t)(oldaddr & 0xFFFF), 
            (uint16_t)(newaddr & 0xFFFF));

    return prev;
}

static uint16_t updateIPv6Checksum(uint16_t prev, uint8_t *oldaddr,
        uint8_t *newaddr) {

    uint16_t *old16 = (uint16_t *)oldaddr;
    uint16_t *new16 = (uint16_t *)newaddr;

    /* TODO verify that this actually works */
    for (int i = 0; i < 8; i++) {
        updateChecksum16(&prev, *old16, *new16);
        old16++;
        new16++;
    }
    return prev;
}

static void anonymiseIPv4(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip_t *ip,
        uint32_t prevsrc, uint32_t prevdst, libtrace_direction_t dir) {

    if (conf->getChecksum() == WDCAP_CSUM_CHECK) {
        uint16_t old = ntohs(ip->ip_sum);
        uint64_t fsum = addChecksum((uint16_t *)ip, ip->ip_hl * 4, 0);
        uint16_t sum = finishChecksum(fsum);

        //printf("%u %u %u %u\n", old, fsum, sum, (uint16_t)~sum); 
        if (sum == 0) {
            /* If non-zero, the checksum is incorrect */
            ip->ip_sum = 0;
        } else {
            ip->ip_sum = ntohs(1);
        }
    }

    if (conf->getChecksum() == WDCAP_CSUM_BLANK) {
        ip->ip_sum = 0;
    }

    /* Anonymise IPs that require anonymisation */
    if (mustAnonSource(conf, dir, anon)) {
        ip->ip_src.s_addr = htonl(anon->anonIPv4(ntohl(ip->ip_src.s_addr)));
    }

    if (mustAnonDest(conf, dir, anon)) {
        ip->ip_dst.s_addr = htonl(anon->anonIPv4(ntohl(ip->ip_dst.s_addr)));
    }

    /* Update the IP checksum, if necessary */
    if (conf->getChecksum() == WDCAP_CSUM_UPDATE) {
        ip->ip_sum = updateIPv4Checksum(ip->ip_sum, prevsrc, ip->ip_src.s_addr);
        ip->ip_sum = updateIPv4Checksum(ip->ip_sum, prevdst, ip->ip_dst.s_addr);
    }
}

static void updateTransportChecksum(WdcapProcessingConfig *conf,
        uint16_t *check, uint8_t ipv, void *ip, uint8_t *prevsrc,
        uint8_t *prevdst) {

    if (ipv == 4) {
        libtrace_ip_t *ip4 = (libtrace_ip_t *)ip;
        uint32_t psrc = *(uint32_t *)prevsrc;
        uint32_t pdst = *(uint32_t *)prevdst;

        if (ip4->ip_src.s_addr != psrc) {
            *check = updateIPv4Checksum(*check, psrc, ip4->ip_src.s_addr);
        } 
        if (ip4->ip_dst.s_addr != pdst) {
            *check = updateIPv4Checksum(*check, pdst, ip4->ip_dst.s_addr);
        }
        return;
    }

    if (ipv == 6) {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)ip;
        
        *check = updateIPv6Checksum(*check, prevsrc, ip6->ip_src.s6_addr);
        *check = updateIPv6Checksum(*check, prevdst, ip6->ip_dst.s6_addr);
    }


}

static void updateICMPChecksum(WdcapProcessingConfig *conf, uint16_t *check,
        libtrace_icmp_t *icmp, uint32_t icmplen) {

    /* TODO implement */
    return;
}

static void updateICMP6Checksum(WdcapProcessingConfig *conf, uint16_t *check,
        void *ip6, libtrace_icmp6_t *icmp, uint32_t icmplen) {

    /* TODO implement */
    return;
}

static void checkICMPChecksum(WdcapProcessingConfig *conf, uint16_t *check, 
        libtrace_icmp_t *icmp, uint32_t icmplen, libtrace_ip_t *ip) {

    uint64_t calcsum = 0;
    uint16_t res = 0;

    if (icmplen + (ip->ip_hl * 4) < ntohs(ip->ip_len)) {
        *check = htons(2);
        return;
    }

    calcsum = addChecksum((uint16_t *)icmp, icmplen, 0);
    res = finishChecksum(calcsum);

    if (res == 0)
        *check = 0;
    else
        *check = htons(1);

    return;
}

static void checkTransportChecksum(WdcapProcessingConfig *conf, uint16_t *check,
        uint8_t ipv, void *ip, uint8_t *prevsrc, uint8_t *prevdst,
        void *payload, uint32_t rem) {

    uint64_t calcsum = 0;
    uint16_t finalsum = 0;
    uint16_t datalen = 0;
    uint16_t *pstart = NULL;

    char fullbuf[65536];
    char *next = fullbuf;

    if (ipv == 4) {
        libtrace_ip_t *ip4 = (libtrace_ip_t *)ip;
        uint32_t psrc = *(uint32_t *)prevsrc;
        uint32_t pdst = *(uint32_t *)prevdst;
        struct ip4_pseudo_hdr pseudo;

        /* Need full payload to calculate checksum */
        if (rem + (ip4->ip_hl * 4) < ntohs(ip4->ip_len)) {
            *check = htons(2);
            return;
        }
        
        datalen = ntohs(ip4->ip_len) - (ip4->ip_hl * 4);
    
        pseudo.ip_src = psrc;
        pseudo.ip_dst = pdst;
        pseudo.zeroes = 0;
        pseudo.protocol = ip4->ip_p;
        pseudo.datalen = htons(datalen);
        pseudo.extra = *(uint32_t *)payload;

        //printf("%u\n", datalen);
        pstart = ((uint16_t *)payload) + 2;
        datalen -= 4;

        calcsum = addChecksum((uint16_t *)&pseudo, 
                sizeof(struct ip4_pseudo_hdr), 0);

    } else if (ipv == 6) {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)ip;
        struct ip6_pseudo_hdr pseudo;

        /* Need full payload to calculate checksum */
        /* This is a bit tricky because we have to account for the
         * possibility of extension headers */
        if (rem + ((char *)payload - (char *)ip) <
                    ntohs(ip6->plen) + sizeof(libtrace_ip6_t)) {
            *check = htons(2);
            return;
        }

        datalen = ntohs(ip6->plen) + sizeof(libtrace_ip6_t) -
                ((char *)payload - (char *)ip);

        memcpy(pseudo.ip_src, prevsrc, 16);
        memcpy(pseudo.ip_dst, prevdst, 16);
        pseudo.upper_len = htons(datalen);
        pseudo.pad_16 = 0;
        pseudo.pad_8 = 0;
        pseudo.nextheader = ip6->nxt;
        pstart = (uint16_t *)payload;

        calcsum = addChecksum((uint16_t *)&pseudo,
                sizeof(struct ip6_pseudo_hdr), 0);
    }
    uint64_t fsum2 = 0;
    uint16_t finalsum2 = 0;

    calcsum = addChecksum(pstart, datalen, calcsum);
    finalsum = finishChecksum(calcsum);

    //printf("%u %lu %lu %u %u\n", datalen, calcsum, fsum2, finalsum, finalsum2);
    if (finalsum == 0) {
        *check = 0;
    } else {
        *check = htons(1);
    }
        
}

static uint32_t walkUDP(WdcapProcessingConfig *conf, libtrace_udp_t *udp,
        uint8_t ipv, void *ip, uint8_t *prevsrc, uint8_t *prevdst, 
        uint32_t rem) {

    void *payload;
    uint32_t udplen = rem;
    
    /* If we don't have the minimum TCP header, remove it */
    if (rem < sizeof(libtrace_udp_t))
        return rem;

    payload = trace_get_payload_from_udp(udp, &rem);
    if (payload == NULL)
        return 0;

    /* Fix the checksum if necessary */
    if (conf->getAnonymise() != WDCAP_ANON_NONE) {
        switch(conf->getChecksum()) {
        case WDCAP_CSUM_UPDATE: 
            updateTransportChecksum(conf, &udp->check, ipv, ip, prevsrc, prevdst);
            break;
        case WDCAP_CSUM_BLANK:
            udp->check = 0;
            break;
        case WDCAP_CSUM_CHECK:
            checkTransportChecksum(conf, &udp->check, ipv, ip, prevsrc, 
                    prevdst, udp, udplen);
            break;
        default:
            break;
        
        }
    }
    
    if (rem == 0)
        return 0;

    if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53) {
        if (conf->getDNSPayload() > conf->getSnapPayload()) {
            if (rem < conf->getDNSPayload())
                return 0;
            else
                return rem - conf->getDNSPayload();
        }
    }

    if (rem < conf->getSnapPayload())
        rem = 0;
    else
        rem -= conf->getSnapPayload();

    return rem;
}

static uint32_t walkTCP(WdcapProcessingConfig *conf, libtrace_tcp_t *tcp,
        uint8_t ipv, void *ip, uint8_t *prevsrc, uint8_t *prevdst, 
        uint32_t rem) {

    void *payload;
    uint32_t tcplen = rem;
    
    /* If we don't have the minimum TCP header, remove it */
    if (rem < sizeof(libtrace_tcp_t))
        return rem;

    payload = trace_get_payload_from_tcp(tcp, &rem);
    if (payload == NULL)
        return 0;

    /* Fix the checksum if necessary */
    if (conf->getAnonymise() != WDCAP_ANON_NONE) {
        switch(conf->getChecksum()) {
        case WDCAP_CSUM_UPDATE: 
            updateTransportChecksum(conf, &tcp->check, ipv, ip, prevsrc, prevdst);
            break;
        case WDCAP_CSUM_BLANK:
            tcp->check = 0;
            break;
        case WDCAP_CSUM_CHECK:
            checkTransportChecksum(conf, &tcp->check, ipv, ip, prevsrc, 
                    prevdst, tcp, tcplen);
            break;
        default:
            break;
        }
    }

    if (ntohs(tcp->source) == 53 || ntohs(tcp->dest) == 53) {
        if (conf->getDNSPayload() > conf->getSnapPayload()) {
            if (rem < conf->getDNSPayload())
                return 0;
            else
                return rem - conf->getDNSPayload();
        }
    }

    if (rem < conf->getSnapPayload())
        rem = 0;
    else
        rem -= conf->getSnapPayload();

    return rem;
}

static uint32_t walkICMP6(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_icmp6_t *icmp,
        uint32_t rem, void *ip, uint8_t *prevsrc, uint8_t *prevdst,
        libtrace_direction_t dir) {

    void *payload;
    uint32_t icmplen = rem;

    if (rem < sizeof(libtrace_icmp6_t))
        return 0;

    if (conf->getAnonymise() != WDCAP_ANON_NONE) {
        switch(conf->getChecksum()) {
        case WDCAP_CSUM_UPDATE: 
            break;
        case WDCAP_CSUM_BLANK:
            icmp->checksum = 0;
            break;
        case WDCAP_CSUM_CHECK:
            checkTransportChecksum(conf, &icmp->checksum, 6, ip, prevsrc,
                    prevdst, icmp, icmplen);
            break;
        default:
            break;
        }
    }

    if (conf->getChecksum() == WDCAP_CSUM_UPDATE && 
            conf->getAnonymise() != WDCAP_ANON_NONE) {
        /* Re-calculate the checksum TODO */
        updateICMP6Checksum(conf, &icmp->checksum, ip, icmp, icmplen);
    }

    payload = trace_get_payload_from_icmp6(icmp, &rem);
    if (payload == NULL || rem == 0)
        return 0;

    return rem;
}

static uint32_t walkICMP(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_icmp_t *icmp,
        uint32_t rem, libtrace_direction_t dir, libtrace_ip_t *ip) {

    void *payload;
    uint32_t icmplen = rem;

    if (rem < sizeof(libtrace_icmp_t))
        return 0;

    if (conf->getAnonymise() != WDCAP_ANON_NONE) {
        switch(conf->getChecksum()) {
        case WDCAP_CSUM_UPDATE: 
            break;
        case WDCAP_CSUM_BLANK:
            icmp->checksum = 0;
            break;
        case WDCAP_CSUM_CHECK:
            checkICMPChecksum(conf, &icmp->checksum, icmp, icmplen, ip);
            break;
        default:
            break;
        }
    }

    payload = trace_get_payload_from_icmp(icmp, &rem);
    if (payload == NULL || rem == 0)
        return 0;

    switch(icmp->type) {
        case 3:
        case 11:
        case 12:
            libtrace_ip_t *ip = (libtrace_ip_t *)payload;
            /* Reverse direction */
            if (dir == TRACE_DIR_OUTGOING)
                dir = TRACE_DIR_INCOMING;
            else if (dir == TRACE_DIR_INCOMING)
                dir = TRACE_DIR_OUTGOING;
            rem = walkIPv4(conf, anon, ip, rem, dir);

            if (conf->getChecksum() == WDCAP_CSUM_UPDATE && 
                    conf->getAnonymise() != WDCAP_ANON_NONE) {
                /* Re-calculate the checksum */
                updateICMPChecksum(conf, &icmp->checksum, icmp, icmplen);
            }
            break;
    }

    return rem;
}

static uint32_t walkIPv6(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip6_t *ip6, uint32_t rem, libtrace_direction_t dir) {
    void *ip_payload;
    uint8_t proto;
    /* Remember unanonymised IPs for checksum updates */
    uint8_t prevsrc[16];
    uint8_t prevdst[16];

    /* If the IP header is incomplete, discard it */
    if (rem < sizeof(libtrace_ip6_t))
        return rem;

    /* TODO Fragments? */

    if (conf->getAnonymise() != WDCAP_ANON_NONE) {
        memcpy(prevsrc, &ip6->ip_src.s6_addr, 16);
        memcpy(prevdst, &ip6->ip_dst.s6_addr, 16);
        anonymiseIPv6(conf, anon, ip6, dir);
    }

    ip_payload = trace_get_payload_from_ip6(ip6, &proto, &rem);
    if (ip_payload == NULL || rem == 0) {
        return 0;
    }

    switch (proto) {
    case TRACE_IPPROTO_ICMPV6:
        rem = walkICMP6(conf, anon, (libtrace_icmp6_t *)ip_payload, rem, ip6,
                prevsrc, prevdst, dir);
        break;
    case TRACE_IPPROTO_TCP:
        rem = walkTCP(conf, (libtrace_tcp_t *)ip_payload, 6, ip6,
                prevsrc, prevdst, rem);
        break;
    case TRACE_IPPROTO_UDP:
        rem = walkUDP(conf, (libtrace_udp_t *)ip_payload, 6, ip6,
                prevsrc, prevdst, rem);
        break;
    case TRACE_IPPROTO_IPIP:
        rem = walkIPv4(conf, anon, (libtrace_ip_t *)ip_payload, rem, dir);
        break;
    default:
        break;
    }
    return rem;
}

static uint32_t walkIPv4(WdcapProcessingConfig *conf, WdcapAnonymiser *anon,
        libtrace_ip_t *ip, uint32_t rem, libtrace_direction_t dir) {
    void *ip_payload;
    uint8_t proto;
    /* Remember unanonymised IPs for checksum updates */
    uint32_t prevsrc;
    uint32_t prevdst;

    /* If the IP header is incomplete, discard it */
    if (rem < ip->ip_hl * 4)
        return rem;

    /* Check IP version */
    if (ip->ip_v != 4) {
        //logger(LOG_DAEMON, "WARNING: bad IPv4 version: %u", ip->ip_v);
        return rem;
    }

    if (ip->ip_off & 0xff1f) {
        /* This is a fragment and not the first fragment */

        /* Decrease remaining by the size of the IP header and discard the
         * rest of the packet.
         */
        if (rem < (ip->ip_hl * 4))
            return 0;
        return (rem - (ip->ip_hl * 4));
    }

    prevsrc = ip->ip_src.s_addr;
    prevdst = ip->ip_dst.s_addr;
    if (conf->getAnonymise() != WDCAP_ANON_NONE)
        anonymiseIPv4(conf, anon, ip, prevsrc, prevdst, dir);

    ip_payload = trace_get_payload_from_ip(ip, &proto, &rem);
    if (ip_payload == NULL || rem == 0)
        return 0;

    switch (proto) {
    case TRACE_IPPROTO_ICMP:
        rem = walkICMP(conf, anon, (libtrace_icmp_t *)ip_payload, rem, dir, ip);
        break;
    case TRACE_IPPROTO_TCP:
        rem = walkTCP(conf, (libtrace_tcp_t *)ip_payload, ip->ip_v, ip,                 (uint8_t *)&prevsrc, (uint8_t *)&prevdst, rem);
        break;
    case TRACE_IPPROTO_UDP:
        rem = walkUDP(conf, (libtrace_udp_t *)ip_payload, ip->ip_v, ip,                 (uint8_t *)&prevsrc, (uint8_t *)&prevdst, rem);
        break;
    case TRACE_IPPROTO_IPV6:
        rem = walkIPv6(conf, anon, (libtrace_ip6_t *)ip_payload, rem, dir);
        break;
    case TRACE_IPPROTO_IPIP:
        rem = walkIPv4(conf, anon, (libtrace_ip_t *)ip_payload, rem, dir);
        break;
    default:
        break;
    }

    return rem;
}

uint32_t walkHeaders(WdcapProcessingConfig *conf, libtrace_packet_t *packet,
        WdcapAnonymiser *anon) {
    
    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    libtrace_direction_t dir;
    
    l3 = trace_get_layer3(packet, &ethertype, &rem);

    if (l3 == NULL) {
        return 0;
    }

    dir = trace_get_direction(packet);

    if (ethertype == TRACE_ETHERTYPE_IP) {
        return walkIPv4(conf, anon, (libtrace_ip_t *)l3, rem, dir);
    }

    if (ethertype == TRACE_ETHERTYPE_IPV6) {
        return walkIPv6(conf, anon, (libtrace_ip6_t *)l3, rem, dir);
    }

    return rem;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

