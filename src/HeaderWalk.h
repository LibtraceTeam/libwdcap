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


#ifndef HEADER_WALK_H_
#define HEADER_WALK_H_

#include <libtrace.h>
#include "WdcapPacketProcessor.h"
#include "WdcapAnon.h"

struct ip4_pseudo_hdr {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t datalen;
    uint32_t extra;
};

struct ip6_pseudo_hdr {
    uint8_t ip_src[16];
    uint8_t ip_dst[16];
    uint32_t upper_len;
    uint16_t pad_16;
    uint8_t pad_8;
    uint8_t nextheader;
};

uint32_t walkHeaders(WdcapProcessingConfig *conf, libtrace_packet_t *packet,
        WdcapAnonymiser *anon);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
