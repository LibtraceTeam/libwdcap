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


#ifndef WDCAP_PACKET_PROCESSOR_H_
#define WDCAP_PACKET_PROCESSOR_H_

#include <yaml.h>
#include <libtrace.h>

#ifdef __cplusplus
#include "WdcapAnon.h"
#endif

typedef enum {
    WDCAP_ANON_NONE,
    WDCAP_ANON_LOCAL,
    WDCAP_ANON_EXTERNAL,
    WDCAP_ANON_BOTH
} wdcapAnonMode;

/* Possible actions to perform on checksums after anonymisation to ensure
 * the checksum can't be used to try and "reverse" the anonymisation.
 */
typedef enum {
    WDCAP_CSUM_NONE,    // leave the checksum alone
    WDCAP_CSUM_CHECK,   // replace with 0 if correct, 1 if not
    WDCAP_CSUM_UPDATE,  // update checksum to be "correct"
    WDCAP_CSUM_BLANK    // always replace with 0
} wdcapCsumMode;

#ifdef __cplusplus
class WdcapProcessingConfig {
public:
    WdcapProcessingConfig();
    ~WdcapProcessingConfig();

    void setAnonymise(char *anon);
    void setChecksum(char *csum);
    void setSnapPayload(char *amount);
    void setDNSPayload(char *amount);
    void setLocalMACs(yaml_document_t *doc, yaml_node_t *maclist);
    void setExternalMACs(yaml_document_t *doc, yaml_node_t *maclist);


    wdcapAnonMode getAnonymise();
    wdcapCsumMode getChecksum();
    uint16_t getSnapPayload();
    uint16_t getDNSPayload();
    char *getInboundMACFilter();
    char *getOutboundMACFilter();
    unsigned char *getAnonKey();

private:
    wdcapAnonMode anon;
    wdcapCsumMode csum;
    uint16_t snappayload;
    uint16_t dnspayload;
    char *inmacfilter;
    char *outmacfilter;
    unsigned char *anonkey;

};

class WdcapPacketProcessor {
public:
    WdcapPacketProcessor(WdcapProcessingConfig *pconf);
    ~WdcapPacketProcessor();

    uint16_t processPacket(libtrace_packet_t *packet);

private:
    void tagDirection(libtrace_packet_t *packet);

    WdcapAnonymiser *anon;
    WdcapProcessingConfig *conf;
    libtrace_filter_t *infilter;
    libtrace_filter_t *outfilter;
};
#else
typedef struct wdcapprocessingconfig WdcapProcessingConfig;
typedef struct wdcappacketprocessor WdcapPacketProcessor;
#endif

#ifdef __cplusplus
extern "C" {
#endif
WdcapProcessingConfig *parseWdcapProcessingConfig(char *configfilename);
void deleteWdcapProcessingConfig(WdcapProcessingConfig *conf);
WdcapPacketProcessor *createWdcapPacketProcessor(WdcapProcessingConfig *conf);
void deleteWdcapPacketProcessor(WdcapPacketProcessor *pktproc);
uint16_t processWdcapPacket(WdcapPacketProcessor *pktproc,
        libtrace_packet_t *packet);

#ifdef __cplusplus
}
#endif
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
