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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include "WdcapPacketProcessor.h"
#include "HeaderWalk.h"
#include "WdcapAnon.h"

#include <yaml.h>
#include <libtrace.h>

static unsigned char *generateAnonKey(unsigned char *space) {
    /* If we move to using a crypto library, we can probably get
     * the library to generate us a key */
    FILE *input = fopen("/dev/urandom", "rb");

    if (space == NULL) {
        space = (unsigned char *)malloc(32);
    }

    fread(space, 1, 32, input);
    fclose(input);
    fprintf(stderr, "Generated new anonymisation key");
    return space;

}

WdcapPacketProcessor *createWdcapPacketProcessor(WdcapProcessingConfig *conf) {
    return new WdcapPacketProcessor(conf);
}

void deleteWdcapPacketProcessor(WdcapPacketProcessor *pktproc) {
    delete(pktproc);
}

WdcapPacketProcessor::WdcapPacketProcessor(WdcapProcessingConfig *pconf) {

    this->conf = pconf;

    if (pconf->getAnonymise() != WDCAP_ANON_NONE) {
        this->anon = new WdcapAnonymiser(pconf->getAnonKey(), 32, 20);
    } else {
        this->anon = NULL;
    }

    if (pconf->getInboundMACFilter()) {
        this->infilter = trace_create_filter(pconf->getInboundMACFilter());
    } else {
        this->infilter = NULL;
    }

    if (pconf->getOutboundMACFilter()) {
        this->outfilter = trace_create_filter(pconf->getOutboundMACFilter());
    } else {
        this->outfilter = NULL;
    }
}

WdcapPacketProcessor::~WdcapPacketProcessor(void) {

    if (this->anon) {
        delete(this->anon);
    }

    if (this->infilter) {
        trace_destroy_filter(this->infilter);
    }

    if (this->outfilter) {
        trace_destroy_filter(this->outfilter);
    }
}

void WdcapPacketProcessor::tagDirection(libtrace_packet_t *packet) {
    if (this->infilter && trace_apply_filter(this->infilter, packet)) {
        trace_set_direction(packet, TRACE_DIR_INCOMING);
    } else if (this->outfilter && trace_apply_filter(this->outfilter, packet)) {
        trace_set_direction(packet, TRACE_DIR_OUTGOING);
    } else if (this->infilter && this->outfilter) {
        trace_set_direction(packet, TRACE_DIR_OTHER);
    }
}

uint16_t WdcapPacketProcessor::processPacket(libtrace_packet_t *packet) {

    uint16_t caplen;
    uint32_t discard = 0;

    /* Check we have payload */
    if (trace_get_framing_length(packet) == 0)
        return 65535;

    if (trace_get_capture_length(packet) == -1)
        return 65535;

    if (trace_get_packet_buffer(packet, NULL, NULL) == NULL) {
        trace_set_capture_length(packet, 0);
        return 0;
    }

    /* Tag */
    if (this->infilter != NULL && this->outfilter != NULL) {
        this->tagDirection(packet);
    }

    /* Find payload -- anon as we go */
    /* If no anonymisation needed and full payload capture, we can skip this
     * step. */
    if (this->conf->getAnonymise() != WDCAP_ANON_NONE ||
            this->conf->getSnapPayload() < 65535) {
        discard = walkHeaders(this->conf, packet, this->anon);
    }

    /* Snap */
    caplen = trace_get_capture_length(packet);

    if (discard > 0 && discard <= caplen) {
        return trace_set_capture_length(packet, caplen - discard) + trace_get_framing_length(packet);
    } else if (discard > caplen) {
        fprintf(stderr, "Error: discard %u > caplen %u", discard, caplen);
        return 65535;
    }

    return trace_get_capture_length(packet) + trace_get_framing_length(packet);
}

uint16_t processWdcapPacket(WdcapPacketProcessor *pktproc,
        libtrace_packet_t *packet) {
    return pktproc->processPacket(packet);
}

WdcapProcessingConfig *parseWdcapProcessingConfig(char *configfilename) {

    FILE *in;
    int returncode = -1;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    WdcapProcessingConfig *pl = NULL;

    if ((in = fopen(configfilename, "r")) == NULL) {
        fprintf(stderr, "Failed to open config file: %s", strerror(errno));
        return NULL;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Malformed config file");
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        fprintf(stderr, "Config file is empty!");
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        fprintf(stderr, "Top level of config should be a map");
        goto endconfig;
    }

    pl = new WdcapProcessingConfig();
    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {
        yaml_node_t *optname = yaml_document_get_node(&document, pair->key);
        yaml_node_t *option = yaml_document_get_node(&document, pair->value);

        if (optname->type != YAML_SCALAR_NODE)
            continue;

        if (option->type == YAML_SCALAR_NODE && strcmp("anon",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setAnonymise((char *)option->data.scalar.value);
        }

        if (option->type == YAML_SCALAR_NODE && strcmp("checksum",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setChecksum((char *)option->data.scalar.value);
        }

        if (option->type == YAML_SCALAR_NODE && strcmp("payload",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setSnapPayload((char *)option->data.scalar.value);
        }

        if (option->type == YAML_SCALAR_NODE && strcmp("dnspayload",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setDNSPayload((char *)option->data.scalar.value);
        }

        if (option->type == YAML_SEQUENCE_NODE && strcmp("localmacs",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setLocalMACs(&document, option);
        }

        if (option->type == YAML_SEQUENCE_NODE && strcmp("externalmacs",
                    (char *)optname->data.scalar.value) == 0) {
            pl->setExternalMACs(&document, option);
        }

    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return pl;
}

void deleteWdcapProcessingConfig(WdcapProcessingConfig *conf) {
    delete(conf);
}

wdcapAnonMode WdcapProcessingConfig::getAnonymise(void) {
    return this->anon;
}

wdcapCsumMode WdcapProcessingConfig::getChecksum(void) {
    return this->csum;
}

uint16_t WdcapProcessingConfig::getSnapPayload(void) {
    return this->snappayload;
}

uint16_t WdcapProcessingConfig::getDNSPayload(void) {
    return this->dnspayload;
}

char * WdcapProcessingConfig::getInboundMACFilter(void) {
    return this->inmacfilter;
}

char * WdcapProcessingConfig::getOutboundMACFilter(void) {
    return this->outmacfilter;
}

unsigned char *WdcapProcessingConfig::getAnonKey(void) {
    return this->anonkey;
}

static inline char* updateMACFilter(char *filter, char *mac, const char *dir) {
        char *newfilter = NULL;

        if (filter == NULL) {
            asprintf(&newfilter, "ether %s %s", dir, mac);
        } else {
            /* A bit inefficient in terms of mallocs and frees -- we could
             * pre-calculate the amount of space we need based on the 
             * number of MACs in the sequence, but we'll have to be careful
             * to check that the scalar.value is the right length each time.
             */
            asprintf(&newfilter, "%s or ether %s %s", filter, dir, mac);
            free(filter);
        }
        return newfilter;
}

WdcapProcessingConfig::~WdcapProcessingConfig() {
    if (this->inmacfilter)
        free(this->inmacfilter);

    if (this->outmacfilter)
        free(this->outmacfilter);

}

void WdcapProcessingConfig::setAnonymise(char *anon) {

    if (strcmp(anon, "both") == 0)
        this->anon = WDCAP_ANON_BOTH;
    else if (strcmp(anon, "local") == 0)
        this->anon = WDCAP_ANON_LOCAL;
    else if (strcmp(anon, "external") == 0)
        this->anon = WDCAP_ANON_EXTERNAL;
    else
        this->anon = WDCAP_ANON_NONE;

    if (this->anon != WDCAP_ANON_NONE && this->anonkey == NULL) {
        this->anonkey = generateAnonKey(NULL);
    }

}

WdcapProcessingConfig::WdcapProcessingConfig() {
    this->anon = WDCAP_ANON_NONE;
    this->csum = WDCAP_CSUM_CHECK;
    this->snappayload = 65535;
    this->dnspayload = 0;
    this->inmacfilter = NULL;
    this->outmacfilter = NULL;

}

void WdcapProcessingConfig::setChecksum(char *csum) {
    if (strcmp(csum, "blank") == 0)
        this->csum = WDCAP_CSUM_BLANK;
    else if (strcmp(csum, "update") == 0)
        this->csum = WDCAP_CSUM_UPDATE;
    else if (strcmp(csum, "check") == 0)
        this->csum = WDCAP_CSUM_CHECK;
    else if (strcmp(csum, "leave") == 0)
        this->csum = WDCAP_CSUM_NONE;
    else
        this->csum = WDCAP_CSUM_CHECK;
}

void WdcapProcessingConfig::setSnapPayload(char *amount) {
    uint64_t snap = strtoul(amount, NULL, 10);
    if (snap > 65535)
        snap = 65535;

    this->snappayload = snap;

}

void WdcapProcessingConfig::setDNSPayload(char *amount) {
    uint64_t snap = strtoul(amount, NULL, 10);
    if (snap > 65535)
        snap = 65535;

    this->dnspayload = snap;

}


void WdcapProcessingConfig::setLocalMACs(yaml_document_t * doc, yaml_node_t *macs) {

    yaml_node_item_t *item;
    yaml_node_t *node;

    for (item = macs->data.sequence.items.start; 
           item != macs->data.sequence.items.top; item++) {
        node = yaml_document_get_node(doc, *item);

        if (node->type != YAML_SCALAR_NODE)
            continue;

        this->inmacfilter = updateMACFilter(this->inmacfilter,
                (char *)node->data.scalar.value, "dst");
        this->outmacfilter = updateMACFilter(this->outmacfilter,
                (char *)node->data.scalar.value, "src");
    }

}

void WdcapProcessingConfig::setExternalMACs(yaml_document_t * doc, 
        yaml_node_t *macs) {

    yaml_node_item_t *item;
    yaml_node_t *node;

    for (item = macs->data.sequence.items.start; 
           item != macs->data.sequence.items.top; item++) {
        char *newfilter = NULL;

        node = yaml_document_get_node(doc, *item);

        if (node->type != YAML_SCALAR_NODE)
            continue;

        this->inmacfilter = updateMACFilter(this->inmacfilter,
                (char *)node->data.scalar.value, "src");
        this->outmacfilter = updateMACFilter(this->outmacfilter,
                (char *)node->data.scalar.value, "dst");
    }

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
