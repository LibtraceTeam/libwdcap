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
#include <time.h>
#include <stdarg.h>

#include <libtrace.h>
#include <yaml.h>

#include "WdcapDiskWriter.h"

static uint32_t calcPeriodLength(FileRotationPeriod base, uint8_t freq) {

    /* Number of seconds in an hour */
    uint32_t period = 60 * 60;

    if (base == ROT_DAILY)
        period = period * 24;

    return (uint32_t) (period / freq);
}

static char *getCompressExtension(trace_option_compresstype_t method) {

    if (method == TRACE_OPTION_COMPRESSTYPE_ZLIB)
        return (char *)".gz";
    if (method == TRACE_OPTION_COMPRESSTYPE_BZ2)
        return (char *)".bz2";
    if (method == TRACE_OPTION_COMPRESSTYPE_LZO)
        return (char *)".lzo";
    if (method == TRACE_OPTION_COMPRESSTYPE_LZMA)
        return (char *)".xz";

    return (char *)"";

}

static char *stradd(const char *str, char *bufp, char *buflim) {
    while(bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

static char *generateFileName(char *base, char *format, uint32_t ts,
        FileRotationReason code, trace_option_compresstype_t compress,
        char *idstring) {

    char *ext;
    char scratch[10000];
    char result[10000];
    char codebuf[4];
    char tsbuf[11];
    struct timeval tv;
    char *w;
    char *end = scratch + sizeof(scratch);

    if (strcmp(format, "pcapfile") == 0) {
        ext = (char *)"pcap";
    } else {
        ext = format;
    }

    snprintf(codebuf, 3, "%u", code);

    char *p = base;

    assert(format != NULL);
    w = stradd(format, scratch, end);
    *w++ = ':';

    for (; *p; ++p) {
        if (*p == '%') {
            switch (*++p) {
                case '\0':
                    /* Reached end of naming scheme, stop */
                    --p;
                    break;
                case 'J':
                    /* Add rotation code */
                    w = stradd(codebuf, w, end);
                    continue;
                case 'P':
                    /* Add trace format extension */
                    w = stradd(ext, w, end);
                    continue;
                case 's':
                    /* Add unix timestamp */
                    snprintf(tsbuf, sizeof(tsbuf), "%u", ts);
                    w = stradd(tsbuf, w, end);
                    continue;
                case 'i':
                    if (idstring) {
                        w = stradd(idstring, w, end);
                    }
                    continue;
                default:
                    /* Everything should be handled by strftime */
                    --p;
            }
        }
        if (w == end)
            break;
        *w++ = *p;
    }

    /* Tack .gz on the end to indicate the file will be compressed */
    w = stradd(getCompressExtension(compress), w, end);
    /* Null termination */
    *w = '\0';

    /* Pass off to strftime to fill in the time conversions */
    tv.tv_sec = ts;
    strftime(result, sizeof(result), scratch, gmtime(&tv.tv_sec));
    return strdup(result);
}


WdcapDiskWriter *createWdcapDiskWriter(WdcapDiskWriterConfig *conf,
        char *idstr) {
    return new WdcapDiskWriter(conf, idstr);
}

void deleteWdcapDiskWriter(WdcapDiskWriter *writer) {
    delete(writer);
}

char *getWdcapDiskWriterErrorMessage(WdcapDiskWriter *writer) {
    return writer->getErrorMessage();
}

WdcapDiskWriter::WdcapDiskWriter(WdcapDiskWriterConfig *conf, char *idstr) {
    this->conf = conf;
    this->fileswritten = 0;
    this->nextrotate = 0;
    this->periodlength = calcPeriodLength(this->conf->getRotationPeriod(),
            this->conf->getRotationFrequency());
    this->outputName = NULL;
    this->output = NULL;
    this->filter = NULL;
    this->dropped = 0;
    this->errors = 0;
    this->cycle = CODE_WDCAPSTART;

    if (this->conf->getFilterString() != NULL) {
        this->filter = trace_create_filter(this->conf->getFilterString());
    }

    this->errorseen = 1;

    if (idstr) {
        this->idstring = strdup(idstr);
    } else {
        this->idstring = NULL;
    }
}

WdcapDiskWriter::~WdcapDiskWriter() {

    if (this->output) {
        trace_destroy_output(this->output);
    }

    if (this->outputName) {
        free(this->outputName);
    }

    if (this->filter) {
        trace_destroy_filter(this->filter);
    }

    if (this->idstring) {
        free(this->idstring);
    }

}

int writeWdcapPacketToDisk(WdcapDiskWriter *writer, libtrace_packet_t *pkt) {
    if (writer->isActive()) {
        return writer->writePacket(pkt);
    }
    return 0;
}

bool WdcapDiskWriter::isActive(void) {

    if (this->conf->getMaximumFiles() > 0 && this->fileswritten >=
                    this->conf->getMaximumFiles()) {
        //this->setErrorState("Maximum file count reached -- halting WdcapDiskWriter");
        return false;
    }

    return true;
}

int WdcapDiskWriter::writePacket(libtrace_packet_t *pkt) {
    libtrace_stat_t *stats;
    struct timeval tv;

    if (pkt->trace == NULL) {
        this->setErrorState("WdcapDiskWriter: packet has no source libtrace object?");
        return -1;
    }

    stats = trace_get_statistics(pkt->trace, NULL);
    if (stats->dropped_valid && stats->dropped > this->dropped) {
        this->cycle = CODE_LOSTPKT;
        this->dropped = stats->dropped;
    }
    if (stats->errors_valid && stats->errors > this->errors) {
        this->cycle = CODE_LOSTPKT;
        this->errors = stats->errors;
    }

    if (this->filter) {
        int filt = trace_apply_filter(this->filter, pkt);
        if (filt < 0) {
            this->setErrorState("WdcapDiskWriter: Error while attempting to filter packets");
            return -1;
        }
        if (filt == 0) {
            /* Packet does not match filter, skip it */
            return 1;
        }
    }

    tv = trace_get_timeval(pkt);
    if (this->cycle != CODE_NEWFILE) {
        this->createOutputFilename(tv.tv_sec);
        this->nextrotate = this->findNextRotate(tv.tv_sec);
        this->cycle = CODE_NEWFILE;
    } else if (tv.tv_sec >= this->nextrotate) {
        uint32_t nextend = this->findNextRotate(this->nextrotate + 1);

        /* Skip empty time periods */
        while (nextend <= tv.tv_sec) {
            this->nextrotate = nextend;
            nextend = this->findNextRotate(nextend + 1);
        }

        this->createOutputFilename(this->nextrotate);
        this->nextrotate = nextend;
    }

    /* If we don't have a valid file to write to at this point, something
     * has gone wrong. */

    if (!this->outputName) {
        this->setErrorState("WdcapDiskWriter was unable to create a suitable output filename");
        return -1;
    }

    if (!this->isActive()) {
        return 0;
    }

    if (this->output == NULL) {
        if (this->createOutputTrace() == -1) {
            return -1;
        }
    }

    if (this->conf->getStripOption()) {
        pkt = trace_strip_packet(pkt);
    }

    if (trace_write_packet(this->output, pkt) < 0) {
        libtrace_err_t err = trace_get_err_output(this->output);
        this->setErrorState("WdcapDiskWriter failed to write packet,",
                err.problem);
        return -1;
    }

    return 1;

}

void WdcapDiskWriter::createOutputFilename(uint32_t ts) {

        /* Close any existing output traces */
    if (this->output) {
        trace_destroy_output(this->output);
        this->output = NULL;

        /* Only increment the counter if we hit a rotation boundary */
        if (this->cycle == CODE_NEWFILE)
            this->fileswritten ++;

    }

    /* XXX Can we re-use this memory in some cases? Is it worthwhile? */
    if (this->outputName) {
        free(this->outputName);
    }

    this->outputName = generateFileName(this->conf->getNamingScheme(),
            this->conf->getFileFormat(), ts, this->cycle,
            this->conf->getCompressMethod(), this->idstring);

}

uint32_t WdcapDiskWriter::findNextRotate(uint32_t ts) {
    uint32_t next;

    /* Round to last hour or last day depending on our config */
    if (this->conf->getRotationPeriod() == ROT_DAILY) {
        next = (ts/86400)*86400;
    } else {
        next = (ts/3600)*3600;
    }

    /* Keep stepping ahead by 'periodlength' until we find the first boundary
     * after our current start time */
    while (next <= ts) {
        next += this->periodlength;
    }
    return next;
}

int WdcapDiskWriter::createOutputTrace(void) {

    libtrace_err_t err;
    if (this->outputName == NULL) {
        this->setErrorState("WdcapDiskWriter tried to open output trace without a filename!");
        return -1;
    }

    this->output = trace_create_output(this->outputName);
    if (trace_is_err_output(this->output)) {
        err = trace_get_err_output(this->output);
        this->setErrorState("WdcapDiskWriter encountered an error while creating output trace:", err.problem);
        return -1;
    }

    /* Configure compression options */
    int level = this->conf->getCompressLevel();
    if (trace_config_output(this->output, TRACE_OPTION_OUTPUT_COMPRESS, 
            &level) < 0) {
        err = trace_get_err_output(this->output);
        this->setErrorState("WdcapDiskWriter encountered an error while setting compression level:", err.problem);
        return -1;
    }

    trace_option_compresstype_t method = this->conf->getCompressMethod();
    if (trace_config_output(this->output, TRACE_OPTION_OUTPUT_COMPRESSTYPE, 
            &method) < 0) {
        err = trace_get_err_output(this->output);
        this->setErrorState("WdcapDiskWriter encountered an error while setting compression method:", err.problem);
        return -1;
    }

    /* Start the output trace */
    if (trace_start_output(this->output) < 0) {
        err = trace_get_err_output(this->output);
        this->setErrorState("WdcapDiskWriter encountered an error while starting the output trace:", err.problem);
        return -1;
    }

    return 1;

}

void WdcapDiskWriter::setErrorState(const char *msg,...) {

    /* XXX is it worth including the idstring in the message? */

    va_list va;
    va_start(va, msg);
    vsnprintf(this->errorstr, sizeof(this->errorstr), msg, va);
    va_end(va);

    this->errorseen = 0;
}

char *WdcapDiskWriter::getErrorMessage(void) {
    if (this->errorseen == 1) {
        return (char *)"No error";
    }

    this->errorseen = 1;
    return this->errorstr;
}

WdcapDiskWriterConfig::WdcapDiskWriterConfig() {

    this->fileformat = NULL;
    this->naming = NULL;
    this->compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    this->compresslevel = 1;
    this->rotperiod = ROT_HOURLY;
    this->rotfreq = 1;
    this->maxfiles = 0;
    this->filterstring = NULL;

}

WdcapDiskWriterConfig::~WdcapDiskWriterConfig() {
    if (this->fileformat)
        free(this->fileformat);
    if (this->naming)
        free(this->naming);
    if (this->filterstring)
        free(this->filterstring);
}

void WdcapDiskWriterConfig::setFileFormat(char *format) {
    if (this->fileformat)
        free(this->fileformat);
    this->fileformat = strdup(format);

}

void WdcapDiskWriterConfig::setFilterString(char *filter) {
    if (this->filterstring)
        free(this->filterstring);
    this->filterstring = strdup(filter);
}

void WdcapDiskWriterConfig::setNamingScheme(char *format) {
    if (this->naming)
        free(this->naming);
    this->naming = strdup(format);

}

void WdcapDiskWriterConfig::setCompressMethod(char *method) {
    if (strcmp(method, "gzip") == 0 || strcmp(method, "zlib") == 0)
        this->compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    else if (strcmp(method, "bzip") == 0 || strcmp(method, "bzip2") == 0)
        this->compressmethod = TRACE_OPTION_COMPRESSTYPE_BZ2;
    else if (strcmp(method, "lzo") == 0)
        this->compressmethod = TRACE_OPTION_COMPRESSTYPE_LZO;
    else if (strcmp(method, "xz") == 0)
        this->compressmethod = TRACE_OPTION_COMPRESSTYPE_LZMA;
    else
        this->compressmethod = TRACE_OPTION_COMPRESSTYPE_NONE;
}

void WdcapDiskWriterConfig::setCompressLevel(char *level) {
    uint64_t l = strtoul(level, NULL, 10);
    if (l > 9)
        l = 9;
    this->compresslevel = l;

}

void WdcapDiskWriterConfig::setRotationPeriod(char *period) {

    if (strcmp(period, "day") == 0 || strcmp(period, "daily") == 0)
        this->rotperiod = ROT_DAILY;

    if (strcmp(period, "hour") == 0 || strcmp(period, "hourly") == 0)
        this->rotperiod = ROT_HOURLY;
}

void WdcapDiskWriterConfig::setRotationFrequency(char *freq) {
    uint64_t f = strtoul(freq, NULL, 10);
    if (f > 255)
        f = 255;
    this->rotfreq = f;
}

void WdcapDiskWriterConfig::setMaximumFiles(char *max) {
    this->maxfiles = strtoul(max, NULL, 10);

}

void WdcapDiskWriterConfig::setStripOption(char *opt) {
    if (strcmp(opt, "yes") == 0 || strcmp(opt, "true") == 0) {
        this->stripopt = true;
    }

    if (strcmp(opt, "no") == 0 || strcmp(opt, "false") == 0) {
        this->stripopt = false;
    }
}

WdcapDiskWriterConfig *parseWdcapDiskWriterConfig(char *configfilename) {

    FILE *in;
    int returncode = -1;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    WdcapDiskWriterConfig *dconf = NULL;

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

    dconf = new WdcapDiskWriterConfig();

    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {
        yaml_node_t *optname = yaml_document_get_node(&document, pair->key);
        yaml_node_t *option = yaml_document_get_node(&document, pair->value);

        if (optname->type != YAML_SCALAR_NODE)
            continue;

        if (option->type == YAML_SCALAR_NODE && strcmp("format",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setFileFormat((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("namingscheme",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setNamingScheme((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("compressmethod",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setCompressMethod((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("compresslevel",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setCompressLevel((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("rotationperiod",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setRotationPeriod((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("rotationfreq",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setRotationFrequency((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("maxfiles",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setMaximumFiles((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("filter",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setFilterString((char *)option->data.scalar.value);
        } else if (option->type == YAML_SCALAR_NODE && strcmp("strip",
                (char *)optname->data.scalar.value) == 0) {
            dconf->setStripOption((char *)option->data.scalar.value);
        }
    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return dconf;
}

void deleteWdcapDiskWriterConfig(WdcapDiskWriterConfig *conf) {
    delete(conf);
}

char *WdcapDiskWriterConfig::getFileFormat(void) {
    return this->fileformat;
}

char *WdcapDiskWriterConfig::getNamingScheme(void) {
    return this->naming;
}

char *WdcapDiskWriterConfig::getFilterString(void) {
    return this->filterstring;
}

trace_option_compresstype_t WdcapDiskWriterConfig::getCompressMethod(void) {
    return this->compressmethod;
}

uint8_t WdcapDiskWriterConfig::getCompressLevel(void) {
    return this->compresslevel;
}

FileRotationPeriod WdcapDiskWriterConfig::getRotationPeriod(void) {
    return this->rotperiod;
}

uint8_t WdcapDiskWriterConfig::getRotationFrequency(void) {
    return this->rotfreq;
}

uint64_t WdcapDiskWriterConfig::getMaximumFiles(void) {
    return this->maxfiles;
}

bool WdcapDiskWriterConfig::getStripOption(void) {
    return this->stripopt;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
