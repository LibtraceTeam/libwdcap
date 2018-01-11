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

#ifndef WDCAP_DISK_WRITER_H_
#define WDCAP_DISK_WRITER_H_

#include <libtrace.h>

typedef enum {
    ROT_HOURLY,
    ROT_DAILY
} FileRotationPeriod;

typedef enum {
    CODE_NEWFILE = 0,
    CODE_KEYCHANGE = 1,
    CODE_LOSTPKT = 2,
    CODE_LOSTCONN = 3,
    CODE_WDCAPSTART = 4,
    CODE_CLIENTDROP = 5,
    CODE_TRUNCATED = 6
} FileRotationReason;


#ifdef __cplusplus

class WdcapDiskWriterConfig {
public:
    WdcapDiskWriterConfig();
    ~WdcapDiskWriterConfig();

    void setFileFormat(char *format);
    void setNamingScheme(char *format);
    void setCompressMethod(char *method);
    void setCompressLevel(char *level);
    void setRotationPeriod(char *period);
    void setRotationFrequency(char *freq);
    void setMaximumFiles(char *max);
    void setFilterString(char *string);
    void setStripOption(char *strip);

    char *getFileFormat(void);
    char *getNamingScheme(void);
    trace_option_compresstype_t getCompressMethod();
    uint8_t getCompressLevel();
    FileRotationPeriod getRotationPeriod();
    uint8_t getRotationFrequency();
    uint64_t getMaximumFiles();
    char *getFilterString();
    bool getStripOption();

private:
    char *fileformat;
    char *naming;
    trace_option_compresstype_t compressmethod;
    uint8_t compresslevel;
    FileRotationPeriod rotperiod;
    uint8_t rotfreq;
    uint64_t maxfiles;
    char *filterstring;
    bool stripopt;
};

class WdcapDiskWriter {
public:
    WdcapDiskWriter(WdcapDiskWriterConfig *conf, char *idstr);
    ~WdcapDiskWriter();
    int writePacket(libtrace_packet_t *packet);
    char *getErrorMessage();
    bool isActive();

private:

    uint32_t findNextRotate(uint32_t ts);
    int createOutputTrace(void);
    void setErrorState(const char *msg,...);
    void createOutputFilename(uint32_t ts);

    WdcapDiskWriterConfig *conf;
    uint64_t fileswritten;
    uint32_t nextrotate;
    uint32_t periodlength;
    char *outputName;
    libtrace_out_t *output;
    libtrace_filter_t *filter;
    uint64_t dropped;
    uint64_t errors;
    FileRotationReason cycle;

    char errorstr[1024];
    int errorseen;

    char *idstring;
};

#else
typedef struct wdcapdiskwriterconfig WdcapDiskWriterConfig;
typedef struct wdcapdiskwriter WdcapDiskWriter;
#endif


#ifdef __cplusplus
extern "C" {
#endif
WdcapDiskWriterConfig *parseWdcapDiskWriterConfig(char *configfilename);
void deleteWdcapDiskWriterConfig(WdcapDiskWriterConfig *conf);

WdcapDiskWriter *createWdcapDiskWriter(WdcapDiskWriterConfig *conf,
        char *idstr);
void deleteWdcapDiskWriter(WdcapDiskWriter *writer);
int writeWdcapPacketToDisk(WdcapDiskWriter *writer, libtrace_packet_t *pkt);
char *getWdcapDiskWriterErrorMessage(WdcapDiskWriter *writer);
#ifdef __cplusplus
}
#endif

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
