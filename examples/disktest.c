/*
 * This file is part of libwdcap
 *
 * Copyright (c) 2018, 2019 The University of Waikato, Hamilton, New Zealand.
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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#include <libtrace.h>
#include <libtrace_parallel.h>
#include <WdcapDiskWriter.h>

static int count = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static libtrace_t *trace = NULL;

static void stop(int signal UNUSED)
{
    if (trace)
        trace_pstop(trace);
}


static void *init_test(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
        void *global) {

    WdcapDiskWriterConfig *conf = (WdcapDiskWriterConfig *)global;
    WdcapDiskWriter *writer;
    char idstr[128];

    pthread_mutex_lock(&lock);
    snprintf(idstr, 128, "t%d", count);
    count ++;
    pthread_mutex_unlock(&lock);

    writer = createWdcapDiskWriter(conf, idstr);
    return writer;
}

static void stop_test(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
        void *global, void *tls) {
    WdcapDiskWriterConfig *conf = (WdcapDiskWriterConfig *)global;
    WdcapDiskWriter *writer = (WdcapDiskWriter *)tls;

    deleteWdcapDiskWriter(writer);
}

static libtrace_packet_t *per_packet(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED,
        void *global UNUSED, void *tls, libtrace_packet_t *packet) {

    WdcapDiskWriter *writer = (WdcapDiskWriter *)tls;
    if (writeWdcapPacketToDisk(writer, packet) == -1) {
        fprintf(stderr, "ERROR | %s\n", getWdcapDiskWriterErrorMessage(writer));
    }
    return packet;
}

void usage(char *prog) {
    fprintf(stderr, "Usage: %s -c wdcapconfig -s sourceuri [-t threads]\n",
            prog);
}


int main(int argc, char *argv[]) {

    int nb_threads = 2;
    char *wdcapconffile = NULL;
    char *sourceuri = NULL;
    libtrace_callback_set_t *proccbs = NULL;
    int result = 0;
    WdcapDiskWriterConfig *wdcapconf = NULL;
    struct sigaction sigact;

    sigact.sa_handler = stop;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    while (1) {
        int optind, c;
        struct option long_options[] = {
            { "threads", 1, 0, 't' },
            { "config", 1, 0, 'c' },
            { "source", 1, 0, 's' },
            { "help", 0, 0, 'h' },
            { NULL, 0, 0, 0 },
        };

        c = getopt_long(argc, argv, "ht:c:s:", long_options, &optind);
        if (c == -1)
            break;
        switch(c) {
            case 't':
                nb_threads = atoi(optarg);
                break;
            case 'c':
                wdcapconffile = optarg;
                break;
            case 's':
                sourceuri = optarg;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (nb_threads <= 0) {
        nb_threads = 1;
    }

    if (wdcapconffile == NULL) {
        fprintf(stderr, "Please specify the location of the wdcap writer config file.\n\n");
        usage(argv[0]);
        return 1;
    }

    if (sourceuri == NULL) {
        fprintf(stderr, "Please specify the source of your packets.\n\n");
        usage(argv[0]);
        return 1;
    }

    trace = trace_create(sourceuri);
    if (trace_is_err(trace)) {
        trace_perror(trace, "Creating source trace object");
        return 1;
    }

    proccbs = trace_create_callback_set();
    trace_set_starting_cb(proccbs, init_test);
    trace_set_stopping_cb(proccbs, stop_test);
    trace_set_packet_cb(proccbs, per_packet);

    trace_set_perpkt_threads(trace, nb_threads);

    wdcapconf = parseWdcapDiskWriterConfig(wdcapconffile);
    if (wdcapconf == NULL) {
        fprintf(stderr, "Failed to parse WdcapDiskWriter config file.");
        result = 1;
    } else if (trace_pstart(trace, wdcapconf, proccbs, NULL)) {
        trace_perror(trace, "Starting source trace");
        result = 1;
    } else {
        trace_join(trace);

        if (trace_is_err(trace)) {
            trace_perror(trace, "Reading packets from source trace");
            result = 1;
        }
    }

    deleteWdcapDiskWriterConfig(wdcapconf);
    trace_destroy_callback_set(proccbs);
    trace_destroy(trace);

    pthread_mutex_destroy(&lock);

    return result;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
