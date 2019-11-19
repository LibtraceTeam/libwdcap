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
#include <WdcapPacketProcessor.h>


#define PPROC_FAIL	65535

typedef struct trace_globals_type {
    WdcapDiskWriterConfig *dwconf;
    WdcapProcessingConfig *ppconf;

} trace_globals_type;
static trace_globals_type trace_globals;

typedef struct trace_locals_type {
    WdcapDiskWriter *writer;
    WdcapPacketProcessor *pproc;
} trace_locals_type;

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
    trace_locals_type *trace_locals = malloc(sizeof*trace_locals);
    trace_globals_type *trace_globals = (trace_globals_type*)global;
    WdcapDiskWriterConfig *dwconf = trace_globals->dwconf;
    WdcapProcessingConfig *ppconf = trace_globals->ppconf;
    char idstr[128];

    pthread_mutex_lock(&lock);
    snprintf(idstr, 128, "t%d", count);
    count ++;
    pthread_mutex_unlock(&lock);

    trace_locals->writer = createWdcapDiskWriter(dwconf, idstr);
    trace_locals->pproc = createWdcapPacketProcessor(ppconf);
    return trace_locals;
}

static void stop_test(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
        void *global, void *tls) {
    trace_globals_type *trace_globals = (trace_globals_type*)global;
    trace_locals_type *trace_locals = (trace_locals_type*)tls;
    WdcapDiskWriterConfig *conf = trace_globals->dwconf;
    WdcapDiskWriter *writer = trace_locals->writer;
    WdcapPacketProcessor *pproc = trace_locals->pproc;
    deleteWdcapDiskWriter(writer);
    deleteWdcapPacketProcessor(pproc);
    free(trace_locals);
}

static libtrace_packet_t *per_packet(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED,
        void *global, void *tls, libtrace_packet_t *packet) {
    trace_globals_type *trace_globals = (trace_globals_type*)global;
    trace_locals_type *trace_locals = (trace_locals_type*)tls;
    WdcapPacketProcessor *pproc = trace_locals->pproc;
    WdcapDiskWriter *writer = trace_locals->writer;
    int newlen = processWdcapPacket(pproc, packet);
    if (newlen == PPROC_FAIL) {
	fprintf(stderr, "ERROR in process packet\n");
	return packet;
    }
    if (writeWdcapPacketToDisk(writer, packet) == -1) {
        fprintf(stderr, "ERROR | %s\n", getWdcapDiskWriterErrorMessage(writer));
    }
    return packet;
}


void show_usage(char *prog) {
    fprintf(stderr, "Usage: %s -c WdcapDiskWriter.yaml -p WdcapProcessingConfig.yaml -s sourceuri [-t threads]\n",
            prog);
}


void show_error(char *error_msg) {
    fprintf(stderr, "%s.\n\n", error_msg);
}


void show_usage_error(char *argv[], char *error_msg) {
    show_error(error_msg);
    show_usage(argv[0]);
}


int parse_args(int argc, char *argv[], int *nb_threads, char **sourceuri,
		WdcapDiskWriterConfig **dwconf, WdcapProcessingConfig **ppconf) {
    char *dwconffile = NULL;
    char *ppconffile = NULL;
    int help = 0;

    while (1) {
        int optind, c;
        struct option long_options[] = {
            { "threads", 1, 0, 't' },
            { "dwconfig", 1, 0, 'c' },
            { "ppconfig", 1, 0, 'p' },
            { "source", 1, 0, 's' },
            { "help", 0, 0, 'h' },
            { NULL, 0, 0, 0 },
        };

        c = getopt_long(argc, argv, "ht:c:s:p:", long_options, &optind);
        if (c == -1)
            break;
        switch(c) {
            case 't':
                *nb_threads = atoi(optarg);
                break;
            case 'c':
                dwconffile = optarg;
                break;
            case 'p':
                ppconffile = optarg;
                break;
            case 's':
                *sourceuri = optarg;
                break;
            case 'h':
		help = 1;
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
		help = 1;
        }
    }

    if (help) {
	show_usage(argv[0]);
        return 1;
    }

    if (*nb_threads <= 0) {
        *nb_threads = 1;
    }

    if (dwconffile == NULL) {
        show_usage_error(argv, "Please specify the location of the WdcapDiskWriterConfig file");
        return 1;
    }

    *dwconf = parseWdcapDiskWriterConfig(dwconffile);
    if (*dwconf == NULL) {
        show_error("Failed to parse WdcapDiskWriterConfig file");
	return 1;
    }

    if (ppconffile == NULL) {
        show_usage_error(argv, "Please specify the location of the WdcapProcessingConfig file");
        return 1;
    }

    *ppconf = parseWdcapProcessingConfig(ppconffile);
    if (*ppconf == NULL) {
	show_error("Failed to parse WdcapProcessingConfig file");
	return 1;
    }

    if (*sourceuri == NULL) {
        show_usage_error(argv, "Please specify the source URI of your packets");
        return 1;
    }

    return 0;
}


void set_signals() {
    struct sigaction sigact;

    sigact.sa_handler = stop;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
}


int main(int argc, char *argv[]) {
    int nb_threads = 2;
    char *sourceuri = NULL;
    libtrace_callback_set_t *proccbs = NULL;
    int result = 0;

    if (parse_args(argc, argv, &nb_threads, &sourceuri,
			    &(trace_globals.dwconf),
			    &(trace_globals.ppconf))) {
        return 1;
    }

    set_signals();

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

    if (trace_pstart(trace, &trace_globals, proccbs, NULL)) {
        trace_perror(trace, "Starting source trace");
        result = 1;
    } else {
        trace_join(trace);

        if (trace_is_err(trace)) {
            trace_perror(trace, "Reading packets from source trace");
            result = 1;
        }
    }

    deleteWdcapDiskWriterConfig(trace_globals.dwconf);
    deleteWdcapProcessingConfig(trace_globals.ppconf);

    trace_destroy_callback_set(proccbs);
    trace_destroy(trace);

    pthread_mutex_destroy(&lock);

    return result;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
