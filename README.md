libwdcap -- C/C++ Library containing routines to support long-term packet trace
            capture and archival.

Version 1.0.1

Written by Shane Alcock  <shane.alcock@waikato.ac.nz>

---------------------------------------------------------------------------

Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
All rights reserved.

This code has been developed by the University of Waikato WAND
research group. For further information please see http://www.wand.net.nz/.

This software is licensed under the GNU General Public License (GPL) version
3. Please see the included file COPYING for details of this license.

---------------------------------------------------------------------------


Acknowledgements
================

Special thanks to CAIDA for helping fund the development of libwdcap.


Requirements
============

 * libtrace-4.0.0 (or more recent)
 * libyaml
 * libcrypto



Compiling and Installing
========================

  ./bootstrap.sh (if you have cloned from Github)
  ./configure
  make
  sudo make install


Introduction
============

libwdcap consists of two APIs: the PacketProcessor API and the DiskWriter API.

The PacketProcessor API provides routines that allow you to perform several
common post-capture tasks on captured packets in memory. These tasks include
anonymisation of packets, truncation of post-transport header payload and
direction tagging.

The DiskWriter API can be used to write the packets to disk as compressed trace
files. If desired, the output files can be rotated at regular intervals and
named using a naming scheme of your choosing that will ensure you can easily
identify the appropriate trace file(s) for any given time period.

Either or both of these APIs may be used in your own programs -- both are
entirely independent of each other. The API should work with both C and C++
programs.

Both APIs require the use of a YAML configuration file which you use to signal
which options you would like to have applied when the API is invoked against
a captured packet. The available configuration options for each API is
explained in the next two sections.


PacketProcessor Configuration
=============================

The configuration file provided to the PacketProcessor will determine which
operations are applied to each captured packet. Each config option that
appears in the file should be expressed as a YAML key:value pair.

For example,

anon: none
checksum: none
localmacs:
    - aa:bb:cc:dd:ee:ff
    - 00:11:22:11:22:11
payload: 4
dnspayload: 12

There are six packet processing options available:

anon: Describes which IP addresses should be anonymised in each received
      packet. Use 'none' if you do not want any anonymisation, 'both' if you
      want both addresses anonymised, 'local' if you want only the local (as
      determined by direction) address anonymised and 'external' if you only
      want the external address anonymised.
      Defaults to 'none'.

checksum: Describes how wdcap should obscure checksums in anonymised packets.
          If not obscured, it is much easier for the anonymisation to be
          reversed by a third party.
          Possible values are 'none' for leaving the checksums as they are,
          'blank' to replace all checksums with 0, 'check' to replace all
          correct checksums with 0 and all incorrect checksums with 1, and
          'update' to try and update the checksum so that it is valid for
          the new anonymised addresses.
          Defaults to 'check'.

payload: Describes how many bytes of application payload to retain for each
         packet. Defaults to full payload capture.

dnspayload: Describes how many bytes of DNS payload to retain for each packet.
            DNS packets will always be truncated to contain the larger of
            this value and 'payload' above.
            Defaults to 0.

localmacs: A list of MAC addresses that should be considered as "local" when
           determining the direction for a packet. All packets sourced from
           these MACs will be regarded as outgoing, all packets destined for
           these MACs will be regarded as incoming.

externalmacs: A list of MAC addresses that should be considered as "external"
              when determining the direction for a packet. All packets sourced
              from these MACs will be regarded as incoming, all packets
              destined for these MACs will be regarded as outgoing.

If both 'localmacs' and 'externalmacs' are not present in the configuration
file, no direction tagging will be performed. Note that some capture formats,
most notably pcap, do not support direction tagging so providing local or
external MAC addresses will have no useful effect.


DiskWriter Configuration
========================

The configuration file provided to the DiskWriter will determine how the
resulting trace files are named and rotated. Each config option that
appears in the file should be expressed as a YAML key:value pair.

For example,

format: erf
namingscheme: "/trace/%Y%m%d-%H%M%S-%J.%P"
compressmethod: gzip
compresslevel: 1
rotationperiod: hour
rotationfreq: 4


The options supported by the DiskWriter and their meaning is given below:

format: The trace file format to use. Can be any output file format supported by
        libtrace, but I recommend 'erf' if you have no preference.

namingscheme: Describes the directory where output files should be written
              and how the file names should be formatted. The output file name
              format should be specified as a string containing strftime
              conversion specification characters that will be substituted with
              appropriate values when the file is created. All strftime
              conversions are supported - date and time conversions will be
              replaced with the appropriate value based on the first packet in
              the new trace file.

              We have also added some wdcap-specific conversions:
              %J      The code which describes the event that resulted in this
                      new trace file to be created.
              %P      The output format ("pcapfile" is replaced by "pcap")
              %i      The ID string associated with the DiskWriter that
                      created this trace file.

              Codes are as follows:
              0       rotation boundary was reached
              2       packets were lost by the capture process
              4       first trace produced by this DiskWriter

compressmethod: Describes how the output files should be compressed. Supported
                values are "gzip", "bzip", "lzo", "xz" and "none.
                Defaults to "gzip".

compresslevel: Describes the compression level to use when compressing the
               output files. Higher levels use more CPU but can achieve better
               compression ratios.
               Defaults to 1.

rotationperiod: Describes the base period to use when calculating how often to
                close the current output file and start a new one. Can be 'day'
                for a daily rotation period or 'hour' for an hourly rotation
                period.
                Defaults to 'hour'.

rotationfreq: Describes how often to rotate the output file within the rotation
              period. For example, if the rotation period is 'hour' and the
              rotation frequency is 4, the output file will be rotated every
              15 minutes (60 minutes / 4 rotations).

maxfiles: If not zero, the disk output module will cease writing files to disk
          once it has completed writing this number of files. Only rotations
          caused by reaching the rotation boundary count towards this limit.
          Defaults to 0.

filter: Only write packets to disk that match this BPF filter.

strip: If set to 'yes', VLAN, MPLS and other layer 2.5 headers will be
       automatically removed from each captured packet. Note that this will
       have an impact on performance.
       Defaults to 'no'.



PacketProcessor API
=============================

Use of the PacketProcessor API is generally very straightforward. There are
only five API functions and they are typically invoked in the same order, e.g.
the following pseudocode:

   #include <WdcapPacketProcessor.h>

   conf = parseWdcapProcessingConfig(configfilename);
   proc = createWdcapPacketProcessor(conf);

   while (there are packets) {
        newlen = processWdcapPacket(proc, packet);
        if (newlen == 65535) {
                ERROR; break;
        }
        // do something with the modified packet
   }

   deleteWdcapPacketProcessor(proc);
   deleteWdcapProcessingConfig(conf);



More specifics on the API functions themselves:

parseWdcapProcessingConfig:
  - takes a string containing the configuration filename as an argument.
  - parses the given config file and returns a freshly created
    WdcapProcessingConfig instance based on the contents of that file.
  - if parsing fails, returns NULL and prints an error message to stderr.


createWdcapPacketProcessor:
  - takes a WdcapProcessingConfig instance as an argument.
  - creates a new instance of a WdcapPacketProcessor and returns it.


processWdcapPacket:
  - takes 2 arguments: a WdcapPacketProcessor instance and a libtrace packet
    instance.
  - Modifies the packet according to the configuration associated with the
    provided WdcapPacketProcessor, i.e. truncates, tags and anonymises.
  - Returns the new length of the packet after modification. Will return
    65535 (0xffff) if the packet is invalid in some way and could not be
    processed.

deleteWdcapPacketProcessor:
  - takes a WdcapPacketProcessor as an argument.
  - frees all allocated memory associated with the given WdcapPacketProcessor.

deleteWdcapProcessingConfig:
  - takes a WdcapProcessingConfig as an argument.
  - frees all allocated memory associated with the given WdcapProcessingConfig.


DiskWriter API
========================

The DiskWriter API is structured similarly to the PacketProcessor one which
is described above. There are six API functions for the DiskWriter, which
are typically invoked in the order and manner described as pseudocode below:

  #include <WdcapDiskWriter.h>

  conf = parseWdcapDiskWriterConfig(configfilename);
  writer = createWdcapDiskWriter(conf);

  while (there are packets) {
     ret = writeWdcapPacketToDisk(writer);
     if (ret == -1) {
         // Error occurred
         fprintf(stderr, "%s\n", getWdcapDiskWriterErrorMessage(writer));
         break;
     }
     if (ret == 0) {
        // No more output files to write, stop
        break;
     }
  }

  deleteWdcapDiskWriter(writer);
  deleteWdcapDiskWriterConfig(conf);


NOTE: the DiskWriter API expects packets to be received in chronological
order! Behaviour when packets are out-of-order is undefined.

More specifics on the API functions themselves:

parseWdcapDiskWriterConfig:
  - takes a string containing the configuration filename as an argument.
  - parses the given config file and returns a freshly created
    WdcapDiskWriterConfig instance based on the contents of that file.
  - if parsing fails, returns NULL and prints an error message to stderr.


createWdcapDiskWriter:
  - takes a WdcapDiskWriterConfig instance as an argument.
  - creates a new instance of a WdcapDiskWriter and returns it.


writeWdcapPacketToDisk:
  - takes 2 arguments: a WdcapPacketProcessor instance and a libtrace packet
    instance.
  - writes the provided packet to a trace file on disk. If the DiskWriter
    currently has a file open and the timestamp of the packet is within the
    time range associated with that file, then the packet will be appended
    to that file. Otherwise, the open file is closed and a new file is
    created for the packet to be written into.

getWdcapDiskWriterErrorMessage:
  - takes a WdcapDiskWriter as an argument.
  - returns a string describing the cause of the most recent error when
    attempting to write packets to disk (e.g. failure to open file or
    invalid packet). The error status is cleared upon calling this function.

deleteWdcapDiskWriter:
  - takes a WdcapDiskWriter as an argument.
  - frees all allocated memory associated with the given WdcapDiskWriter.

deleteWdcapDiskWriterConfig:
  - takes a WdcapDiskWriterConfig as an argument.
  - frees all allocated memory associated with the given WdcapDiskWriterConfig.

