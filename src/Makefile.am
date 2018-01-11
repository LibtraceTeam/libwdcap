lib_LTLIBRARIES = libwdcap.la
include_HEADERS = WdcapPacketProcessor.h WdcapAnon.h WdcapDiskWriter.h

libwdcap_la_SOURCES = WdcapPacketProcessor.cc WdcapPacketProcessor.h \
                Anon.cc WdcapAnon.h HeaderWalk.cc HeaderWalk.h \
                WdcapDiskWriter.h WdcapDiskWriter.cc

libwdcap_la_LIBADD = @ADD_LIBS@
libwdcap_la_LDFLAGS = @ADD_LDFLAGS@
libwdcap_la_CPPFLAGS = @ADD_INCLS@
