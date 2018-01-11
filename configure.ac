AC_INIT(libwdcap, 1.0.1, contact@wand.net.nz)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR(src/WdcapPacketProcessor.cc)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CXX
AC_PROG_INSTALL

if test "$GCC" = "yes"; then
        CFLAGS="$CFLAGS -Wall -W -O2 "
fi

AC_PROG_LIBTOOL

AC_CHECK_LIB([trace], [trace_pstart],,trace_found=0)
AC_CHECK_LIB([yaml], [yaml_document_get_node],,yaml_found=0)
AC_CHECK_LIB([crypto], [EVP_EncryptInit_ex],,crypto_found=0)

AC_CONFIG_FILES([Makefile src/Makefile])

if test "$trace_found" = 0; then
        AC_MSG_ERROR(Required library libtrace4 not found; use LDFLAGS to specify library location)
fi

if test "$yaml_found" = 0; then
        AC_MSG_ERROR(Required library libyaml not found; use LDFLAGS to specify library location)
fi

if test "$crypto_found" = 0; then
        AC_MSG_ERROR(Required library libcrypto not found; use LDFLAGS to specify library location)
fi

AC_SUBST([ADD_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])


AC_OUTPUT

reportopt() {
        if test x"$2" = xtrue -o x"$2" = xyes; then
                AC_MSG_NOTICE([$1: Yes])
        else
                AC_MSG_NOTICE([$1: No])
        fi
}



