MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_PROGRAMS = padding_sctest

AM_CFLAGS = -I$(top_srcdir)/src/ \
	$(OPTIONAL_OPENSSL_CFLAGS)
LDADD = $(top_builddir)/src/libopensc/libopensc.la \
	$(OPTIONAL_OPENSSL_LIBS)

padding_sctest_SOURCES = padding-sctest.c