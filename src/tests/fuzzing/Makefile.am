AM_CPPFLAGS = -I$(top_srcdir)/src -D'SC_PKCS15_PROFILE_DIRECTORY="$(pkgdatadir)"'
AM_CFLAGS = -g -O0 $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
LIBS = $(FUZZING_LIBS)\
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/pkcs15init/libpkcs15init.la \
	$(top_builddir)/src/common/libcompat.la

noinst_PROGRAMS = fuzz_asn1_print fuzz_asn1_sig_value fuzz_pkcs15_decode fuzz_pkcs15_reader \
					fuzz_scconf_parse_string fuzz_pkcs15init
if ENABLE_OPENSSL
noinst_PROGRAMS += fuzz_piv
endif

noinst_HEADERS = fuzzer_reader.h fuzzer_tool.h \
				  piv_fuzz.h
BUILT_SOURCES = piv_fuzz.h

ADDITIONAL_SRC =
if !ENABLE_FUZZING
ADDITIONAL_SRC += fuzzer.c
endif

fuzz_asn1_print_SOURCES = fuzz_asn1_print.c $(ADDITIONAL_SRC)
fuzz_asn1_sig_value_SOURCES = fuzz_asn1_sig_value.c $(ADDITIONAL_SRC)
fuzz_pkcs15_decode_SOURCES = fuzz_pkcs15_decode.c $(ADDITIONAL_SRC)
fuzz_pkcs15_reader_SOURCES = fuzz_pkcs15_reader.c fuzzer_reader.c $(ADDITIONAL_SRC)
fuzz_scconf_parse_string_SOURCES = fuzz_scconf_parse_string.c $(ADDITIONAL_SRC)
fuzz_pkcs15init_SOURCES = fuzz_pkcs15init.c fuzzer_reader.c $(ADDITIONAL_SRC)
fuzz_pkcs15init_LDADD = $(OPTIONAL_OPENSSL_LIBS) $(OPENPACE_LIBS)
fuzz_pkcs15init_LDFLAGS = -static

fuzz_piv_SOURCES = fuzz_piv.c fuzzer_reader.c fuzzer_tool.c $(ADDITIONAL_SRC)
fuzz_piv_LDADD = $(OPTIONAL_OPENSSL_LIBS) $(OPENPACE_LIBS)

%_fuzz.h: $(srcdir)/../../tools/%-tool.c
	$(AM_V_GEN) ./helper.sh $@

CLEANFILES = piv_fuzz.h
