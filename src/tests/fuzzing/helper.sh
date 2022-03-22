#!/bin/bash
# Script for conversion of tool's source code into header file
# used for convenient fuzzing.
# * rename main
# * fixup include paths
# * supply virtual reader returning fuzzing inputs instead of connecting real card

HEADER_FILE="$1"
SOURCE_FILE=""
SOURCE_PATH=""

case $HEADER_FILE in
    piv_fuzz.h)
        SOURCE_FILE="piv-tool.c"
    ;;
    pkcs15_fuzz.h)
        SOURCE_FILE="pkcs15-tool.c"
    ;;
esac

SOURCE_PATH="../../tools/${SOURCE_FILE}"

cat $SOURCE_PATH |
sed -e 's~int main~int _main~' \
    -e 's~#include "~#include "../../~' \
    -e 's~#include "../../config~#include "config~' \
    -e 's~#include "../../util.h~#include "../../tools/util.c~' \
    -e 's~stderr~stdout~' \
    -e 's~util.c"~util.c"\n\nint fuzz_util_connect_card(sc_context_t *, sc_card_t **);~' \
    -e 's~util_connect_card(ctx, &card, opt_reader, opt_wait, verbose)~fuzz_util_connect_card(ctx, \&card)~' > $HEADER_FILE

case $HEADER_FILE in
    pkcs15_fuzz.h)
        sed -i.bak 's~util_connect_card_ex(ctx, &card, opt_reader, opt_wait, 0, verbose)~fuzz_util_connect_card(ctx, \&card)~' $HEADER_FILE
    ;;
esac

if [ -f "${HEADER_FILE}.bak" ]; then
	rm "${HEADER_FILE}.bak"
fi
