/*
 * fuzz_piv.c: Fuzzer for piv-tool
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "libopensc/internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "fuzzer_reader.h"
#include "fuzzer_tool.h"

/* Needs header file with tool source code to test main() */
#include "pkcs11_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *argv[] = {"./fuzz_pkcs11", "-I", "--module", "libsofthsm2.so"};
	_main(4, argv);
	return 0;
}
/*
./bootstrap
# FIXME FUZZING_LIBS="$LIB_FUZZING_ENGINE" fails with some missing C++ library, I don't know how to fix this
./configure --disable-optimization --disable-shared --disable-pcsc --enable-ctapi --enable-fuzzing FUZZING_LIBS="$LIB_FUZZING_ENGINE"
make -j4

fuzzerFiles=$(find $SRC/opensc/src/tests/fuzzing/ -name "fuzz_*.c")

for F in $fuzzerFiles; do
    fuzzerName=$(basename $F .c)
    cp "$SRC/opensc/src/tests/fuzzing/$fuzzerName" $OUT
    if [ -d "$SRC/opensc/src/tests/fuzzing/corpus/${fuzzerName}" ]; then
        zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/opensc/src/tests/fuzzing/corpus/${fuzzerName}/*
    fi
done

git clone https://github.com/opendnssec/SoftHSMv2.git
mkdir "$SRC/opensc/SoftHSMv2/built"
cd "$SRC/opensc/SoftHSMv2"
ls
./autogen.sh
./configure --prefix="$SRC/opensc/SoftHSMv2/built"
make install
cp "$SRC/opensc/SoftHSMv2/built/lib/softhsm/libsofthsm2.so" "$SRC/opensc/src/tests/fuzzing/libsofthsm2.so"
cd "$SRC/opensc/src/tests/fuzzing"
./setup_softhsm.sh "$SRC/opensc/SoftHSMv2/built/bin/softhsm2-util"

cp "$SRC/opensc/src/tests/fuzzing/libsofthsm2.so" $OUT
cp "$SRC/opensc/src/tests/fuzzing/.softhsm2.conf" $OUT
cp -r "$SRC/opensc/src/tests/fuzzing/.tokens" $OUT
export SOFTHSM2_CONF=".softhsm2.conf"

*/
