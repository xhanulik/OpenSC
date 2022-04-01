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

static char* path = NULL;
#define NAME_LEN 11

int LLVMFuzzerInitialize(int* argc, char*** argv) {
  path = (*argv)[0];
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *argv[] = {"./fuzz_pkcs11", "-I", "--module", NULL, NULL};
    size_t len = strlen(path);
    char *new_path = malloc(len - NAME_LEN + 14 + 1);
    memcpy(new_path, path, len - NAME_LEN);
    memcpy(new_path + (len - NAME_LEN), "libsofthsm2.so\0", 15);
    printf("%s\n", new_path);
    argv[3] = new_path;

    optind = 0;
	_main(4, argv);
	return 0;
}
