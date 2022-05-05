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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11-opensc.h"

/* Needs header file with tool source code to test main() */
CK_FUNCTION_LIST_3_0 pkcs11_function_list_3_0;

#define main _main
#define C_LoadModule(opt_module, p11_v2) load_module(p11_v2)
# include "tools/pkcs11-tool.c"
#undef main

void *load_module(CK_FUNCTION_LIST_PTR_PTR funcs)
{
	CK_FUNCTION_LIST_PTR _p11 = NULL;
	C_GetFunctionList(&_p11);
	*funcs = _p11;
	return (void *)_p11;
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	putenv("SOFTHSM2_CONF=.softhsm2.conf");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char **argv = NULL;
	const uint8_t *ptr = data, *help_ptr = data;
	size_t ptr_size = size;
	int argc = 1;
	opt_module = "";
	optind = 0;

	/* Count arguments until double zero bytes occurs*/
	while(*ptr) {
		ptr = get_word(help_ptr, ptr_size);
		if (!ptr)
			return -1;
		argc++;
		ptr_size -= (ptr - help_ptr);
		help_ptr = ptr;
	}

	argv = malloc((argc + 1) * sizeof(char*));
	if (!argv)
		return -1;

	/* Copy arguments into argv */
	ptr = data;
	ptr_size = size;
	argv[0] = strdup(app_name);
	for (int i = 1; i < argc; i++) {
		argv[i] = extract_word(&ptr, &ptr_size);
	}
	argv[argc] = NULL;

	_main(argc, argv);
	free_arguments(argc, argv);
	return 0;
}
