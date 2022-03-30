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
#include "piv_fuzz.h"

static const uint8_t *reader_data = NULL;
static size_t reader_data_size = 0;


/* Use instead of util_connect_card() */
int fuzz_util_connect_card(sc_context_t *ctx, sc_card_t **card)
{
	struct sc_reader *reader = NULL;

	/* Erase possible readers from ctx */
	while (list_size(&ctx->readers)) {
		sc_reader_t *rdr = (sc_reader_t *) list_get_at(&ctx->readers, 0);
		_sc_delete_reader(ctx, rdr);
	}
	if (ctx->reader_driver->ops->finish != NULL)
		ctx->reader_driver->ops->finish(ctx);

	/* Create virtual reader */
	ctx->reader_driver = sc_get_fuzz_driver();
	fuzz_add_reader(ctx, reader_data, reader_data_size);
	reader = sc_ctx_get_reader(ctx, 0);

	/* Connect card APDU reader */
	if (sc_connect_card(reader, card))
		return SC_ERROR_INTERNAL;
	
	return SC_SUCCESS;
}

void initilize_global()
{
	ctx = NULL;
	card = NULL;
	bp = NULL;
	evpkey = NULL;

	optind = 0;
	opterr = 0;
	optopt = 0;
}

void test_load(char *op, const uint8_t *data, size_t size)
{
	char *filename = NULL;
	char *argv[] = {"./fuzz_piv", op, NULL /*ref*/, "-i", NULL /*filename*/, "-A", NULL /*admin*/, NULL};
	int argc = 3;
	char *opt_ref = NULL, *opt_admin = NULL;

	if (!(opt_ref = extract_word(&data, &size)))
		return;
	argv[2] = opt_ref;

	if (!(opt_admin = extract_word(&data, &size))) {
		free(opt_ref);
		return;
	}
	argv[7] = opt_admin;

	if (create_input_file(&filename, &data, &size) != 0) {
		free(opt_ref);
		free(opt_admin);
		remove_file(filename);
		return;
	}
	argv[4] = filename;

	reader_data = data;
	reader_data_size = size;
	_main(argc, argv);

	free(opt_ref);
	free(opt_admin);
	remove_file(filename);
}

/* ./piv-tool
 * load object: -O containerID -i file -A argument
 * load certificate: -C ref -A argument -i file
 * load compressed certificate: -Z ref -i file -A argument
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t operation = 0;
	char *filename = NULL;
	char **argv = NULL;
	int argc = 0;
	char auth_path[50] = {0};

#ifdef FUZZING_ENABLED
	fclose(stdout);
#endif
	if (size < 10)
		return 0;

	initilize_global();
	operation = data[0];
	data++;
	size--;

	/* extract admin argument and set file with admin key */
	if (create_input_file(&filename, &data, &size) != 0 || size < 3)
		goto err;
	sprintf(auth_path, "PIV_EXT_AUTH_KEY=%s", filename);
	putenv(auth_path);

	switch (operation) {
		case 0:
			test_load("-O", data, size);
			break;
		case 1:
			test_load("-C", data, size);
			break;
		case 2:
			test_load("-Z", data, size);
			break;
		default:
			if (get_fuzzed_argv("./fuzz_piv", data, size, &argv, &argc, &reader_data, &reader_data_size) != 0)
				goto err;
			_main(argc, argv);
			free_arguments(argc, argv);
	}

err:
	remove_file(filename);
	return 0;
}
