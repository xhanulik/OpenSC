/*
 * fuzz_pkcs15init.c: Fuzzer for functions processing pkcs15 init
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

#include "pkcs15init/pkcs15-lib.c"
#include "scconf/scconf.h"
#include "pkcs15init/pkcs15-init.h"
#include "pkcs15init/profile.c"
#include "pkcs15init/profile.h"

#include "fuzzer_reader.h"
#include "fuzzer_tool.h"

int fuzz_profile_load(struct sc_profile *profile, const uint8_t *data, size_t size)
{
	int rv = 0;
	scconf_context	*conf = NULL;
	conf = scconf_new(NULL);
	if (!conf)
		return 0;

	if ((rv = scconf_parse_string(conf, (char *)data)) < 0) {
		scconf_free(conf);
		return rv;
	}

	rv = process_conf(profile, conf);
	scconf_free(conf);
	return rv;
}

void fuzz_pkcs15init_bind(struct sc_card *card, struct sc_profile **result,
						  const uint8_t *data, size_t size)
{
	struct sc_profile *profile = NULL;
	const char		  *driver;
	struct sc_pkcs15init_operations * (* func)(void) = NULL;
	int r = 0;

	if (!card || !card->driver || !result)
		return;

	*result = NULL;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0 && r != SC_ERROR_NOT_SUPPORTED) {
		return;
	}

	profile = sc_profile_new();
	if (!profile)
		return;
	profile->card = card;
	driver = card->driver->short_name;

	for (int i = 0; profile_operations[i].name; i++) {
		if (!strcasecmp(driver, profile_operations[i].name)) {
			func = (struct sc_pkcs15init_operations *(*)(void)) profile_operations[i].func;
			break;
		}
	}
	if (func) {
		profile->ops = func();
	} else {
		sc_profile_free(profile);
		return;
	}
	profile->name = strdup("Fuzz profile");

	r = sc_pkcs15init_read_info(card, profile);
	if (r < 0) {
		sc_profile_free(profile);
		return;
	}

	if (fuzz_profile_load(profile, data, size) < 0) {
		sc_profile_free(profile);
		return;
	}

	if (sc_profile_finish(profile, NULL) < 0) {
		sc_profile_free(profile);
		return;
	}
	*result = profile;
}

int fuzz_initialize(struct sc_card **card, struct sc_profile **profile, sc_context_t **ctx,
					const uint8_t **data, size_t *size)
{
	const uint8_t *profile_data = *data;
	size_t profile_data_size = 0;

	/* Establish context for fuzz app*/
	sc_establish_context(ctx, "fuzz");
	if (!(*ctx))
		return SC_ERROR_INTERNAL;

	if ((profile_data_size = get_buffer(&profile_data, *size, data, size, 4000)) == 0) {
		sc_release_context(*ctx);
		*ctx = NULL;
		return SC_ERROR_INTERNAL;
	}

	if (fuzz_connect_card(*ctx, card, NULL, *data, *size) != SC_SUCCESS){
		sc_release_context(*ctx);
		*ctx = NULL;
		return SC_ERROR_INTERNAL;
	}

	/* Load profile and bind with card */
	fuzz_pkcs15init_bind(*card, profile, profile_data, profile_data_size);
	if (!(*profile)) {
		sc_disconnect_card(*card);
		sc_release_context(*ctx);
		*ctx = NULL;
		*card = NULL;
		return SC_ERROR_INTERNAL;
	}
	return SC_SUCCESS;
}

void fuzz_release(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
				  sc_card_t *card, sc_context_t *ctx)
{
	struct sc_pkcs15_card *tmp_p15_data = NULL;

	if (profile) {
		tmp_p15_data = profile->p15_data;
		sc_pkcs15init_unbind(profile);
		if (tmp_p15_data != p15card)
			sc_pkcs15_unbind(tmp_p15_data);
		profile = NULL;
	}
	if (p15card) {
		sc_pkcs15_unbind(p15card);
		p15card = NULL;
	}
	if (card){
		sc_disconnect_card(card);
		card = NULL;	
	}
	if (ctx) {
		sc_release_context(ctx);
		ctx = NULL;
	}
}

int fuzz_bind_card(const uint8_t *data, size_t size, sc_context_t **ctx,
				   struct sc_profile **profile, struct sc_pkcs15_card **p15card, sc_card_t **card)
{
	if (fuzz_initialize(card, profile, ctx, &data, &size) != SC_SUCCESS)
		return SC_ERROR_INTERNAL;

	if (sc_pkcs15_bind(*card, NULL, p15card) != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	sc_pkcs15init_set_p15card(*profile, *p15card);

	return SC_SUCCESS;
}

void do_init_app(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	unsigned char *so_pin = NULL;
	unsigned char *so_puk = NULL;
	struct sc_pkcs15init_initargs init_args;
	sc_pkcs15_auth_info_t info;
	int so_puk_disabled = 0;

	if (!(so_pin = (unsigned char *) extract_word(&data, &size)))
		return;
	if (!(so_puk = (unsigned char *) extract_word(&data, &size)))
		goto end;

	if (fuzz_initialize(&card, &profile, &ctx, &data, &size) != SC_SUCCESS)
		goto end;

	memset(&init_args, 0, sizeof(init_args));

	sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &info);
	if ((info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED) &&
		(info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
		so_puk_disabled = 1;

	init_args.so_pin = so_pin;
	init_args.so_pin_len = sizeof(so_pin);

	if (!so_puk_disabled) {
		init_args.so_puk = so_puk;
		init_args.so_puk_len = sizeof(so_puk);
	}

	sc_pkcs15init_add_app(card, profile, &init_args);
end:
	free(so_pin);
	free(so_puk);
	fuzz_release(profile, p15card, card, ctx);
}

void do_store_pin(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	unsigned char *pin = NULL;
	unsigned char *puk = NULL;
	struct sc_pkcs15init_pinargs args;
	char *pin_id = NULL, *puk_id = NULL;

	if (!(pin = (unsigned char *) extract_word(&data, &size)))
		return;
	args.pin = pin;
	args.pin_len = sizeof(pin);
	if (!(pin_id = extract_word(&data, &size)))
		goto end;

	if (!(puk = (unsigned char *) extract_word(&data, &size)))
		goto end;
	args.puk = puk;
	args.puk_len = sizeof(puk);
	if (!(puk_id = extract_word(&data, &size)))
		goto end;

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	sc_pkcs15_format_id(pin_id, &args.auth_id);
	sc_pkcs15_format_id(puk_id, &args.puk_id);
	sc_pkcs15init_store_pin(p15card, profile, &args);
end:
	free(pin);
	free(puk);
	free(pin_id);
    free(puk_id);
	fuzz_release(profile, p15card, card, ctx);
}

void do_store_data_object(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	struct sc_pkcs15init_dataargs args;
	char *object_id;
	const uint8_t *ptr = NULL;
	u8 *object_data = NULL;
	size_t object_data_size = 0;

	if(!(object_id = extract_word(&data, &size)))
		return;

	ptr = data;
	if ((object_data_size = get_buffer(&ptr, size, &data, &size, 1024)) == 0)
		goto end;
	if (!(object_data = malloc(object_data_size)))
		goto end;
	memcpy(object_data, ptr, object_data_size);

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	memset(&args, 0, sizeof(args));
	sc_format_oid(&args.app_oid, object_id);
	sc_init_oid(&args.app_oid);

	args.der_encoded.value = object_data;
	args.der_encoded.len = object_data_size; 
	sc_pkcs15init_store_data_object(p15card, profile, &args, NULL);

end:
	free(object_id);
	free(object_data);
	fuzz_release(profile, p15card, card, ctx);
}

void do_generate_key(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	struct sc_pkcs15init_keygen_args args;
	char *key_id = NULL, *auth_id = NULL;
	unsigned int keybits = 0;
    int algorithm = 0;

	if (!(key_id = extract_word(&data, &size)))
		return;
	if (!(auth_id = extract_word(&data, &size)))
		goto end;

	memset(&args, 0, sizeof(args));
	sc_pkcs15_format_id(key_id, &(args.prkey_args.id));
	sc_pkcs15_format_id(auth_id, &(args.prkey_args.auth_id));
	if (size < sizeof(unsigned int) + 3)
		goto end;
	args.prkey_args.access_flags = *data;
	data++; size--;
	keybits = *((unsigned int *) data);
	data += sizeof(unsigned int); size -= sizeof(unsigned int);
	args.prkey_args.key.algorithm = algorithm = *data;
	data++; size--;

	if (algorithm == SC_ALGORITHM_EC) {
		if (!(args.prkey_args.key.u.ec.params.named_curve = extract_word(&data, &size)))
			goto end;
	}

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;
		
	sc_pkcs15init_generate_key(p15card, profile, &args, keybits, NULL);
end:
	if (algorithm == SC_ALGORITHM_EC)
		free(args.prkey_args.key.u.ec.params.named_curve);
	free(key_id);
	free(auth_id);
	fuzz_release(profile, p15card, card, ctx);
}

void do_generate_skey(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	struct sc_pkcs15init_skeyargs args;

	if (size < 10)
		return;

	memset(&args, 0, sizeof(args));
	args.algorithm = data[0];
	args.value_len = data[1];
	args.usage = data[2];
	args.user_consent = data[3];
	data += 4;
	size -= 4;

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	sc_pkcs15init_generate_secret_key(p15card, profile, &args, NULL);
end:
	fuzz_release(profile, p15card, card, ctx);
}

void do_store_secret_key(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	struct sc_pkcs15init_skeyargs args;
	const uint8_t *ptr = NULL;

	if (size < 10)
		return;

	memset(&args, 0, sizeof(args));
	args.algorithm = data[0];
	args.value_len = data[1];
	args.usage = data[2];
	data += 3;
	size -= 3;

	ptr = data;
	if ((args.key.data_len = get_buffer(&ptr, size, &data, &size, 1024)) == 0)
		return;
	if (!(args.key.data = malloc(args.key.data_len)))
		return;
	memcpy(args.key.data, ptr, args.key.data_len);

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	sc_pkcs15init_store_secret_key(p15card, profile, &args, NULL);
end:
	free(args.key.data);
	fuzz_release(profile, p15card, card, ctx);
}

void do_store_certificate(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	struct sc_pkcs15init_certargs args;
	const uint8_t *ptr = data;

	if ((args.der_encoded.len = get_buffer(&ptr, size, &data, &size, 2048)) == 0)
		return;
	if (!(args.der_encoded.value = malloc(args.der_encoded.len)))
		return;
	memcpy(args.der_encoded.value, ptr, args.der_encoded.len);

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	sc_pkcs15init_store_certificate(p15card, profile, &args, NULL);

end:
	free(args.der_encoded.value);
	fuzz_release(profile, p15card, card, ctx);
}

void do_update_certificate(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;
	char *obj_id = NULL;
	sc_pkcs15_id_t id;
	sc_pkcs15_object_t *obj = NULL;
	sc_pkcs15_der_t cert_data = {0};
	const uint8_t *ptr = NULL;

	if (!(obj_id = extract_word(&data, &size)))
		return;

	if ((cert_data.len = get_buffer(&ptr, size, &data, &size, 2048)) == 0)
		goto end;
	if (!(cert_data.value = malloc(cert_data.len)))
		return;
	memcpy(cert_data.value, ptr, cert_data.len);

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		goto end;

	sc_pkcs15_format_id(obj_id, &id);
	if (sc_pkcs15_find_cert_by_id(p15card, &id, &obj) != 0)
		goto end;
	sc_pkcs15init_update_certificate(p15card, profile, obj, cert_data.value, cert_data.len);

end:
	free(cert_data.value);
	free(obj_id);
	fuzz_release(profile, p15card, card, ctx);
}

void do_erase(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_pkcs15_card *tmp_p15card = NULL;
	sc_card_t *card = NULL;

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
		return;

	tmp_p15card = sc_pkcs15_card_new();
	tmp_p15card->card = card;

	sc_pkcs15init_erase_card(p15card, profile, NULL);
	sc_pkcs15_card_free(p15card);
	fuzz_release(profile, p15card, card, ctx);
}

void do_sanity_check(const uint8_t *data, size_t size)
{
	sc_context_t *ctx = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	sc_card_t *card = NULL;

	if (fuzz_bind_card(data, size, &ctx, &profile, &p15card, &card) != SC_SUCCESS)
	    return;
    sc_pkcs15init_sanity_check(p15card, profile);
    fuzz_release(profile, p15card, card, ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t operation = 0;
	void (*func_ptr[])(const uint8_t*, size_t) = {
		do_init_app,
		do_store_pin,
		do_store_data_object,
		do_generate_key,
		do_generate_skey,
		do_store_secret_key,
        do_store_certificate,
        do_update_certificate,
		do_erase
	};

	if (size < 10)
		return 0;

	operation = *data % 7;
	data++;
	size--;

	func_ptr[operation](data, size);

	return 0;
}
