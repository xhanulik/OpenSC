/*
 * piv-tool.c: Tool for accessing smart cards with libopensc
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2010 Douglas E. Engert <deengert@gmail.com>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

/* Module only built if OPENSSL is enabled */
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>

#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/param_build.h>
# include <openssl/params.h>
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "util.h"
#include "libopensc/sc-ossl-compat.h"

static const char *app_name = "piv-tool";

static int	opt_wait = 0;
static char **	opt_apdus;
static char *	opt_reader;
static int	opt_apdu_count = 0;
static int	verbose = 0;

enum {
	OPT_SERIAL = 0x100,
};

static const struct option options[] = {
	{ "serial",		0, NULL,	OPT_SERIAL  },
	{ "name",		0, NULL,		'n' },
	{ "admin",		1, NULL, 		'A' },
	{ "genkey",		1, NULL,		'G' },
	{ "object",		1, NULL,		'O' },
	{ "cert",		1, NULL,		'C' },
	{ "compresscert",	1, NULL,		'Z' },
	{ "out",		1, NULL, 		'o' },
	{ "in",			1, NULL, 		'i' },
	{ "send-apdu",		1, NULL,		's' },
	{ "reader",		1, NULL,		'r' },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Print the card serial number",
	"Identify the card and print its name",
	"Authenticate using default 3DES key",
	"Generate key <ref>:<alg> 9A:06 on card, and output pubkey",
	"Load an object <containerID> containerID as defined in 800-73 without leading 0x",
	"Load a cert <ref> where <ref> is 9A,9C,9D or 9E",
	"Load a cert that has been gzipped <ref>",
	"Output file for cert or key",
	"Input file for cert",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Verbose operation, may be used several times",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static BIO *bp = NULL;

static int load_object(const char * object_id, const char * object_file)
{
	FILE *fp = NULL;
	sc_path_t path;
	size_t derlen;
	u8 *der = NULL;
	u8 *body;
	size_t bodylen;
	int r = -1;
	struct stat stat_buf;

	if (!object_file || (fp = fopen(object_file, "rb")) == NULL) {
		printf("Cannot open object file, %s %s\n",
				(object_file) ? object_file : "", strerror(errno));
		goto err;
	}

	if (0 != stat(object_file, &stat_buf)) {
		printf("unable to read file %s\n", object_file);
		goto err;
	}
	derlen = stat_buf.st_size;
	der = malloc(derlen);
	if (der == NULL) {
		printf("file %s is too big, %lu\n",
		object_file, (unsigned long)derlen);
		goto err;
	}
	if (1 != fread(der, derlen, 1, fp)) {
		printf("unable to read file %s\n",object_file);
		goto err;
	}
	/* check if tag and length are valid */
	body = (u8 *)sc_asn1_find_tag(card->ctx, der, derlen, 0x53, &bodylen);
	if (body == NULL || derlen != body - der + bodylen) {
		fprintf(stderr, "object tag or length not valid\n");
		goto err;
	}

	sc_format_path(object_id, &path);

	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "select file failed\n");
		r = -1;
		goto err;
	}
	/* leave 8 bits for flags, and pass in total length */
	r = sc_write_binary(card, 0, der, derlen, derlen<<8);

err:
	free(der);
	if (fp)
		fclose(fp);

	return r;
}


static int load_cert(const char * cert_id, const char * cert_file,
					int compress)
{
	X509 * cert = NULL;
	FILE *fp = NULL;
	u8 buf[1];
	size_t buflen = 1;
	sc_path_t path;
	u8 *der = NULL;
	u8 *p;
	size_t derlen;
	int r = -1;

	if (!cert_file) {
		printf("Missing cert file\n");
		goto err;
	}

	if ((fp = fopen(cert_file, "rb")) == NULL) {
		printf("Cannot open cert file, %s %s\n",
				cert_file, strerror(errno));
		goto err;
	}
	if (compress) { /* file is gzipped already */
		struct stat stat_buf;

		if (0 != stat(cert_file, &stat_buf)) {
			printf("unable to read file %s\n", cert_file);
			goto err;
		}
		derlen = stat_buf.st_size;
		der = malloc(derlen);
		if (der == NULL) {
			printf("file %s is too big, %lu\n",
				cert_file, (unsigned long)derlen);
			goto err;
		}
		if (1 != fread(der, derlen, 1, fp)) {
			printf("unable to read file %s\n", cert_file);
			goto err;
		}
	} else {
		cert = PEM_read_X509(fp, &cert, NULL, NULL);
		if (cert == NULL) {
			sc_log_openssl(ctx);
			printf("file %s does not contain PEM-encoded certificate\n", cert_file);
			goto err;
		}

		derlen = i2d_X509(cert, NULL);
		der = malloc(derlen);
		if (!der) {
			goto err;
		}
		p = der;
		i2d_X509(cert, &p);
	}
	sc_hex_to_bin(cert_id, buf,&buflen);

	switch (buf[0]) {
		case 0x9a: sc_format_path("0101",&path); break;
		case 0x9c: sc_format_path("0100",&path); break;
		case 0x9d: sc_format_path("0102",&path); break;
		case 0x9e: sc_format_path("0500",&path); break;
		default:
			fprintf(stderr,"cert must be 9A, 9C, 9D or 9E\n");
			r = 2;
			goto err;
	}

	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "select file failed\n");
		goto err;
	}
	/* we pass length  and  8 bits of flag to card-piv.c write_binary */
	/* pass in its a cert and if needs compress */
	r = sc_write_binary(card, 0, der, derlen, (derlen << 8) | (compress << 4) | 1);

err:
	free(der);
	if (fp)
		fclose(fp);

	return r;
}
static int admin_mode(const char* admin_info)
{
	int r;
	u8 opts[3];
	size_t buflen = 2;


	if (admin_info && strlen(admin_info) == 7 &&
			(admin_info[0] == 'A' || admin_info[0] == 'M') &&
			admin_info[1] == ':' &&
			(sc_hex_to_bin(admin_info+2, opts+1, &buflen) == 0) &&
			buflen == 2) {
		opts[0] = admin_info[0];
	} else {
		fprintf(stderr, " admin_mode params <M|A>:<keyref>:<alg>\n");
		return -1;
	}

	r = sc_card_ctl(card, SC_CARDCTL_PIV_AUTHENTICATE, &opts);
	if (r)
		fprintf(stderr, " admin_mode failed %d\n", r);
	return r;
}

/* generate a new key pair, and save public key in newkey */
static int gen_key(const char * key_info)
{
	int r = 1;
	u8 buf[2];
	size_t buflen = 2;
	sc_cardctl_piv_genkey_info_t
		keydata = {0, 0, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0};
	EVP_PKEY *evpkey = NULL;
#if !defined(OPENSSL_NO_EC)
	int nid = -1;
#endif

	sc_hex_to_bin(key_info, buf, &buflen);
	if (buflen != 2) {
		fprintf(stderr, "<keyref>:<algid> invalid, example: 9A:06\n");
		return 2;
	}
	switch (buf[0]) {
		case 0x9a:
		case 0x9c:
		case 0x9d:
		case 0x9e:
			keydata.key_num = buf[0];
			break;
		default:
			fprintf(stderr, "<keyref>:<algid> must be 9A, 9C, 9D or 9E\n");
			return 2;
	}

	switch (buf[1]) {
		case 0x05: keydata.key_bits = 3072; break;
		case 0x06: keydata.key_bits = 1024; break;
		case 0x07: keydata.key_bits = 2048; break;
#if !defined(OPENSSL_NO_EC)
		case 0x11: keydata.key_bits = 0;
			nid = NID_X9_62_prime256v1; /* We only support one curve per algid */
			break;
		case 0x14: keydata.key_bits = 0;
			nid = NID_secp384r1;
			break;
		case 0xE0:
			keydata.key_bits = 0;
			nid = NID_ED25519;
			break;
		case 0xE1:
			keydata.key_bits = 0;
			nid = NID_X25519;
			break;
#endif
		default:
			fprintf(stderr, "<keyref>:<algid> algid=RSA - 05, 06, 07 for 3072, 1024, 2048;EC - 11, 14 for 256, 384\n");
			return 2;
	}

	keydata.key_algid = buf[1];


	r = sc_card_ctl(card, SC_CARDCTL_PIV_GENERATE_KEY, &keydata);
	if (r) {
		fprintf(stderr, "gen_key failed %d\n", r);
		return 1;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	evpkey = EVP_PKEY_new();
	if (!evpkey) {
		sc_log_openssl(ctx);
		fprintf(stderr, "allocation of key failed\n");
		r = 1;
		goto out;
	}
#endif

	if (keydata.key_bits > 0) { /* RSA key */
		BIGNUM *newkey_n, *newkey_e;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		RSA *newkey = NULL;
#else
		EVP_PKEY_CTX *cctx = NULL;
		OSSL_PARAM_BLD *bld = NULL;
		OSSL_PARAM *params = NULL;
#endif

		if (!keydata.pubkey || !keydata.exponent) {
			fprintf(stderr, "gen_key failed %d\n", r);
			r = 1;
			goto out;
		}

		newkey_n = BN_bin2bn(keydata.pubkey, (int)keydata.pubkey_len, NULL);
		newkey_e = BN_bin2bn(keydata.exponent, (int)keydata.exponent_len, NULL);
		if (!newkey_n || !newkey_e) {
			sc_log_openssl(ctx);
			fprintf(stderr, "conversion or key params failed\n");
			r = 1;
			goto out;
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		newkey = RSA_new();
		if (!newkey) {
			sc_log_openssl(ctx);
			fprintf(stderr, "gen_key RSA_new failed\n");
			r = 1;
			goto out;
		}

		if (RSA_set0_key(newkey, newkey_n, newkey_e, NULL) != 1) {
			sc_log_openssl(ctx);
			RSA_free(newkey);
			BN_free(newkey_n);
			BN_free(newkey_e);
			fprintf(stderr, "gen_key unable to set RSA values");
			r = 1;
			goto out;
		}

		if (verbose)
			RSA_print_fp(stdout, newkey, 0);

		if (EVP_PKEY_assign_RSA(evpkey, newkey) != 1) {
			sc_log_openssl(ctx);
			RSA_free(newkey);
			BN_free(newkey_n);
			BN_free(newkey_e);
			fprintf(stderr, "gen_key unable to set RSA values");
			r = 1;
			goto out;
		}
#else
		if (!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_BN(bld, "n", newkey_n) != 1 ||
				OSSL_PARAM_BLD_push_BN(bld, "e", newkey_e) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
			sc_log_openssl(ctx);
			OSSL_PARAM_BLD_free(bld);
			BN_free(newkey_n);
			BN_free(newkey_e);
			r = 1;
			goto out;
		}

		OSSL_PARAM_BLD_free(bld);
		BN_free(newkey_n);
		BN_free(newkey_e);

		cctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		if (!cctx ||
				EVP_PKEY_fromdata_init(cctx) != 1 ||
				EVP_PKEY_fromdata(cctx, &evpkey, EVP_PKEY_KEYPAIR, params) != 1) {
			sc_log_openssl(ctx);
			EVP_PKEY_CTX_free(cctx);
			OSSL_PARAM_free(params);
			fprintf(stderr, "gen_key unable to gen RSA");
			r = 1;
			goto out;
		}
		if (verbose)
			EVP_PKEY_print_public_fp(stdout, evpkey, 0, NULL);

		EVP_PKEY_CTX_free(cctx);
		OSSL_PARAM_free(params);
#endif

#ifdef EVP_PKEY_ED25519
	} else if (nid == NID_ED25519 || nid == NID_X25519) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		fprintf(stderr, "This build of OpenSSL does not support ED25519 or X25519 keys\n");
		r = 1;
		goto out;
#else
		if (!keydata.ecpoint) {
			fprintf(stderr, "gen_key failed\n");
			r = 1;
			goto out;
		}
		evpkey = EVP_PKEY_new_raw_public_key(nid, NULL, keydata.ecpoint, keydata.ecpoint_len);
		if (!evpkey) {
			sc_log_openssl(ctx);
			fprintf(stderr, "gen key failed ti copy 25519 pubkey\n");
			r = 1;
			goto out;
		}

		if (verbose)
			EVP_PKEY_print_public_fp(stdout, evpkey, 0, NULL);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
#else
		fprintf(stderr, "This build of OpenSSL does not support ED25519 or X25519 keys\n");
		return -1;
#endif		 /* EVP_PKEY_ED25519 */
	} else { /* EC key */
#if !defined(OPENSSL_NO_EC)
		int i;
		BIGNUM *x = NULL;
		BIGNUM *y = NULL;
		EC_GROUP * ecgroup = NULL;
		EC_POINT * ecpoint = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		EC_KEY * eckey = NULL;
#else
		EVP_PKEY_CTX *cctx = NULL;
		OSSL_PARAM_BLD *bld = NULL;
		OSSL_PARAM *params = NULL;
		size_t len = 0;
		unsigned char * buf = NULL;
		const char *group_name;
#endif

		if (!keydata.ecpoint) {
			fprintf(stderr, "gen_key failed\n");
			r = 1;
			goto out;
		}

		ecgroup = EC_GROUP_new_by_curve_name(nid);
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
		ecpoint = EC_POINT_new(ecgroup);

		/* PIV returns 04||x||y  and x and y are the same size */
		i = (int)(keydata.ecpoint_len - 1) / 2;
		x = BN_bin2bn(keydata.ecpoint + 1, i, NULL);
		y = BN_bin2bn(keydata.ecpoint + 1 + i, i, NULL);
		if (!x || !y) {
			sc_log_openssl(ctx);
			BN_free(x);
			BN_free(y);
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			r = 1;
			goto out;
		}
		r = EC_POINT_set_affine_coordinates(ecgroup, ecpoint, x, y, NULL);

		BN_free(x);
		BN_free(y);

		if (r == 0) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_POINT_set_affine_coordinates_GFp failed\n");
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			r = 1;
			goto out;
		}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		eckey = EC_KEY_new();
		if (eckey == NULL) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_KEY_new failed\n");
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			r = 1;
			goto out;
		}
		r = EC_KEY_set_group(eckey, ecgroup);
		EC_GROUP_free(ecgroup);
		if (r == 0) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_KEY_set_group failed\n");
			EC_POINT_free(ecpoint);
			EC_KEY_free(eckey);
			r = 1;
			goto out;
		}
		r = EC_KEY_set_public_key(eckey, ecpoint);
		EC_POINT_free(ecpoint);
		if (r == 0) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_KEY_set_public_key failed\n");
			EC_KEY_free(eckey);
			r = 1;
			goto out;
		}

		if (verbose)
			EC_KEY_print_fp(stdout, eckey, 0);

		if (EVP_PKEY_assign_EC_KEY(evpkey, eckey) != 1) {
			EC_KEY_free(eckey);
			sc_log_openssl(ctx);
			r = 1;
			goto out;
		}
#else
		group_name = OBJ_nid2sn(nid);
		len = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
		if (!(buf = malloc(len))) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_KEY_set_public_key out of memory\n");
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			r = 1;
			goto out;
		}
		if (EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_COMPRESSED, buf, len, NULL) == 0) {
			sc_log_openssl(ctx);
			fprintf(stderr, "EC_KEY_set_public_key failed\n");
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			free(buf);
			r = 1;
			goto out;
		}

		EC_GROUP_free(ecgroup);
		EC_POINT_free(ecpoint);

		if (!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_utf8_string(bld, "group", group_name, strlen(group_name)) != 1 ||
				OSSL_PARAM_BLD_push_octet_string(bld, "pub", buf, len) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
			sc_log_openssl(ctx);
			OSSL_PARAM_BLD_free(bld);
			free(buf);
			r = 1;
			goto out;
		}
		free(buf);
		OSSL_PARAM_BLD_free(bld);

		cctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (!cctx ||
				EVP_PKEY_fromdata_init(cctx) != 1 ||
				EVP_PKEY_fromdata(cctx, &evpkey, EVP_PKEY_KEYPAIR, params) != 1) {
			sc_log_openssl(ctx);
			fprintf(stderr, "gen_key unable to gen EC key");
			EVP_PKEY_CTX_free(cctx);
			OSSL_PARAM_free(params);
			r = 1;
			goto out;
		}
		if (verbose)
			EVP_PKEY_print_public_fp(stdout, evpkey, 0, NULL);

		EVP_PKEY_CTX_free(cctx);
		OSSL_PARAM_free(params);
#endif
#else  /* OPENSSL_NO_EC */
		fprintf(stderr, "This build of OpenSSL does not support EC keys\n");
		r = 1;
#endif /* OPENSSL_NO_EC */

	}

	if (bp) {
		r = i2d_PUBKEY_bio(bp, evpkey);
		if (r != 1) {
			sc_log_openssl(ctx);
			fprintf(stderr, "Failed to encode public key");
			r = 1;
			goto out;
		}
	}
	r = SC_SUCCESS;
out:
	free(keydata.pubkey);
	free(keydata.exponent);
	free(keydata.ecpoint);

	EVP_PKEY_free(evpkey);

	return r;
}


static int send_apdu(void)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE+3];
	u8 rbuf[8192];
	size_t len0, i;
	int r;
	int c;

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);

		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
			return 2;
		}

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		printf("Sending: ");
		for (i = 0; i < len0; i++)
			printf("%02X ", buf[i]);
		printf("\n");
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
			return 1;
		}
		printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
		       apdu.resplen ? ":" : "");
		if (apdu.resplen)
			util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}
	return 0;
}

static void print_serial(sc_card_t *in_card)
{
	int r;
	sc_serial_number_t serial;

	r = sc_card_ctl(in_card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r < 0)
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GET_SERIALNR, *) failed %d\n", r);
	else
		util_hex_dump_asc(stdout, serial.value, serial.len, -1);
}

int main(int argc, char *argv[])
{
	int err = 0, r, c;
	int do_send_apdu = 0;
	int do_admin_mode = 0;
	int do_gen_key = 0;
	int do_load_cert = 0;
	int do_load_object = 0;
	int compress_cert = 0;
	int do_print_serial = 0;
	int do_print_name = 0;
	int action_count = 0;
	const char *out_file = NULL;
	const char *in_file = NULL;
	const char *cert_id = NULL;
	const char *object_id = NULL;
	const char *key_info = NULL;
	const char *admin_info = NULL;
	sc_context_param_t ctx_param;
	char **old_apdus = NULL;

	while ((c = getopt_long(argc, argv, "nA:G:O:Z:C:i:o:r:fvs:c:w", options, (int *) 0)) != -1) {
		switch (c) {
		case OPT_SERIAL:
			do_print_serial = 1;
			action_count++;
			break;
		case 's':
			old_apdus = opt_apdus;
			opt_apdus = (char **) realloc(opt_apdus,
					(opt_apdu_count + 1) * sizeof(char *));
			if (!opt_apdus) {
				free(old_apdus);
				err = 1;
				goto end;
			}
			opt_apdus[opt_apdu_count] = optarg;
			do_send_apdu++;
			if (opt_apdu_count == 0)
				action_count++;
			opt_apdu_count++;
			break;
		case 'n':
			do_print_name = 1;
			action_count++;
			break;
		case 'A':
			do_admin_mode = 1;
			admin_info = optarg;
			action_count++;
			break;
		case 'G':
			do_gen_key = 1;
			key_info = optarg;
			action_count++;
			break;
		case 'O':
			do_load_object = 1;
			object_id = optarg;
			action_count++;
			break;
		case 'Z':
			compress_cert = 1;
			/* fall through */
		case 'C':
			do_load_cert = 1;
			cert_id = optarg;
			action_count++;
			break;
		case 'i':
			in_file = optarg;
			break;
		case 'o':
			out_file = optarg;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		default:
			util_print_usage(app_name, options, option_help, NULL);
			if (opt_apdus)
				free(opt_apdus);
			return 2;
		}
	}

	if (action_count == 0) {
		util_print_usage(app_name, options, option_help, NULL);
		if (opt_apdus)
			free(opt_apdus);
		return 2;
	}

	if (out_file) {
		bp = BIO_new(BIO_s_file());
		if (!BIO_write_filename(bp, (char *)out_file))
			goto end;
	} else {
		bp = BIO_new(BIO_s_file());
		BIO_set_fp(bp,stdout,BIO_NOCLOSE);
	}

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.app_name = app_name;
	ctx_param.debug    = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	if (action_count <= 0)
		goto end;

	/* force PIV card driver */
	err = sc_set_card_driver(ctx, "PIV-II");
	if (err) {
		fprintf(stderr, "PIV card driver not found!\n");
		err = 1;
		goto end;
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait);
	if (err)
		goto end;

	/* fail if card is not a PIV card */
	if (card->type < SC_CARD_TYPE_PIV_II_BASE || card->type >= SC_CARD_TYPE_PIV_II_BASE+1000) {
		fprintf(stderr, "Card type %X: not a PIV card\n", card->type);
		err = 1;
		goto end;
	}

	if (do_admin_mode) {
		if ((err = admin_mode(admin_info)))
			goto end;
		action_count--;
	}
	if (do_send_apdu) {   /* can use pin before load cert for a beta card */
		if ((err = send_apdu()))
			goto end;
		action_count--;
	}
	if (do_gen_key) {
		if ((err = gen_key(key_info)))
			goto end;
		action_count--;
	}
	if (do_load_object) {
		if ((err = load_object(object_id, in_file)))
			goto end;
		action_count--;
	}
	if (do_load_cert) {
		if ((err = load_cert(cert_id, in_file, compress_cert)))
			goto end;
		action_count--;
	}
	if (do_print_serial) {
		if (verbose)
			printf("Card serial number:");
		print_serial(card);
		action_count--;
	}
	if (do_print_name) {
		if (verbose)
			printf("Card name: ");
		printf("%s\n", card->name);
		action_count--;
	}
end:
	if (bp)
		BIO_free(bp);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (opt_apdus)
		free(opt_apdus);
	sc_release_context(ctx);

	ERR_print_errors_fp(stderr);
	return err;
}
