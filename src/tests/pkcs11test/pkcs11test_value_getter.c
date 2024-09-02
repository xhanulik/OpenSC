#include "pkcs11test_value_getter.h"

int
get_CK_BYTE(const char *value, CK_BYTE_PTR result)
{
	unsigned long r;
    if (xmlStrcasecmp((const xmlChar *)value, (const xmlChar *)"true") == 0) {
        *result = CK_TRUE;
    } else if (xmlStrcasecmp((const xmlChar *)value, (const xmlChar *)"false") == 0) {
        result = CK_FALSE;
    } else {
		char *end = NULL;
		r = strtoul(value, &end, 16);
		if (*end != '\0' || r > 0xFF) {
			return PKCS11TEST_INVALID_ARGUMENTS;
		}
		*result = (CK_BYTE)r;
    }
	return PKCS11TEST_SUCCESS;
}

int
get_num_value(char *value, CK_ULONG_PTR result, enum ck_type type)
{
	unsigned long r;
	if (type == INT) {
		char *end = NULL;
		r = strtoul(value, &end, 10);
		if (*end != '\0') {
			return PKCS11TEST_INVALID_ARGUMENTS;
		}
		*result = (CK_ULONG)r;
		return PKCS11TEST_SUCCESS;
	} else if (type == FLG_T) {
		char *token = NULL;
		char *endptr;

		// convert hexadecimal number
		if (strstr(value, "0x") == value || strstr(value, "0X") == value) {
			*result = strtol(value, &endptr, 16);
			return PKCS11TEST_SUCCESS;
		}

		// convert decimal number
		if (isdigit(*value) != 0) {
			*result = strtol(value, &endptr, 10);
			return PKCS11TEST_SUCCESS;
		}
		
		// convert by names
		token = strtok(value, "|");
		while (token != NULL) {
			CK_ULONG current = 0;
			if ((r = lookup_string(type, (const char *) token, &current)) != PKCS11TEST_SUCCESS) {
				return r;
			}
			*result |= current;
			token = strtok(NULL, "|");
		}
		return PKCS11TEST_SUCCESS;
	} else {
		return lookup_string(type, (const char *) value, result);
	}
	return PKCS11TEST_INVALID_PARAM_NAME;
}

int
get_CK_UTF8CHAR_PTR(char *value, CK_UTF8CHAR_PTR *result, CK_ULONG_PTR length)
{
	if ((*result = calloc(*length, sizeof(CK_UTF8CHAR))) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	memcpy(*result, value, *length);
	return PKCS11TEST_SUCCESS;
}

int
get_CK_CHAR_PTR(char *value, CK_CHAR_PTR *result, CK_ULONG_PTR length)
{
	if ((*result = calloc(*length, sizeof(CK_UTF8CHAR))) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	memcpy(*result, value, *length);
	return PKCS11TEST_SUCCESS;
}

int
get_CK_BYTE_PTR(char *value, CK_BYTE_PTR *result, CK_ULONG_PTR length)
{
	CK_ULONG str_len = strlen((char *)value);
	if ((*((CK_BYTE_PTR *)result) = malloc(str_len / 2)) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	if (sc_hex_to_bin((CK_BYTE_PTR)value, *result, &str_len) != PKCS11TEST_SUCCESS) {
		free(*((CK_BYTE_PTR *)result));
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	*length = str_len / 2;
	return PKCS11TEST_SUCCESS;
}
