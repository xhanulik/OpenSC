#include "torture.h"
#include "libopensc/log.c"
#include "libopensc/padding.c"
#include "common/compat_strlcpy.c"
#include <cmocka.h>

static void torture_long_output_buffer(void **state)
{
	int n = 14;
	int in_len = 14;
	unsigned char in[] = {0x00, 0x02,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x00,
                        'm', 's', 'g'};
	int out_len = 3;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	unsigned char result_msg[] = {'m', 's', 'g'};
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, 3);
	assert_memory_equal(out, result_msg, r);
	free(out);
}

static void torture_short_output_buffer(void **state)
{
	int n = 14;
	int in_len = 14;
	unsigned char in[] = {0x00, 0x02,
								0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x00,
                        'm', 's', 'g'};
	int out_len = 1;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_short_message_correct_padding(void **state)
{
	int n = 14;
	int in_len = 14;
	unsigned char in[] = {0x00, 0x02,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x00,
                        'm', 's', 'g'};
	int out_len = 3;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	unsigned char result_msg[] = {'m', 's', 'g'};
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, 3);
	assert_memory_equal(out, result_msg, r);
	free(out);
}

static void torture_missing_first_zero(void **state)
{
	int n = 13;
	int in_len = 13;
	unsigned char in[] = {0x02,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						0x00,
						'm', 's', 'g'};
	int out_len = 10;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_missing_two(void **state)
{
	int n = 13;
	int in_len = 13;
	unsigned char in[] = {0x00,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						0x00,
						'm', 's', 'g'};
	int out_len = 10;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_short_padding(void **state)
{
	int n = 13;
	int in_len = 13;
	unsigned char in[] = {0x00, 0x02,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x00,
						'm', 's', 'g'};
	int out_len = 10;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_missing_second_zero(void **state)
{
	int n = 13;
	int in_len = 13;
	unsigned char in[] = {0x00, 0x02,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						'm', 's', 'g'};
	int out_len = 10;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_missing_message(void **state)
{
	int n = 20;
	int in_len = 11;
	unsigned char in[] = {0x00, 0x02,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						0x00};
	int out_len = 11;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, SC_ERROR_INTERNAL);
	free(out);
}

static void torture_one_byte_message(void **state)
{
	int n = 12;
	int in_len = 12;
	unsigned char in[] = {0x00, 0x02,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						0x00,
						'm'};
	int out_len = 1;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
    unsigned char result_msg[] = {'m'};
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, 1);
    assert_memory_equal(out, result_msg, r);
	free(out);
}

static void torture_longer_padding(void **state)
{
	int n = 26;
	int in_len = 26;
	unsigned char in[] = {0x00, 0x02,
                            0x0e, 0x38, 0x97, 0x18, 0x16, 0x57, 0x9e, 0x30, 0xb6, 0xa5, 0x78, 0x13, 0x20, 0xca, 0x11,
                        0x00, 
	                    0x9d, 0x98, 0x3d, 0xca, 0xa9, 0xa7, 0x11, 0x0a};
	int out_len = 8;
	unsigned char *out = malloc(out_len * sizeof(unsigned char));
    unsigned char result_msg[] = {0x9d, 0x98, 0x3d, 0xca, 0xa9, 0xa7, 0x11, 0x0a};
	int r = sc_pkcs1_strip_02_padding_constant_time(NULL, n, in, in_len, out, &out_len);
	assert_int_equal(r, 8);
    assert_memory_equal(out, result_msg, r);
	free(out);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_long_output_buffer),
		cmocka_unit_test(torture_short_output_buffer),
		cmocka_unit_test(torture_short_message_correct_padding),
		cmocka_unit_test(torture_missing_first_zero),
		cmocka_unit_test(torture_missing_two),
		cmocka_unit_test(torture_short_padding),
		cmocka_unit_test(torture_missing_second_zero),
		cmocka_unit_test(torture_missing_message),
		cmocka_unit_test(torture_one_byte_message),
		cmocka_unit_test(torture_longer_padding)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
