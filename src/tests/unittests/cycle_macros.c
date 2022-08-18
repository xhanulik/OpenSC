#define SC_PKCS15_PROFILE_DIRECTORY "."
#include "torture.h"
#include "pkcs15init/profile.c"

static void torture_single_no_cycle(void **state)
{
	sc_profile_t profile = { 0 };
	scconf_list list1 = { NULL, "$b" };
	struct sc_macro mac1 = { "a", NULL, &list1 };
	profile.macro_list = &mac1;
	assert_int_equal(check_cyclic_dependency(&profile, "b"), 0);
}

static void torture_more_no_cycle(void **state)
{
	sc_profile_t profile = { 0 };
	scconf_list list1 = { NULL, "$b" };
	scconf_list list2 = { NULL, "$c" };
	struct sc_macro mac2 = { "b", NULL, &list2 };
	struct sc_macro mac1 = { "a", &mac2, &list1 };

	profile.macro_list = &mac1;
	assert_int_equal(check_cyclic_dependency(&profile, "b"), 0);
}

static void torture_two_single_cycle(void **state)
{
	sc_profile_t profile = { 0 };
	scconf_list list1 = { NULL, "$b" };
	scconf_list list2 = { NULL, "$a" };
	struct sc_macro mac2 = { "b", NULL, &list2 };
	struct sc_macro mac1 = { "a", &mac2, &list1 };

	profile.macro_list = &mac1;
	assert_int_equal(check_cyclic_dependency(&profile, "b"), 1);
}

static void torture_three_single_cycle(void **state)
{
	sc_profile_t profile = { 0 };
	scconf_list list1 = { NULL, "$b" };
	scconf_list list2 = { NULL, "$c" };
	scconf_list list3 = { NULL, "$a" };
	struct sc_macro mac3 = { "c", NULL, &list3 };
	struct sc_macro mac2 = { "b", &mac3, &list2 };
	struct sc_macro mac1 = { "a", &mac2, &list1 };

	profile.macro_list = &mac1;
	assert_int_equal(check_cyclic_dependency(&profile, "b"), 1);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_single_no_cycle),
		cmocka_unit_test(torture_more_no_cycle),
		cmocka_unit_test(torture_two_single_cycle),
		cmocka_unit_test(torture_three_single_cycle),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
