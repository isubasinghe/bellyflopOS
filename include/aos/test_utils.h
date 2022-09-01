// Type your code here, or load an example.
#include <stdio.h>
#ifndef __TEST_UTILS_H
#    define __TEST_UTILS_H

#    define RED "\x1b[31m"
#    define GREEN "\x1b[32m"

typedef bool (*test_func_t)(void);

typedef struct func_ptr_s {
    test_func_t cb; /* function callback */
} func_ptr_t;

#    define ADD_FUNC(group, func_cb)                                                     \
        static func_ptr_t ptr_##func_cb __attribute((used, section(#group))) = {         \
            .cb = func_cb,                                                               \
        }

#    define RUN_TESTS(group)                                                             \
        do {                                                                             \
            DEBUG_PRINTF("RUNNING %s TESTS\n", #group);                                   \
            int succeeded = 0;                                                           \
            int total = 0;                                                               \
            for (func_ptr_t *elem = ({                                                   \
                     extern func_ptr_t __start_##group;                                  \
                     &__start_##group;                                                   \
                 });                                                                     \
                 elem != ({                                                              \
                     extern func_ptr_t __stop_##group;                                   \
                     &__stop_##group;                                                    \
                 });                                                                     \
                 ++elem) {                                                               \
                succeeded += elem->cb();                                                 \
                total++;                                                                 \
            }                                                                            \
            if (succeeded == total) {                                                    \
                DEBUG_PRINTF(GREEN "All %d/%d tests in %s succeeded.\n" COLOR_RESET, succeeded,      \
                             total, #group);                                             \
            } else {                                                                     \
                DEBUG_PRINTF(RED "%d/%d tests in %s failed.\n" COLOR_RESET, total - succeeded,       \
                             total, #group);                                             \
            }                                                                            \
        } while (0)


#    define CREATE_TEST(name, group, code_block)                                         \
        __attribute__((unused)) static bool test_##name##group(void)                     \
        {                                                                                \
            __unused const char *test_name = #name;                                               \
            __unused const char *group_name = #group;                                             \
            __unused  bool __any_check_failed = false;                                             \
            {                                                                            \
                code_block                                                               \
            }                                                                            \
            if (__any_check_failed) {                                                    \
                goto __error;                                                            \
            }                                                                            \
            return true;                                                                 \
        __error:                                                                         \
            __attribute__((cold, unused));                                               \
            DEBUG_PRINTF(RED "Test %s in %s failed.\n" COLOR_RESET, test_name, group_name);          \
            return false;                                                                \
        }                                                                                \
        ADD_FUNC(group, test_##name##group);


#    define TEST_REQUIRE_FAIL_WITH(was, want)                                            \
        do {                                                                             \
            errval_t __was = was;                                                        \
            errval_t __want = want;                                                      \
            if (__was != __want) {                                                       \
                DEBUG_PRINTF(RED "%s:%d: %s \n" COLOR_RESET, __FILE__, __LINE__, __func__);          \
                DEBUG_ERR(__was, "WAS:\n");                                              \
                DEBUG_ERR(__want, "WANT\n");                                             \
                goto __error;                                                            \
            }                                                                            \
        } while (0)

#    define TEST_REQUIRE_OK(err)                                                          \
        do {                                                                              \
            errval_t __err = err;                                                         \
            if (err_is_fail(__err)) {                                                     \
                DEBUG_ERR(__err, RED "%s:%d: %s failed\n" COLOR_RESET, __FILE__, __LINE__, __func__); \
                goto __error;                                                             \
            }                                                                             \
        } while (0)

#    define TEST_REQUIRE(test)                                                           \
        do {                                                                             \
            bool __result = test;                                                        \
            if (!__result) {                                                             \
                DEBUG_PRINTF(RED "%s:%d: %s failed\n" COLOR_RESET, __FILE__, __LINE__, #test);       \
                goto __error;                                                            \
            }                                                                            \
        } while (0)

#    define TEST_CHECK(test)                                                             \
        do {                                                                             \
            bool __result = test;                                                        \
            if (!__result) {                                                             \
                __any_check_failed = true;                                               \
                DEBUG_PRINTF(RED "%s:%d: %s failed\n" COLOR_RESET, __FILE__, __LINE__, #test);       \
            }                                                                            \
        } while (0)

#    define TEST_EXIT_EARLY() return true


#endif  // __TEST_UTILS_H
