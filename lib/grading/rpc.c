#include <stdarg.h>
#include <stdio.h>

#include <aos/aos.h>
#include <aos/sys_debug.h>
#include <grading.h>

static void finalize_tests(void);

static uintptr_t number_goldens[] = { 75, 80, RPC_TEST_END_MAGIC };
static size_t number_rpc_counter = 0;
static bool number_passed = true;

static char *string_goldens[] = STRING_GOLDENS;
static size_t string_rpc_counter = 0;
static bool string_passed = true;

void grading_rpc_handle_number(uintptr_t val)
{
    size_t exp_rpc_calls = sizeof(number_goldens) / sizeof(uintptr_t);
    if (number_rpc_counter >= exp_rpc_calls) {
        DEBUG_PRINTF("handle_number test failed: too many requests, got %lu, exp: %lu\n",
                     number_rpc_counter, exp_rpc_calls);
        number_passed = false;
        return;
    }

    if (number_goldens[number_rpc_counter] != val) {
        DEBUG_PRINTF("handle_number test failed: got: %lu exp: %lu\n", val,
                     number_goldens[number_rpc_counter]);
        number_passed = false;
    }

    number_rpc_counter++;

    if (val == RPC_TEST_END_MAGIC) {
        finalize_tests();
    }
}

void grading_rpc_handler_string(const char *string)
{
    size_t golends_len = sizeof(string_goldens) / sizeof(char *);
    if (string_rpc_counter >= golends_len) {
        DEBUG_PRINTF("handle_string test failed: too many requests, got %lu, exp: %lu\n",
                     string_rpc_counter, golends_len);
        string_passed = false;
        return;
    }

    if (strcmp(string, string_goldens[string_rpc_counter]) != 0) {
        DEBUG_PRINTF("handle_string test failed: got: %s exp: %s", string,
                     string_goldens[string_rpc_counter]);
        string_passed = false;
    }

    string_rpc_counter++;
}

void grading_rpc_handler_serial_getchar(void) { }

void grading_rpc_handler_serial_putchar(char c) { }

void grading_rpc_handler_ram_cap(size_t bytes, size_t alignment) { }

void grading_rpc_handler_process_spawn(char *cmdline, coreid_t core) { }

void grading_rpc_handler_process_get_name(domainid_t pid) { }

void grading_rpc_handler_process_get_all_pids(void) { }

static void finalize_tests(void)
{
    if (number_passed) {
        DEBUG_PRINTF("RPC (init): Number test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (init): Number test failed.\n");
    }

    if (string_passed) {
        DEBUG_PRINTF("RPC (init): String test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (init): String test failed.\n");
    }
}
