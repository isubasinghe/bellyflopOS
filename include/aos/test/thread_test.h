#ifndef THREAD_TESTS_H
#define THREAD_TESTS_H

#include <mm/mm.h>
#include <aos/test_utils.h>
#include <aos/units.h>

#define PAGING_THREADS_NUM 10

static int thread_adder(void *counter_arg)
{
    volatile int *counter = (volatile int *)counter_arg;
    __atomic_add_fetch(counter, 1, __ATOMIC_SEQ_CST);
    return 0;
}

CREATE_TEST(run_many, thread_tests, {
    volatile int counter = 0;
    size_t num_threads = 10;
    struct thread **thread_hnds = malloc(sizeof(struct thread *) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        struct thread *thread_hnd = thread_create(thread_adder, (void *)&counter);
        TEST_REQUIRE(thread_hnd);
        thread_hnds[i] = thread_hnd;
    }

    for (int i = 0; i < num_threads; i++) {
        int retval = 0;
        errval_t err = thread_join(thread_hnds[i], &retval);
        TEST_REQUIRE_OK(err);
    }

    TEST_REQUIRE(counter == num_threads);

    free(thread_hnds);
});

static int synced_paging(void *counter_arg)
{
    volatile int *counter = (volatile int *)counter_arg;
    __atomic_add_fetch(counter, 1, __ATOMIC_SEQ_CST);

    volatile char *buf = malloc(1 * MB);

    // Poor man's barrier.
    while (*counter != PAGING_THREADS_NUM) {
        thread_yield();
    }

    for (size_t i = 0; i < 1 * MB; i += BASE_PAGE_SIZE) {
        buf[i] = 'a';
    }

    return 0;
};

CREATE_TEST(thread_safe_paging, thread_tests, {
    volatile int counter = 0;
    size_t num_threads = PAGING_THREADS_NUM;
    struct thread **thread_hnds = malloc(sizeof(struct thread *) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        struct thread *thread_hnd = thread_create(synced_paging, (void *)&counter);
        thread_hnds[i] = thread_hnd;
    }

    for (int i = 0; i < num_threads; i++) {
        int retval = 1;
        errval_t err = thread_join(thread_hnds[i], &retval);
        TEST_REQUIRE(retval == 0);
        TEST_REQUIRE_OK(err);
    }

    free(thread_hnds);
});

#endif  // THREAD_TESTS_H
