#ifndef UMP_CHAN_TESTS_H
#define UMP_CHAN_TESTS_H

#include <aos/test_utils.h>
#include <aos/aos.h>
#include <aos/ump_chan.h>
#include <aos/ump_ringbuffer.h>
#include <aos/units.h>

// Note: These tests are not robust. There's no parallel accessing of the channel as it
// runs on a single core.

static char ump_chan_buf_write[BASE_PAGE_SIZE] __attribute__((aligned(CACHE_LINE_SIZE)));
static char ump_chan_buf_read[BASE_PAGE_SIZE] __attribute__((aligned(CACHE_LINE_SIZE)));

CREATE_TEST(ump_ringbuffer_sanitytest, ump_chan_tests, {
    struct ump_ringbuffer rb_writer;
    struct ump_ringbuffer rb_reader;
    memset(ump_chan_buf_write, 0, BASE_PAGE_SIZE);
    memset(ump_chan_buf_read, 0, BASE_PAGE_SIZE);

    ump_ringbuffer_init(&rb_writer, UMP_RINGBUFFER_MODE_WRITER, ump_chan_buf_write,
                        BASE_PAGE_SIZE);
    ump_ringbuffer_init(&rb_reader, UMP_RINGBUFFER_MODE_READER, ump_chan_buf_write,
                        BASE_PAGE_SIZE);

    char send_buffer[DATA_SIZE_B] = { 0 };
    char recv_buffer[DATA_SIZE_B] = { 0 };

    for (volatile int i = 0; i < DATA_SIZE_B; i++) {
        send_buffer[i] = i;
    }

    ump_ringbuffer_write(&rb_writer, send_buffer, DATA_SIZE_B);
    errval_t err = ump_ringbuffer_read(&rb_reader, recv_buffer, DATA_SIZE_B,
                                       /*is_blocking=*/true);
    TEST_REQUIRE_OK(err);

    for (size_t i = 0; i < DATA_SIZE_B; i++) {
        TEST_REQUIRE(recv_buffer[i] == i);
    }
});

CREATE_TEST(ump_chan_send_recv_caller_buf, ump_chan_tests, {
    struct ump_chan a_to_b;
    struct ump_chan b_to_a;
    ump_chan_init(&a_to_b, ump_chan_buf_write, BASE_PAGE_SIZE, ump_chan_buf_read,
                  BASE_PAGE_SIZE);
    ump_chan_init(&b_to_a, ump_chan_buf_read, BASE_PAGE_SIZE, ump_chan_buf_write,
                  BASE_PAGE_SIZE);

    const char *hello = "hello";
    ump_chan_send(&a_to_b, (uint8_t *)hello, 5, NULL_CAP);

    char recv_buf[10];
    size_t recv_buflen = 10;
    char *buf = recv_buf;
    errval_t err = ump_chan_recv_blocking(&b_to_a, (uint8_t **)&buf, &recv_buflen, NULL);
    TEST_REQUIRE_OK(err);

    TEST_REQUIRE(recv_buflen == 5);
    TEST_REQUIRE(memcmp("hello", recv_buf, 5) == 0);
});

CREATE_TEST(ump_chan_send_recv_one_data_size, ump_chan_tests, {
    struct ump_chan a_to_b;
    struct ump_chan b_to_a;
    ump_chan_init(&a_to_b, ump_chan_buf_write, BASE_PAGE_SIZE, ump_chan_buf_read,
                  BASE_PAGE_SIZE);
    ump_chan_init(&b_to_a, ump_chan_buf_read, BASE_PAGE_SIZE, ump_chan_buf_write,
                  BASE_PAGE_SIZE);

    uint8_t send_buf[DATA_SIZE_B];
    for (uint8_t i = 0; i < DATA_SIZE_B; ++i) {
        send_buf[i] = i;
    }
    ump_chan_send(&a_to_b, send_buf, DATA_SIZE_B, NULL_CAP);

    uint8_t recv_buf[DATA_SIZE_B];
    size_t recv_buflen = DATA_SIZE_B;
    uint8_t *buf = recv_buf;
    errval_t err = ump_chan_recv_blocking(&b_to_a, &buf, &recv_buflen, NULL);
    TEST_REQUIRE_OK(err);

    TEST_REQUIRE(recv_buflen == DATA_SIZE_B);
    for (size_t i = 0; i < DATA_SIZE_B; ++i) {
        TEST_REQUIRE(recv_buf[i] == i);
    }
});

#define BIG_MSG_SIZE_B 400

CREATE_TEST(ump_chan_send_recv_callee_mallocs, ump_chan_tests, {
    struct ump_chan a_to_b;
    struct ump_chan b_to_a;
    ump_chan_init(&a_to_b, ump_chan_buf_write, BASE_PAGE_SIZE, ump_chan_buf_read,
                  BASE_PAGE_SIZE);
    ump_chan_init(&b_to_a, ump_chan_buf_read, BASE_PAGE_SIZE, ump_chan_buf_write,
                  BASE_PAGE_SIZE);

    uint8_t send_buf[BIG_MSG_SIZE_B];
    for (size_t i = 0; i < BIG_MSG_SIZE_B; ++i) {
        send_buf[i] = i % 256;
    }

    ump_chan_send(&a_to_b, send_buf, BIG_MSG_SIZE_B, NULL_CAP);

    uint8_t *buf;
    size_t buflen = 0;
    errval_t err = ump_chan_recv_blocking(&b_to_a, &buf, &buflen, NULL);
    TEST_REQUIRE_OK(err);

    TEST_REQUIRE(buflen == BIG_MSG_SIZE_B);
    for (size_t i = 0; i < BIG_MSG_SIZE_B; ++i) {
        TEST_REQUIRE(buf[i] == i % 256);
    }
    free(buf);
});

CREATE_TEST(ump_chan_send_recv_many, ump_chan_tests, {
    struct ump_chan a_to_b;
    struct ump_chan b_to_a;
    ump_chan_init(&a_to_b, ump_chan_buf_write, BASE_PAGE_SIZE, ump_chan_buf_read,
                  BASE_PAGE_SIZE);
    ump_chan_init(&b_to_a, ump_chan_buf_read, BASE_PAGE_SIZE, ump_chan_buf_write,
                  BASE_PAGE_SIZE);

    uint8_t send_buf[DATA_SIZE_B];
    for (uint8_t i = 0; i < DATA_SIZE_B; ++i) {
        send_buf[i] = i;
    }

    for (size_t i = 0; i < 10; ++i) {
        ump_chan_send(&a_to_b, send_buf, DATA_SIZE_B, NULL_CAP);
    }

    for (size_t i = 0; i < 10; ++i) {
        uint8_t *buf;
        size_t buflen = 0;
        errval_t err = ump_chan_recv_blocking(&b_to_a, &buf, &buflen, NULL);
        TEST_REQUIRE_OK(err);

        TEST_REQUIRE(buflen == DATA_SIZE_B);
        for (size_t j = 0; j < DATA_SIZE_B; ++j) {
            TEST_REQUIRE(buf[j] == j);
        }
        free(buf);
    }
});

CREATE_TEST(ump_chan_send_frame, ump_chan_tests, {
    struct ump_chan a_to_b;
    struct ump_chan b_to_a;
    ump_chan_init(&a_to_b, ump_chan_buf_write, BASE_PAGE_SIZE, ump_chan_buf_read,
                  BASE_PAGE_SIZE);
    ump_chan_init(&b_to_a, ump_chan_buf_read, BASE_PAGE_SIZE, ump_chan_buf_write,
                  BASE_PAGE_SIZE);

    struct capref cap;
    errval_t err = frame_alloc(&cap, BASE_PAGE_SIZE, NULL);
    TEST_REQUIRE_OK(err);
    ump_chan_send(&a_to_b, NULL, 0, cap);

    uint8_t *buf = NULL;
    size_t buflen = 0;
    struct capref cap_recv;
    err = ump_chan_recv_blocking(&b_to_a, &buf, &buflen, &cap_recv);
    TEST_REQUIRE_OK(err);

    struct capability c_gold;
    struct capability c_test;
    TEST_REQUIRE_OK(cap_direct_identify(cap, &c_gold));
    TEST_REQUIRE_OK(cap_direct_identify(cap_recv, &c_test));

    TEST_REQUIRE(c_test.type == ObjType_Frame);
    TEST_REQUIRE(c_gold.u.frame.base == c_test.u.frame.base);
    TEST_REQUIRE(c_gold.u.frame.bytes == c_test.u.frame.bytes);
});

#endif  // UMP_CHAN_TESTS_H
