#include <mm/mm.h>
#include <aos/units.h>
#include <aos/test_utils.h>

CREATE_TEST(small_allocs, malloc_test, {
    volatile char *b1 = malloc(1);
    volatile char *b2 = malloc(2);
    volatile char *b3 = malloc(3);
    volatile char *b4 = malloc(4);

    b1[0] = 1;
    b2[0] = 2;
    b3[0] = 3;
    b4[0] = 4;
    TEST_REQUIRE(b1[0] == 1);
    TEST_REQUIRE(b2[0] == 2);
    TEST_REQUIRE(b3[0] == 3);
    TEST_REQUIRE(b4[0] == 4);
})

CREATE_TEST(alloc_64MB, malloc_test, {
    size_t buf_size = 64 * MB;
    volatile char *v = malloc(buf_size);

    for (size_t i = 0; i < buf_size; i += BASE_PAGE_SIZE) {
        v[i] = 1;
    }
    free((void *)v);
})

CREATE_TEST(touch_256MB_region, malloc_test, {
    size_t buf_size = 256 * MB;
    volatile char *v = malloc(buf_size);

    v[127 * MB] = 1;
    TEST_REQUIRE(v[127 * MB] == 1);

    free((void *)v);
})