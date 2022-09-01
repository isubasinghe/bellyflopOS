#include <mm/mm.h>
#include <aos/test_utils.h>


extern struct bootinfo *bi;
size_t getLargestSize(void)
{
    size_t max = 0;
    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            if (max < bi->regions[i].mr_bytes) {
                max = bi->regions[i].mr_bytes;
            }
        }
    }

    return max;
}

static struct mm *test_mm;

CREATE_TEST(partial_frees, mm_tests, {
    // Test partial free.
    struct capref retcap;
    errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE * 2, BASE_PAGE_SIZE * 2,
                                    &retcap);
    TEST_REQUIRE_OK(err);


    struct capref split_cap;
    err = slot_alloc(&split_cap);
    TEST_REQUIRE_OK(err);

    cap_retype(split_cap, retcap, 0, ObjType_RAM, BASE_PAGE_SIZE, 1);

    err = mm_free(test_mm, split_cap);
    TEST_REQUIRE_OK(err);

    err = mm_free(test_mm, retcap);
    TEST_REQUIRE_FAIL_WITH(
        err, err_push(LIB_ERR_FREE_LIST_DOUBLE_FREE, LIB_ERR_FREE_LIST_ADD_FREE));

    err = slot_alloc(&split_cap);
    TEST_REQUIRE_OK(err);

    cap_retype(split_cap, retcap, BASE_PAGE_SIZE, ObjType_RAM, BASE_PAGE_SIZE, 1);
    err = mm_free(test_mm, split_cap);
    TEST_REQUIRE_OK(err);

    cap_destroy(retcap);
})


CREATE_TEST(allocate_memory_continuous1, mm_tests, {
    // Continuos allocations are continuos + get the same allocs after free.
    struct capref retcap[10];

    for (int i = 0; i < 10; i++) {
        errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                                        &retcap[i]);
        TEST_REQUIRE_OK(err);
    }

    size_t prev_base = 0;
    size_t first_base = 0;


    for (int i = 0; i < 10; i++) {
        struct capability c;
        errval_t err = cap_direct_identify(retcap[i], &c);
        TEST_REQUIRE_OK(err);
        TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE);
        if (prev_base != 0) {
            TEST_REQUIRE(prev_base + BASE_PAGE_SIZE == c.u.ram.base);
        } else if (prev_base == 0) {
            first_base = c.u.ram.base;
        }
        prev_base = c.u.ram.base;
    }

    for (int i = 0; i < 10; i++) {
        errval_t err = mm_free(test_mm, retcap[i]);
        TEST_REQUIRE_OK(err);
    }


    for (int i = 0; i < 10; i++) {
        errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                                        &retcap[i]);
        TEST_REQUIRE_OK(err);
    }

    prev_base = first_base - BASE_PAGE_SIZE;


    for (int i = 0; i < 10; i++) {
        struct capability c;
        errval_t err = cap_direct_identify(retcap[i], &c);
        TEST_REQUIRE_OK(err);
        TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE);
        if (prev_base != 0) {
            TEST_REQUIRE(prev_base + BASE_PAGE_SIZE == c.u.ram.base);
        } else if (prev_base == 0) {
            first_base = c.u.ram.base;
        }
        prev_base = c.u.ram.base;
    }

    // Free Backwards this time.
    for (int i = 0; i < 10; i++) {
        errval_t err = mm_free(test_mm, retcap[9 - i]);
        TEST_REQUIRE_OK(err);
    }

    for (int i = 0; i < 10; i++) {
        errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                                        &retcap[i]);
        TEST_REQUIRE_OK(err);
    }

    prev_base = first_base - BASE_PAGE_SIZE;


    for (int i = 0; i < 10; i++) {
        struct capability c;
        errval_t err = cap_direct_identify(retcap[i], &c);
        TEST_REQUIRE_OK(err);
        TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE);
        if (prev_base != 0) {
            TEST_REQUIRE(prev_base + BASE_PAGE_SIZE == c.u.ram.base);
        } else if (prev_base == 0) {
            first_base = c.u.ram.base;
        }
        prev_base = c.u.ram.base;
    }

    // Free Backwards this time.
    for (int i = 0; i < 10; i++) {
        errval_t err = mm_free(test_mm, retcap[9 - i]);
        TEST_REQUIRE_OK(err);
    }
})

CREATE_TEST(allocate_memory_continuous2, mm_tests, {
    struct capref retcap[10];

    for (int i = 0; i < 10; i++) {
        errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE * 2,
                                        &retcap[i]);
        TEST_REQUIRE_OK(err);
    }

    size_t prev_base = 0;
    size_t first_base = 0;

    for (int i = 0; i < 10; i++) {
        struct capability c;
        errval_t err = cap_direct_identify(retcap[i], &c);
        TEST_REQUIRE_OK(err);
        {
            TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE);
            if (prev_base != 0) {
                // This is technically not an error. But for small sizes this should be
                // the case with my impl.
                TEST_REQUIRE(prev_base + BASE_PAGE_SIZE * 2 == c.u.ram.base
                             && c.u.ram.base % (BASE_PAGE_SIZE * 2) == 0);
            } else if (prev_base == 0) {
                first_base = c.u.ram.base;
            }
            prev_base = c.u.ram.base;
        }
    }

    for (int i = 0; i < 10; i++) {
        errval_t err = mm_free(test_mm, retcap[i]);
        TEST_REQUIRE_OK(err);
    }
})


CREATE_TEST(allocate_memory_aligned, mm_tests, {
    struct capref retcap;
    errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE * 2, &retcap);
    TEST_REQUIRE_OK(err);
    err = mm_free(test_mm, retcap);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(allocate_large_region, mm_tests, {
    struct capref retcap;
    struct capref retcap2;
    // OBJSIZE_L2CNODE Is the space the slot allocator might have taken
    errval_t err = mm_alloc_aligned(test_mm, getLargestSize() / 2, BASE_PAGE_SIZE,
                                    &retcap);
    TEST_REQUIRE_OK(err);
    err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE * 1, &retcap2);
    TEST_REQUIRE_OK(err);
    err = mm_free(test_mm, retcap);
    TEST_REQUIRE_OK(err);
    err = mm_free(test_mm, retcap2);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(out_of_memory, mm_tests, {
    struct capref retcap;
    errval_t err = mm_alloc_aligned(test_mm, getLargestSize() + BASE_PAGE_SIZE,
                                    BASE_PAGE_SIZE, &retcap);
    TEST_REQUIRE_FAIL_WITH(err, MM_ERR_OUT_OF_MEMORY);
})

CREATE_TEST(many_300_pages, mm_tests, {
    // Test if slot allocator gets refilled.
    struct capref retcap[300];
    for (int i = 0; i < 300; i++) {
        errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                                        &retcap[i]);
        TEST_REQUIRE_OK(err);
    }
    for (int i = 0; i < 300; i++) {
        struct capability c;
        errval_t err = cap_direct_identify(retcap[i], &c);
        TEST_REQUIRE_OK(err);
        TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE);
    }

    for (int i = 0; i < 300; i++) {
        errval_t err = mm_free(test_mm, retcap[i]);
        TEST_REQUIRE_OK(err);
    }
})

// Goes through 2.28 GB of data.
//#define MM_TEST8_RUNS 10000
#define MM_TEST8_RUNS 1000


CREATE_TEST(allocate_loads_of_memory, mm_tests, {
    // Test if slab allocator gets refilled.

    struct capref retcap[MM_TEST8_RUNS];

    for (int j = 0; j < 2; j++) {
        for (int i = 0; i < MM_TEST8_RUNS; i++) {
            // Use alignment to force new entries in free list.
            errval_t err = mm_alloc_aligned(test_mm, BASE_PAGE_SIZE * 4,
                                            8 * BASE_PAGE_SIZE, &retcap[i]);
            TEST_REQUIRE_OK(err);
        }
        for (int i = 0; i < MM_TEST8_RUNS; i++) {
            struct capability c;
            errval_t err = cap_direct_identify(retcap[i], &c);
            TEST_REQUIRE_OK(err);
            TEST_REQUIRE(c.u.ram.bytes == BASE_PAGE_SIZE * 4);
        }

        for (int i = 0; i < MM_TEST8_RUNS; i++) {
            errval_t err = mm_free(test_mm, retcap[i]);
            TEST_REQUIRE_OK(err);
        }
    }
})