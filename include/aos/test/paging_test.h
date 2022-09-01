#include <mm/mm.h>
#include <aos/test_utils.h>

CREATE_TEST(map_one_page, paging_tests, {
    struct paging_state *pst = get_current_paging_state();
    struct capref frame;
    size_t retbytes = 0;
    errval_t err = frame_alloc_aligned(&frame, BASE_PAGE_SIZE * 2, BASE_PAGE_SIZE,
                                       &retbytes);
    TEST_REQUIRE_OK(err);

    size_t *buf = NULL;
    err = paging_map_frame(pst, (void **)&buf, retbytes, frame);
    TEST_REQUIRE_OK(err);

    TEST_REQUIRE(buf >= (size_t *)VADDR_OFFSET);

    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can write to our buffer.
        buf[i] = i;
        TEST_REQUIRE(buf[i] == i);
    }

    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can read our buffer.
        TEST_REQUIRE(buf[i] == i);
    }

    err = paging_unmap(pst, buf);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(map_superpages, paging_tests, {
    struct paging_state *pst = get_current_paging_state();
    struct capref frame;
    size_t retbytes = 0;
    errval_t err = frame_alloc_aligned(&frame, LARGE_PAGE_SIZE * 4, LARGE_PAGE_SIZE,
                                       &retbytes);
    TEST_REQUIRE_OK(err);

    size_t *buf = (size_t *)1099511627776;
    // This does not work anymore since paging_map_fixed_attr will check if
    // the address is free and paging_alloc marks adresses as not free.
    // err = paging_alloc(pst, (void **)&buf, LARGE_PAGE_SIZE, LARGE_PAGE_SIZE);
    TEST_REQUIRE_OK(err);

    err = paging_map_fixed_attr(pst, (lvaddr_t)buf, frame, retbytes,
                                VREGION_FLAGS_READ_WRITE);
    TEST_REQUIRE_OK(err);

    TEST_REQUIRE(buf >= (size_t *)VADDR_OFFSET);

    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can write to our buffer.
        buf[i] = i;
        TEST_REQUIRE(buf[i] == i);
    }

    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can read our buffer.
        TEST_REQUIRE(buf[i] == i);
    }

    err = paging_unmap(pst, buf);
    TEST_REQUIRE_OK(err);
})

// When only the following testcase is run this is the magic number to
// make the root_slot alloc run out of space and triggers the Bug I reported
// on Moodle.
#define NUM_PAGES 355


// When only the following testcase is run this is the magic number to
// make the slot refill in paging_map map the same page that is currently
// tried to be mapped.
// This is happening by slot refill-> slab refill -> paging map
// #define NUM_PAGES 256

CREATE_TEST(map_may_pages, paging_tests_slow, {
    struct paging_state *pst = get_current_paging_state();
    char *bufbuf[100];
    // We run out of memory around 470 iterations.
    for (int j = 0; j < 100; j++) {
        struct capref frame;
        size_t retbytes = 0;
        errval_t err = frame_alloc_aligned(&frame, BASE_PAGE_SIZE * NUM_PAGES,
                                           BASE_PAGE_SIZE * 2, &retbytes);
        TEST_REQUIRE_OK(err);
        char *buf = NULL;
        err = paging_map_frame(pst, (void **)&buf, retbytes, frame);
        TEST_REQUIRE_OK(err);
        TEST_REQUIRE(buf >= (char *)VADDR_OFFSET);

        for (size_t i = 0; i < retbytes; i++) {
            // Test if we can write to our buffer.
            buf[i] = 'a';
        }
        bufbuf[j] = buf;
    }
    for (int i = 0; i < 100; i++) {
        errval_t err = paging_unmap(pst, bufbuf[i]);
        TEST_REQUIRE_OK(err);
    }
})

CREATE_TEST(map_4MB, paging_tests_slow, {
    struct paging_state *pst = get_current_paging_state();

    size_t bytes_4MiB = 1 << 22;
    struct capref frame;
    size_t retbytes = 0;
    errval_t err = frame_alloc_aligned(&frame, bytes_4MiB, BASE_PAGE_SIZE, &retbytes);
    TEST_REQUIRE_OK(err);
    TEST_REQUIRE(retbytes >= bytes_4MiB);

    char *buf = NULL;
    err = paging_map_frame(pst, (void **)&buf, retbytes, frame);
    TEST_REQUIRE_OK(err);
    TEST_REQUIRE(buf >= (char *)VADDR_OFFSET);
    for (size_t i = 0; i < retbytes; i++) {
        // Test if we can write to our buffer.
        buf[i] = 'a';
    }

    err = paging_unmap(pst, buf);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(unmap, paging_tests, {
    struct paging_state *pst = get_current_paging_state();
    struct capref frame;
    size_t retbytes = 0;
    errval_t err = frame_alloc_aligned(&frame, BASE_PAGE_SIZE * 2, BASE_PAGE_SIZE,
                                       &retbytes);
    TEST_REQUIRE_OK(err);

    size_t *buf = NULL;
    err = paging_map_frame(pst, (void **)&buf, retbytes, frame);
    TEST_REQUIRE_OK(err);

    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can write to our buffer.
        buf[i] = i;
        assert(buf[i] == i);
    }

    err = paging_unmap(pst, buf);
    TEST_REQUIRE_OK(err);

    // Writing to buf[0] but also buf[BASE_PAGE_SIZE] now should give a
    // unhanled page fault.

    buf += BASE_PAGE_SIZE;
    err = paging_map_fixed_attr(pst, (lvaddr_t)buf, frame, retbytes,
                                VREGION_FLAGS_READ_WRITE);
    TEST_REQUIRE_OK(err);

    // Read the written data at a shifted virtual adress.
    for (size_t i = 0; i < retbytes / 8; i++) {
        // Test if we can read our buffer.
        TEST_REQUIRE(buf[i] == i);
    }
})

CREATE_TEST(map_lazy, self_paging_tests, {
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    void *void_buf;
    err = paging_map_lazy(st, &void_buf, BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                          VREGION_FLAGS_READ_WRITE, REGION_TYPE_UNKNOWN);
    TEST_REQUIRE_OK(err);


    // Test if we can write to our buffer.
    char *buf = (char *)void_buf;
    buf[0] = 'a';
    TEST_REQUIRE(buf[0] == 'a');
    err = paging_unmap(st, void_buf);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(map_500MB_lazy, self_paging_tests, {
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    void *void_buf;
    size_t page_count = 128000;
    size_t mb500 = BASE_PAGE_SIZE * page_count;
    err = paging_map_lazy(st, &void_buf, mb500, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE,
                          REGION_TYPE_UNKNOWN);
    TEST_REQUIRE_OK(err);


    // Test if we can write to our buffer.
    for (int i = 0; i < page_count; i += 1000) {
        char *buf = (char *)void_buf + i * BASE_PAGE_SIZE;
        buf[i] = 'a';
        TEST_REQUIRE(buf[i] == 'a');
    }
    for (int i = 0; i < page_count; i += 1000) {
        char *buf = (char *)void_buf + i * BASE_PAGE_SIZE;
        TEST_REQUIRE(buf[i] == 'a');
    }

    err = paging_unmap(st, void_buf);
    TEST_REQUIRE_OK(err);
})