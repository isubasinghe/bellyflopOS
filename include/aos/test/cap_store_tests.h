
#include <aos/test_utils.h>
#include <stdio.h>
#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>

#include <aos/cap_store.h>


static cslot_t slot0;
static cslot_t slot1;
static void free_cap(struct capref data)
{
    if (slot0 == 0) {
        slot0 = data.slot;
    } else {
        slot1 = data.slot;
    }
}

CREATE_TEST(test1, cap_store_tests, {
    char slab_space[CAP_STORE_SLAB_BLOCKSIZE * 10];
    struct slab_allocator slabs;

    slab_init(&slabs, CAP_STORE_SLAB_BLOCKSIZE, NULL);
    slab_grow(&slabs, slab_space, sizeof(slab_space));

    uint32_t slab_size = slabs.slabs->free;


    struct cap_store store;
    cap_store_init(&store, &slabs, free_cap);

    {
        struct capref retcap;
        retcap.slot = 4242;
        cap_store_add(&store, 136, retcap);
    }
    {
        struct capref retcap;
        retcap.slot = 4243;
        cap_store_add(&store, 136, retcap);
    }
    {
        struct capref retcap;
        retcap.slot = 4244;
        cap_store_add(&store, 137, retcap);
    }

    slot0 = 0;
    slot1 = 0;

    cap_store_free(&store, 137);
    TEST_REQUIRE(slot0 == 4244);
    TEST_REQUIRE(slot1 == 0);

    slot0 = 0;
    slot1 = 0;

    cap_store_free(&store, 136);
    TEST_REQUIRE(slot1 == 4242);
    TEST_REQUIRE(slot0 == 4243);


    cap_store_delete(&store);
    TEST_REQUIRE(slab_size == slabs.slabs->free);
})
