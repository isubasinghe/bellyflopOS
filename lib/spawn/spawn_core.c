#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/macros.h>
#include <spawn/spawn.h>
#include <aos/cache.h>
#include <aos/ump_chan.h>
#include <aos/coreboot.h>
#include <aos/ump_ringbuffer.h>

#define BOOT_DRIVER "boot_armv8_generic"
#define CPU_DRIVER_QEMU "cpu_a57_qemu"
#define CPU_DRIVER_IMX8X "cpu_imx8x"
#define INIT "init"

// Amount of static memory that each new core gets
#define CORE_MEMORY_SIZE 256 * MB

// Maybe not the best place for this memory.


errval_t spawn_core(void *from_i_to_0_urpc, size_t coreid, enum pi_platform platform)
{
    errval_t err;
    struct frame_identity urpc_frame_id;
    {
        struct capability c;
        err = cap_direct_identify(cap_urpc, &c);
        assert(c.type == ObjType_Frame);

        urpc_frame_id = (struct frame_identity) {
            .base = cap_get_paddr(cap_urpc),
            .bytes = c.u.frame.bytes,
            .pasid = disp_get_core_id(),
        };
    }

    // Fill URPC page with phys memory of provided static RAM and bootinfo.
    struct capref core_memory;
    size_t core_memory_size_ret;
    err = frame_alloc(&core_memory, CORE_MEMORY_SIZE, &core_memory_size_ret);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    struct capref bi_cap = {
        .cnode = cnode_task,
        .slot = TASKCN_SLOT_BOOTINFO,
    };

    // Because of the way ump_ringbuffer is implemented, don't use from_i_to_0_urpc[7 * n]
    // positions.
    uintptr_t *urpc = (uintptr_t *)from_i_to_0_urpc;
    urpc[0] = cap_get_paddr(core_memory);
    urpc[1] = core_memory_size_ret;
    urpc[2] = cap_get_paddr(bi_cap);
    urpc[3] = cap_get_psize(bi_cap);
    urpc[4] = cap_get_paddr(cap_mmstrings);
    urpc[5] = cap_get_psize(cap_mmstrings);

    // Clear cache of the URPC
    cpu_dcache_wb_range((vm_offset_t)urpc, BASE_PAGE_SIZE);

    const char *cpu_driver = NULL;
    switch (platform) {
    case PI_PLATFORM_QEMU:
        cpu_driver = CPU_DRIVER_QEMU;
        break;
    case PI_PLATFORM_IMX8X:
        cpu_driver = CPU_DRIVER_IMX8X;
        break;
    default:
        DEBUG_PRINTF("Unsupported platform: %d\n", platform);
        assert(0);
    }

    err = coreboot(coreid, BOOT_DRIVER, cpu_driver, INIT, urpc_frame_id);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_COREBOOT);

    return SYS_ERR_OK;
}
