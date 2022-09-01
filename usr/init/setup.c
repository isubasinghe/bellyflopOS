#include "setup.h"

#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>
#include <maps/imx8x_map.h>
#include <spawn/spawn.h>

static errval_t get_device_cap(lpaddr_t address, size_t size, struct capref *return_cap)
{
    struct capref all_dev_cap = { .cnode = { .croot = CPTR_ROOTCN,
                                             .cnode = CPTR_TASKCN_BASE,
                                             .level = CNODE_TYPE_OTHER },
                                  .slot = TASKCN_SLOT_DEV };

    assert(address % BASE_PAGE_SIZE == 0);
    assert(size % BASE_PAGE_SIZE == 0);

    struct capref result_cap;
    errval_t err = slot_alloc(&result_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);

    assert(address > cap_get_paddr(all_dev_cap));
    size_t all_dev_cap_offset = address - cap_get_paddr(all_dev_cap);
    err = cap_retype(result_cap, all_dev_cap, all_dev_cap_offset, ObjType_DevFrame, size,
                     1);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_RETYPE);
    *return_cap = result_cap;

    return SYS_ERR_OK;
}

errval_t setup_network_driver(void)
{
    errval_t err;
    struct capref enet_dev;
    err = get_device_cap(IMX8X_ENET_BASE, IMX8X_ENET_SIZE, &enet_dev);
    RETURN_IF_ERR(err);

    domainid_t enet_pid;
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    assert(si != NULL);
    assert(!capref_is_null(enet_dev));
    err = spawn_load_by_cmdline_argcn("enet", si, &enet_pid, enet_dev, NULL_CAP, NULL_CAP);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);
    return SYS_ERR_OK;
}

errval_t setup_filesystem(void)
{
    errval_t err;
    struct capref sdhc_dev;
    err = get_device_cap(IMX8X_SDHC2_BASE, IMX8X_SDHC_SIZE, &sdhc_dev);
    RETURN_IF_ERR(err);

    domainid_t fs_pid;
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    assert(si != NULL);
    assert(!capref_is_null(sdhc_dev));
    err = spawn_load_by_cmdline_argcn("fsfat32", si, &fs_pid, sdhc_dev, NULL_CAP,
                                      NULL_CAP);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);
    return SYS_ERR_OK;
}

errval_t setup_nameserver_bsp(void)
{
    assert(disp_get_core_id() == 0);
    errval_t err;

    // Start nameserver on core 0.
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t did;
    err = spawn_load_by_name("nameserver", si, &did);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);
    assert(sid_from(did, 0) == NAMESERVER_SERVICEID);
    set_is_nameserver_started(false);

    // Dispatch while nameserver gets started.
    while (!get_is_nameserver_started()) {
        ASSERT_ERR_OK(event_dispatch(get_default_waitset()));
    }

    nameservice_chan_t nschan;
    // Send the connect RPC directly to the nameserver.
    err = nameservice_connect(NAMESERVER_SERVICEID, &nschan);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_NAMESERVICE_CONNECT);
    set_nameserver_chan(nschan);

    return SYS_ERR_OK;
}

errval_t setup_nameserver_app(void)
{
    assert(disp_get_core_id() != 0);

    errval_t err;
    nameservice_chan_t nschan;
    // Send the connect RPC to core 0 because nameserver runs on core 0.
    err = nameservice_connect(NAMESERVER_SERVICEID, &nschan);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_NAMESERVICE_CONNECT);
    set_nameserver_chan(nschan);

    return SYS_ERR_OK;
}

errval_t setup_terminal_driver(void)
{
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t term_pid;

    struct capref lpuart_cap;
    struct capref gic_cap;

    err = get_device_cap(IMX8X_UART3_BASE, IMX8X_UART_SIZE, &lpuart_cap);
    RETURN_IF_ERR(err);
    err = get_device_cap(IMX8X_GIC_DIST_BASE, IMX8X_GIC_DIST_SIZE, &gic_cap);
    RETURN_IF_ERR(err);
    err = spawn_load_by_cmdline_argcn("terminal", si, &term_pid, lpuart_cap, gic_cap,
                                      cap_irq);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);
    return err;
}
