#include <driverkit/driverkit.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/kernel_cap_invocations.h>

errval_t map_device_register(lpaddr_t address, size_t size, struct capref device_cap,
                             struct capref *return_cap, lvaddr_t *return_address)
{
    errval_t err;
    assert(!capref_is_null(device_cap));
    void *buff;
    err = paging_map_frame_attr(get_current_paging_state(), &buff, size, device_cap,
                                VREGION_FLAGS_READ_WRITE_NOCACHE);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

    *return_address = (lvaddr_t)buff;
    *return_cap = device_cap;


    return SYS_ERR_OK;
}
