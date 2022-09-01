//
// Created by fooris on 24.05.22.
//


#include <drivers/sdhc.h>
#include <arch/aarch64/aos/cache.h>
#include <maps/imx8x_map.h>
#include <driverkit/driverkit.h>
#include <aos/macros.h>

#include "sd_wrapper.h"
#include "util.h"

errval_t init_sd_wrapper(struct sd_wrapper *sd)
{
    errval_t err;
    struct capref sdhc_cap;
    lvaddr_t sdhc_base;
    err = map_device_register(IMX8X_SDHC2_BASE, IMX8X_SDHC_SIZE, task_cap_argcn0,
                              &sdhc_cap, &sdhc_base);
    RETURN_IF_ERR(err);

    err = sdhc_init(&sd->sd, (void *)sdhc_base);
    RETURN_IF_ERR(err);

    // Setup buffer.
    err = frame_alloc(&sd->buf_frame_cap, FAT_BUFFER_SIZE, NULL);
    RETURN_IF_ERR(err);

    sd->base_paddr = cap_get_paddr(sd->buf_frame_cap);
    err = paging_map_frame(get_current_paging_state(), (void **)&sd->buf, FAT_BUFFER_SIZE,
                           sd->buf_frame_cap);
    RETURN_IF_ERR(err);
//    sd->first_cached_sector = 0;

    return SYS_ERR_OK;
}


/* Read size bytes starting from sector + offset (in bytes within sector)  */
errval_t read_from_sd_offset(struct sd_wrapper *sd, void *dst, uint32_t sector,
                             uint32_t offset, uint32_t size)
{
    size = size + offset;
    assert(size <= FAT_BUFFER_SIZE);
    assert(offset <= SDHC_BLOCK_SIZE);  // Mainly for consistency.
    errval_t err;
    genpaddr_t base = sd->base_paddr; //cap_get_paddr(sd->buf_frame_cap);
    uint32_t sec = sector;
    cpu_dcache_wbinv_range((lvaddr_t)sd->buf, FAT_BUFFER_SIZE);
    DATA_BARRIER;
    for (int i = 0; i < size; i += SDHC_BLOCK_SIZE) {
        err = sdhc_read_block(sd->sd, sec++, base + i);
        RETURN_IF_ERR(err);
    }
    if (dst) {
        memcpy((void *)dst, (void *)sd->buf + offset, size - offset);
    }
    return SYS_ERR_OK;
}

errval_t read_from_sd(struct sd_wrapper *sd, void *dst, uint32_t sector, uint32_t size)
{
    return read_from_sd_offset(sd, dst, sector, 0, size);
}

errval_t write_to_sd_offset(struct sd_wrapper *sd, uint32_t sector, uint32_t offset,
                            const void *src, uint32_t size)
{
//    DEBUG_PRINTF("WRITE TO SD: sector %u, offset %u, size %u", sector, offset, size);
    size = size + offset;
    assert(size <= FAT_BUFFER_SIZE);
    assert(offset <= SDHC_BLOCK_SIZE);

    errval_t err;
    genpaddr_t base = sd->base_paddr; //cap_get_paddr(sd->buf_frame_cap);

    if (offset) {
//        DEBUG_PRINTF("SD_WRITE: READING IN FIRST BLOCK\n");
        err = sdhc_read_block(sd->sd, sector, base);
        RETURN_IF_ERR(err);
    }
    uint32_t last_sector = sector + (size / SDHC_BLOCK_SIZE);
    assert(last_sector != 0xFFFFFFFF);

    bool already_read_last = offset && (sector == last_sector);
    if (size % SDHC_BLOCK_SIZE && !already_read_last) {
//        DEBUG_PRINTF("SD_WRITE: READING IN LAST BLOCK\n");
        err = sdhc_read_block(sd->sd, last_sector, base);
//        DEBUG_PRINTF("SD_WRITE: READING IN LAST BLOCK --- DONE\n");
        RETURN_IF_ERR(err);
    }
    DATA_BARRIER;
    cpu_dcache_wbinv_range((lvaddr_t)sd->buf, FAT_BUFFER_SIZE);
    DATA_BARRIER;

    memcpy((void *)sd->buf + offset, src, size - offset);

    DATA_BARRIER;
    cpu_dcache_wbinv_range((lvaddr_t)sd->buf, FAT_BUFFER_SIZE);
    DATA_BARRIER;
//    DEBUG_PRINTF("SD_WRITE: ACTUALLY WRITING BLOCKS\n");
    for (int i = 0; i < size; i += SDHC_BLOCK_SIZE) {
        err = sdhc_write_block(sd->sd, sector++, base + i);
        RETURN_IF_ERR(err);
    }
//    DEBUG_PRINTF("SD_WRITE: ACTUALLY WRITING BLOCKS ... DONE\n");

    return SYS_ERR_OK;
}

errval_t read_from_sd_to_paddr(struct sd_wrapper *sd, lpaddr_t paddr, uint32_t sector, uint32_t size) {
    errval_t err;
    uint32_t sec = sector;
    assert(size % SDHC_BLOCK_SIZE == 0);
    for (int i = 0; i < size; i += SDHC_BLOCK_SIZE) {
        err = sdhc_read_block(sd->sd, sec++, paddr + i);
        RETURN_IF_ERR(err);
    }
    return SYS_ERR_OK;
}

errval_t write_to_sd_from_paddr(struct sd_wrapper *sd, lpaddr_t paddr, uint32_t sector, uint32_t size) {
    errval_t err;
    uint32_t sec = sector;
    assert(size % SDHC_BLOCK_SIZE == 0);
    for (int i = 0; i < size; i += SDHC_BLOCK_SIZE) {
        err = sdhc_write_block(sd->sd, sec++, paddr + i);
        RETURN_IF_ERR(err);
    }

    return SYS_ERR_OK;
}
