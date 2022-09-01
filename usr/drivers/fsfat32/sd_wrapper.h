#ifndef BF_AOS_SD_WRAPPER_H
#define BF_AOS_SD_WRAPPER_H

#define SECTOR_SIZE 512
#define FAT_BUFFER_SIZE 4096
#define NUM_CACHED_SECTORS (FAT_BUFFER_SIZE / SECTOR_SIZE)

//#include "fat32_file_system.h"
//struct fat32_file_system;

struct sd_wrapper {
    struct sdhc_s *sd;  // TODO close when done
    // Stuff to keep track of.
    struct capref buf_frame_cap;  // TODO Destroy when done.
    volatile void *buf;           // TODO unmap when done.
    genpaddr_t base_paddr;

    uint32_t first_cached_sector;
};

errval_t init_sd_wrapper(struct sd_wrapper *sd);

errval_t read_from_sd_offset(struct sd_wrapper *sd, void *dst, uint32_t sector,
                             uint32_t offset, uint32_t size);
errval_t read_from_sd(struct sd_wrapper *sd, void *dst, uint32_t sector, uint32_t size);

errval_t write_to_sd_offset(struct sd_wrapper *sd, uint32_t sector, uint32_t offset,
                            const void *src, uint32_t size);

errval_t read_from_sd_to_paddr(struct sd_wrapper *sd, lpaddr_t paddr, uint32_t sector, uint32_t size);
errval_t write_to_sd_from_paddr(struct sd_wrapper *sd, lpaddr_t paddr, uint32_t sector, uint32_t size);

#endif  // BF_AOS_SD_WRAPPER_H
