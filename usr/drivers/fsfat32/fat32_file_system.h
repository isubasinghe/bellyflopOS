//
// Created by fooris on 18.05.22.
//

#ifndef BF_AOS_FAT32_FILE_SYSTEM_H
#define BF_AOS_FAT32_FILE_SYSTEM_H

#include <aos/aos.h>
#include "FAT32_internal.h"
#include "sd_wrapper.h"


struct dir_entry {
    struct FAT_DIRENT entry;
    uint32_t cluster;  // cluster of FAT_DIRENT on disk
    uint32_t index;    // index of dir entry in cluster (in num FAT_DIRENT)
};

struct fat32_file_system {
    struct sd_wrapper sd;

    struct BPB bpb;
    struct FS_INFO fs_info;

    size_t cluster_bytes;
    uint16_t fat_sec_num;
    uint16_t data_sec_num;
    uint16_t root_dir_sec_num;
    struct dir_entry root_dir;  // Dummy directory entry for the root directory.

    volatile fat_entry_t *fat_cache;
    struct capref fat_cache_frame;
    lpaddr_t fat_cache_paddr;
    size_t fat_cache_size;
};

#define FAT_ATTR_READ_ONLY 0x01
#define FAT_ATTR_HIDDEN 0x02
#define FAT_ATTR_SYSTEM 0x04
#define FAT_ATTR_VOLUME_ID 0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_ARCHIVE 0x20
#define FAT_ATTR_LONG_NAME                                                               \
    (FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID)

errval_t init_fat32_file_system(struct fat32_file_system *fat);
errval_t destroy_fat32_file_system(struct fat32_file_system *fat);

errval_t fat32_read(struct fat32_file_system *fat, struct dir_entry *dir_entry, void *buf,
                    size_t pos, size_t bytes, size_t *ret_bytes);
errval_t fat32_write(struct fat32_file_system *fat, struct dir_entry *dir_entry,
                     void *buf, size_t pos, size_t bytes, size_t *ret_bytes);

errval_t fat32_readfile_to_frame(struct fat32_file_system *fat, struct dir_entry *dir_entry, struct capref frame, size_t *ret_bytes);

errval_t fat32_resolve_path(struct fat32_file_system *fat, const char *path,
                            struct dir_entry *result);
errval_t fat32_find_dirent(struct fat32_file_system *fat, struct dir_entry *parent,
    char *filename, struct dir_entry *res);

errval_t fat32_create_file(struct fat32_file_system *fat, struct dir_entry *parent,
                           char *name, uint8_t attr, struct dir_entry *ret);
errval_t fat32_delete_file(struct fat32_file_system *fat, struct dir_entry *parent,
                           struct dir_entry *dir_entry);

errval_t fat32_read_from_cluster(struct fat32_file_system *fat, void *buf,
                                 uint32_t cluster_num, size_t offset, size_t bytes);
errval_t fat32_write_to_cluster(struct fat32_file_system *fat, uint32_t cluster_num,
                                size_t offset, void *buf, size_t bytes);

errval_t fat32_trunc(struct fat32_file_system *fat, struct dir_entry *dir_entry,
                     size_t bytes);

errval_t read_next_dir_after_offset(struct fat32_file_system *fat, struct dir_entry *parent, uint64_t offset, char **ret_name, uint64_t *ret_idx);

#endif  // BF_AOS_FAT32_FILE_SYSTEM_H
