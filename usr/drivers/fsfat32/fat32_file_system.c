#include <aos/aos.h>
#include <aos/macros.h>
//#include <dev/fat_bpb_dev.h>
//#include <dev/fat32_ebpb_dev.h>

#include "fat32_file_system.h"
#include "aos/cache.h"

static uint32_t cluster_to_sector(struct fat32_file_system *fat, uint32_t cluster_num)
{
    return fat->data_sec_num + (cluster_num - 2) * fat->bpb.sec_per_clus;
}

#define FAT_CACHE_OPT
/* Operations on File Allocation Table */
#define FAT_ENTRY_NOT_CACHED 0x1

static  errval_t init_fat_cache(struct fat32_file_system *fat) {
#ifdef FAT_CACHE_OPT
    errval_t err;
    // This makes some assumptions about sector and block size (mainly that they are equal).
    fat->fat_cache_size = roundup2(fat->bpb.fat_sz32 * SECTOR_SIZE, fat->cluster_bytes);
    size_t frame_size;
    err = frame_alloc(&fat->fat_cache_frame, fat->fat_cache_size, &frame_size);
    RETURN_IF_ERR(err);

    fat->fat_cache_paddr = cap_get_paddr(fat->fat_cache_frame);
    err = paging_map_frame(get_current_paging_state(), (void **)&fat->fat_cache, frame_size, fat->fat_cache_frame);
//    DEBUG_IF_ERR(err, "paging map frame");
    RETURN_IF_ERR(err);

    size_t num_entries = fat->fat_cache_size / sizeof(fat_entry_t);
    for (int i = 0; i < num_entries; i++) {
        fat->fat_cache[i] = FAT_ENTRY_NOT_CACHED;
    }

//    cpu_dcache_wbinv_range((lvaddr_t)fat->fat_cache, frame_size);
//    err = read_from_sd_to_paddr(&fat->sd, fat->fat_cache_paddr, fat->fat_sec_num, fat->fat_cache_size);
    return err;
#else
    return SYS_ERR_OK;
#endif
}

static errval_t get_fat_entry(struct fat32_file_system *fat, uint32_t cluster_num, fat_entry_t *ret_entry)
{
#ifdef FAT_CACHE_OPT
    assert(cluster_num_is_valid(cluster_num));
    fat_entry_t res = fat->fat_cache[cluster_num];
    if (res == FAT_ENTRY_NOT_CACHED) {
        errval_t err;
        // If the entry is not cached, we load the entire sector into the cache.
        size_t offset = (cluster_num / FATENT_PER_SEC) * SECTOR_SIZE;
        lpaddr_t addr = fat->fat_cache_paddr + offset;
        uint32_t sector = fat->fat_sec_num + (cluster_num / FATENT_PER_SEC);

        cpu_dcache_wbinv_range(((lvaddr_t)fat->fat_cache) + offset, SECTOR_SIZE);
        err = read_from_sd_to_paddr(&fat->sd, addr, sector, SECTOR_SIZE);
        DATA_BARRIER;
        RETURN_IF_ERR(err);

        res = fat->fat_cache[cluster_num];
    }
    *ret_entry = res;

    return SYS_ERR_OK;
#else
    fat_entry_t buf[FATENT_PER_SEC];
    uint32_t idx = fat->fat_sec_num + (cluster_num / FATENT_PER_SEC);
    errval_t err = read_from_sd(&fat->sd, (void *)buf, idx, SECTOR_SIZE);
    RETURN_IF_ERR(err);
    *ret_entry = buf[cluster_num % FATENT_PER_SEC] & 0x0fffffff;

//    DEBUG_PRINTF("get fat entry:     old: %u ; new: %u\n", *ret_entry, res);
    return SYS_ERR_OK;
#endif
}

static errval_t set_fat_entry(struct fat32_file_system *fat, uint32_t cluster_num, fat_entry_t val)
{
//    DEBUG_PRINTF("SET FAT entry for cluster %d to 0x%x\n", cluster_num, val);
#ifdef FAT_CACHE_OPT
    fat->fat_cache[cluster_num] = val;
#endif

    // TODO: This should be optimized to fit with get_fat_entry.
    uint32_t sector = fat->fat_sec_num + (cluster_num / FATENT_PER_SEC);
    uint32_t offset = (cluster_num % FATENT_PER_SEC) * sizeof(fat_entry_t);
    return write_to_sd_offset(&fat->sd, sector, offset, &val, sizeof(fat_entry_t));
}

static errval_t get_next_cluster_num(struct fat32_file_system *fat, uint32_t cluster_num,
                                     uint32_t *next_cluster_num)
{
    return get_fat_entry(fat, cluster_num, next_cluster_num);
}

static errval_t get_next_free_cluster(struct fat32_file_system *fat, uint32_t *ret_cluster)
{
    uint32_t start_cluster = (fat->fs_info.nxt_free != 0xFFFFFFFF) ? fat->fs_info.nxt_free : 5;
    if (start_cluster < 5) start_cluster = 5;

//    DEBUG_PRINTF("Looking for free cluster (sc: 0x%x, fs_info.nxt_free: 0x%x).\n",
//                 start_cluster, fat->fs_info.nxt_free);
    for (uint32_t cluster = start_cluster; cluster < fat->bpb.fat_sz32 * FATENT_PER_SEC;
         cluster++) {
        fat_entry_t entry;
        RETURN_IF_ERR(get_fat_entry(fat, cluster, &entry));
//        DEBUG_PRINTF("Inspecting cluster %d: Has fat value = 0x%x\n", cluster, entry);
        if (entry == 0) {
            fat->fs_info.nxt_free = cluster;
            *ret_cluster = cluster;
            return SYS_ERR_OK;
        }
    }
    for (uint32_t cluster = 5; cluster < start_cluster; cluster++) {
        fat_entry_t entry;
        RETURN_IF_ERR(get_fat_entry(fat, cluster, &entry));
//        DEBUG_PRINTF("Inspecting cluster %d: Has fat value = %x", entry);
        if (entry == 0) {
            fat->fs_info.nxt_free = cluster;
            *ret_cluster = cluster;
            return SYS_ERR_OK;
        }
    }
    return FAT_ERR_DISK_FULL;
}

static errval_t alloc_cluster(struct fat32_file_system *fat, uint32_t *ret_cluster)
{
    errval_t err;


    err = get_next_free_cluster(fat, ret_cluster);
    RETURN_IF_ERR(err);
    fat->fs_info.nxt_free++;

    err = set_fat_entry(fat, *ret_cluster, EOC_INDICATOR);
    RETURN_IF_ERR(err);

//    DEBUG_PRINTF("alloced new cluster: %d\n", *ret_cluster);

    return SYS_ERR_OK;
}

static errval_t free_cluster_chain(struct fat32_file_system *fat, uint32_t first_cluster)
{
    errval_t err;
    uint32_t cluster = first_cluster;
    uint32_t next_cluster = first_cluster;

    while (cluster_num_is_valid(cluster)) {
        err = get_next_cluster_num(fat, cluster, &next_cluster);
        RETURN_IF_ERR(err);
        err = set_fat_entry(fat, cluster, 0);
        RETURN_IF_ERR(err);
        cluster = next_cluster;
    }
    return SYS_ERR_OK;
}


/* Operations on directory entries */

errval_t fat32_find_dirent(struct fat32_file_system *fat, struct dir_entry *parent,
                            char *filename, struct dir_entry *res)
{
    errval_t err;
    if (!is_dir(&parent->entry)) {
        return FS_ERR_NOTDIR;
    }

    char fat_name[11];
    err = str_to_fat_name(fat_name, filename);
    RETURN_IF_ERR(err);

    uint32_t cluster_num = get_first_cluster_num(&parent->entry);
    while (cluster_num_is_valid(cluster_num)) {
        uint32_t base_sector = cluster_to_sector(fat, cluster_num);

        // TODO: Optimize (read cluster at a time).
        for (uint32_t sec_idx = 0; sec_idx < fat->bpb.sec_per_clus; sec_idx++) {
            struct FAT_DIRENT entries[DIRENT_PER_SECTOR];

            err = read_from_sd(&fat->sd, entries, base_sector + sec_idx, SECTOR_SIZE);
            RETURN_IF_ERR(err);

            for (int dir_idx = 0; dir_idx < DIRENT_PER_SECTOR; dir_idx++) {
                if (is_end_of_dir(&entries[dir_idx])) {
                    return FS_ERR_NOTFOUND;
                }
//                DEBUG_PRINTF("looking at entry: %.11s\n", entries[dir_idx].name);
                if (memcmp(fat_name, entries[dir_idx].name, 11) == 0) {
                    if (res) {
                        *res = (struct dir_entry) { .entry = entries[dir_idx],
                                                    .cluster = cluster_num,
                                                    .index = sec_idx * DIRENT_PER_SECTOR
                                                             + dir_idx };
                    }
//                    DEBUG_PRINTF("found entry: %s\n", entries[dir_idx].name);
                    return SYS_ERR_OK;
                }
            }
        }
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
    }

    return FS_ERR_NOTFOUND;
}

static errval_t write_back_dir_entry(struct fat32_file_system *fat,
                                     struct dir_entry *dir_entry)
{
    uint32_t sector = cluster_to_sector(fat, dir_entry->cluster);
    sector += dir_entry->index / DIRENT_PER_SECTOR;
    uint32_t offset = (dir_entry->index % DIRENT_PER_SECTOR) * sizeof(dir_entry->entry);
    return write_to_sd_offset(&fat->sd, sector, offset, &dir_entry->entry,
                              sizeof(dir_entry->entry));
}

static errval_t read_dir_entry(struct fat32_file_system *fat, struct dir_entry *ret_entry)
{
    uint32_t sector = cluster_to_sector(fat, ret_entry->cluster);
    sector += ret_entry->index / DIRENT_PER_SECTOR;
    uint32_t offset = (ret_entry->index % DIRENT_PER_SECTOR) * sizeof(ret_entry->entry);
    return read_from_sd_offset(&fat->sd, &ret_entry->entry, sector, offset,
                               sizeof(ret_entry->entry));
}

errval_t read_next_dir_after_offset(struct fat32_file_system *fat, struct dir_entry *parent, uint64_t idx, char **ret_name, uint64_t *ret_idx)
{
    errval_t err;
    if (!is_dir(&parent->entry)) return FS_ERR_NOTDIR;

    uint32_t cluster_num = get_first_cluster_num(&parent->entry);

    uint64_t offset = idx * sizeof(struct FAT_DIRENT);

    while (offset > fat->cluster_bytes && cluster_num_is_valid(cluster_num)) {
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
        offset -= fat->cluster_bytes;
    }

    uint64_t num_dir_read = 0;

    while (cluster_num_is_valid(cluster_num)) {
        uint32_t base_sector = cluster_to_sector(fat, cluster_num);
        uint32_t base_sec_idx = offset / SECTOR_SIZE;
        int base_dir_idx = (offset % SECTOR_SIZE) / sizeof (struct FAT_DIRENT);
        offset -= offset;

        for (uint32_t sec_idx = base_sec_idx; sec_idx < fat->bpb.sec_per_clus; sec_idx++) {
            struct FAT_DIRENT entries[DIRENT_PER_SECTOR];

            err = read_from_sd(&fat->sd, entries, base_sector + sec_idx, SECTOR_SIZE);
            RETURN_IF_ERR(err);

            for (int dir_idx = base_dir_idx; dir_idx < DIRENT_PER_SECTOR; dir_idx++) {
                num_dir_read += 1;

//                DEBUG_PRINTF("looking at entry: %.11s\n", entries[dir_idx].name);
                if (is_end_of_dir(&entries[dir_idx])) {
                    return FS_ERR_INDEX_BOUNDS;
                }
                if (!is_free(&entries[dir_idx])) {
                    if (ret_name) {
//                        *ret_name = malloc(12);
//                        memcpy(*ret_name, entries[dir_idx].name, 11);
//                        (*ret_name)[11] = '\0';
                        *ret_name = fat_name_to_str(entries[dir_idx].name);
                    }

                    if (ret_idx) {
                        *ret_idx = idx + num_dir_read - 1;
                    }
                    return SYS_ERR_OK;
                }
            }
            base_dir_idx = 0;
        }
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
    }

//    DEBUG_PRINTF("RETURNING CUZ END OF CLUSTERS\n");
    return FS_ERR_INDEX_BOUNDS;
}

// TODO: This is a hack that assumes cluster_bytes <= 4096.
static const char ZERO_CLUSTER[4096] = { 0 };
// TODO: Implement on SD driver level.
static errval_t fat32_zero_cluster(struct fat32_file_system *fat, uint32_t cluster_num)
{
    assert(cluster_num > 2);
    uint32_t start_sector = cluster_to_sector(fat, cluster_num);
    return write_to_sd_offset(&fat->sd, start_sector, 0, ZERO_CLUSTER, fat->cluster_bytes);
}

// TODO Test that this works when dir was empty and when dir exceeds a cluster.
// Note: this just creates the file, it does not check if the file already exists.
static errval_t write_dirent_to_empty_slot(struct fat32_file_system *fat,
                                           struct dir_entry *parent, struct dir_entry *ret_val)
{
    errval_t err;
    assert(is_dir(&parent->entry));
    assert(ret_val);


    uint32_t cluster_num = get_first_cluster_num(&parent->entry);
    assert(cluster_num_is_valid(cluster_num));

    volatile struct FAT_DIRENT *entries = (volatile struct FAT_DIRENT *)fat->sd.buf;
    uint32_t prev_cluster = cluster_num;
    while (cluster_num_is_valid(cluster_num)) {
        const uint32_t chunk_size = fat->cluster_bytes;
        err = fat32_read_from_cluster(fat, NULL, cluster_num, 0, fat->cluster_bytes);
        RETURN_IF_ERR(err);

        uint32_t i = 0;
//        DEBUG_PRINTF("chunk_size: %d\n", chunk_size);
        for (; i < (chunk_size / sizeof(struct FAT_DIRENT)); i++) {
            if (is_free((struct FAT_DIRENT*) &entries[i])) {
//                DEBUG_PRINTF("WRITING TO FOUND EMPTY SLOT %d\n", i);
                ret_val->cluster = cluster_num;
                ret_val->index = i;
                err = write_back_dir_entry(fat, ret_val);
                RETURN_IF_ERR(err);
                return err;
            }
        }

        prev_cluster = cluster_num;
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
    }

    err = alloc_cluster(fat, &cluster_num);
    RETURN_IF_ERR(err);
    err = set_fat_entry(fat, prev_cluster, cluster_num);
    RETURN_IF_ERR(err);
    ret_val->cluster = cluster_num;
    ret_val->index = 0;
    fat32_zero_cluster(fat, cluster_num);
    err = write_back_dir_entry(fat, ret_val);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

static errval_t dir_entry_cleanup_cluster(struct fat32_file_system *fat,
                                          uint32_t cluster_num, bool is_last,
                                          bool *ret_empty)
{
    assert(cluster_num_is_valid(cluster_num));
    errval_t err;

    int num_entries = fat->cluster_bytes / sizeof(struct FAT_DIRENT);
    for (int i = num_entries - 1; i >= 0 && is_last; i--) {
        struct dir_entry cur_entry;
        cur_entry.cluster = cluster_num;
        cur_entry.index = i;

        err = read_dir_entry(fat, &cur_entry);
        RETURN_IF_ERR(err);

        if (!is_free(&cur_entry.entry)) {
            if (ret_empty) {
                *ret_empty = false;
            }
            return SYS_ERR_OK;
        }
        if (is_last && cur_entry.entry.name[0] == 0xE5) {
            cur_entry.entry.name[0] = 0x00;
            err = write_back_dir_entry(fat, &cur_entry);
            RETURN_IF_ERR(err);
        }
    }
    if (ret_empty) {
        *ret_empty = true;
    }

    return SYS_ERR_OK;
}

static errval_t dir_entry_chain_cleanup(struct fat32_file_system *fat, uint32_t *cluster)
{
    errval_t err;
    uint32_t cluster_num = *cluster;
    if (!cluster_num_is_valid(cluster_num)) {
        return SYS_ERR_OK;
    }

    uint32_t next_cluster;
    err = get_next_cluster_num(fat, cluster_num, &next_cluster);
    RETURN_IF_ERR(err);
    uint32_t old_next_cluster = next_cluster;

    err = dir_entry_chain_cleanup(fat, &next_cluster);
    RETURN_IF_ERR(err);

    bool is_last = !cluster_num_is_valid(next_cluster);
    bool empty = false;
    err = dir_entry_cleanup_cluster(fat, cluster_num, is_last, &empty);
    RETURN_IF_ERR(err);

    if (empty) {
        *cluster = next_cluster;
        err = set_fat_entry(fat, cluster_num, 0);
        RETURN_IF_ERR(err);
    } else if (next_cluster != old_next_cluster) {
        err = set_fat_entry(fat, cluster_num, next_cluster);
        RETURN_IF_ERR(err);
    }

    return SYS_ERR_OK;
}

static errval_t dir_entry_cleanup(struct fat32_file_system *fat,
                                  struct dir_entry *dir_entry)
{
    errval_t err;
    // Cleanup Files.
    if (!is_dir(&dir_entry->entry)) {
        uint32_t first_cluster = get_first_cluster_num(&dir_entry->entry);
        if ((dir_entry->entry.file_size == 0) && cluster_num_is_valid(first_cluster)) {
            err = free_cluster_chain(fat, first_cluster);
            RETURN_IF_ERR(err);
        }
        dir_entry->entry.file_size = 0;
        set_first_cluster_num(&dir_entry->entry, EOC_INDICATOR);
        err = write_back_dir_entry(fat, dir_entry);
        return err;
    }

    // TODO: This leads to the root directory never being cleaned up which is technically a bug.
    if (dir_entry->cluster == 0 && dir_entry->index == 0) {
        return SYS_ERR_OK;
    }

    // Cleanup Directories.
    uint32_t first_cluster = get_first_cluster_num(&dir_entry->entry);
    uint32_t old_first_cluster = first_cluster;
    err = dir_entry_chain_cleanup(fat, &first_cluster);
    RETURN_IF_ERR(err);

    if (first_cluster != old_first_cluster) {
        set_first_cluster_num(&dir_entry->entry, first_cluster);
        err = write_back_dir_entry(fat, dir_entry);
        RETURN_IF_ERR(err);
    }

    return SYS_ERR_OK;
}


/* Exported Functions */

errval_t init_fat32_file_system(struct fat32_file_system *fat)
{
    errval_t err;

    err = init_sd_wrapper(&fat->sd);
    RETURN_IF_ERR(err);

    err = read_from_sd(&fat->sd, &fat->bpb, 0, sizeof(struct BPB));
    RETURN_IF_ERR(err);

    err = read_from_sd(&fat->sd, &fat->fs_info, fat->bpb.fs_info, sizeof(struct FS_INFO));
    RETURN_IF_ERR(err);
    fat->cluster_bytes = fat->bpb.sec_per_clus * SECTOR_SIZE;
    assert(fat->cluster_bytes <= FAT_BUFFER_SIZE && "Should allocate larger buffer.");

    fat->fat_sec_num = fat->bpb.rsvd_sec_cnt;
    fat->data_sec_num = fat->fat_sec_num + fat->bpb.num_fats * fat->bpb.fat_sz32;
    fat->root_dir_sec_num = cluster_to_sector(fat, fat->bpb.root_clus);

    memcpy(fat->root_dir.entry.name, "ROOT           ", 11);

    // Must be zero, we check this to see if it is the root cluster.
    fat->root_dir.index = 0;
    fat->root_dir.cluster = 0;

    fat->root_dir.entry.fst_clus_lo = 0xffff & fat->bpb.root_clus;
    fat->root_dir.entry.fst_clus_hi = fat->bpb.root_clus >> 16;
    fat->root_dir.entry.attr = FAT_ATTR_DIRECTORY;

    err = init_fat_cache(fat);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}


errval_t destroy_fat32_file_system(struct fat32_file_system *fat)
{
    // TODO
    return LIB_ERR_NOT_IMPLEMENTED;
}


errval_t fat32_resolve_path(struct fat32_file_system *fat, const char *path,
                            struct dir_entry *result)
{
    errval_t err;
    char *_path = strdup(path);

    const char *sep = "/";

//    DEBUG_PRINTF("resolve path: %s\n", _path);
    struct dir_entry entry = fat->root_dir;

    for (char *token = strtok(_path, sep); token != NULL; token = strtok(NULL, sep)) {
//        DEBUG_PRINTF("resolving token: '%s'\n", token);
        err = fat32_find_dirent(fat, &entry, token, &entry);
        GOTO_IF_ERR(err, cleanup);
    }
    if (result)
        *result = entry;

    err = SYS_ERR_OK;
cleanup:
    free(_path);
    return err;
}


errval_t fat32_read_from_cluster(struct fat32_file_system *fat, void *buf,
                                 uint32_t cluster_num, size_t offset, size_t bytes)
{
    assert(offset < fat->cluster_bytes && (offset + bytes) <= fat->cluster_bytes);

    uint32_t start_sector = cluster_to_sector(fat, cluster_num) + (offset / SECTOR_SIZE);

    return read_from_sd_offset(&fat->sd, buf, start_sector, offset % SECTOR_SIZE, bytes);
}


errval_t fat32_write_to_cluster(struct fat32_file_system *fat, uint32_t cluster_num,
                                size_t offset, void *buf, size_t bytes)
{

//    DEBUG_PRINTF("write to cluster: cluster %x, offset %d, bytes %d\n", cluster_num, offset, bytes);
    assert((offset < fat->cluster_bytes) && ((offset + bytes) <= fat->cluster_bytes));
    assert(cluster_num_is_valid(cluster_num));

    uint32_t start_sector = cluster_to_sector(fat, cluster_num) + (offset / SECTOR_SIZE);

    return write_to_sd_offset(&fat->sd, start_sector, offset % SECTOR_SIZE, buf, bytes);
}


errval_t fat32_read(struct fat32_file_system *fat, struct dir_entry *dir_entry, void *buf,
                    size_t pos, size_t bytes, size_t *ret_bytes)
{
    errval_t err;
//    DEBUG_PRINTF("reading from file\n");

    struct FAT_DIRENT *dirent = &dir_entry->entry;
    if (is_dir(dirent)) {
        return FS_ERR_NOTFILE;
    }
    size_t offset = pos;

    bytes = MIN(bytes, dirent->file_size - offset);
    size_t bytes_read = 0;
    uint32_t cluster_num = get_first_cluster_num(dirent);
//    DEBUG_PRINTF("first cluster num: %x\n", cluster_num);

    while (offset >= fat->cluster_bytes && cluster_num_is_valid(cluster_num)) {
//        DEBUG_PRINTF("walking to through the file: cluster_num : %x\n", cluster_num);
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
        offset -= fat->cluster_bytes;
    }
    if (!cluster_num_is_valid(cluster_num))
        return FS_ERR_INDEX_BOUNDS;

//    DEBUG_PRINTF("reached read position - cluster: %x, start reading\n", cluster_num);

    // Read all other chunks.
    while (bytes_read < bytes && cluster_num_is_valid(cluster_num)) {
        size_t chunk_bytes = MIN(bytes - bytes_read, fat->cluster_bytes - offset);
//        DEBUG_PRINTF("Reading %d bytes from cluster %d\n", chunk_bytes, cluster_num);
//        DEBUG_PRINTF("READ %u bytes from cluster %x with offset %u\n",  chunk_bytes, cluster_num, offset);
        err = fat32_read_from_cluster(fat, buf + bytes_read, cluster_num, offset, chunk_bytes);
        RETURN_IF_ERR(err);
        offset -= offset;
        bytes_read += chunk_bytes;
        err = get_next_cluster_num(fat, cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
    }

//    DEBUG_PRINTF("done reading (next cluster num would be: %x)\n", cluster_num);

    *ret_bytes = bytes_read;
    return SYS_ERR_OK;
}

errval_t fat32_readfile_to_frame(struct fat32_file_system *fat, struct dir_entry *dir_entry, struct capref frame, size_t *ret_bytes) {
    struct FAT_DIRENT *dirent = &dir_entry->entry;
    if (is_dir(dirent)) {
        return FS_ERR_NOTFILE;
    }

    lpaddr_t addr = cap_get_paddr(frame);
    lpaddr_t frame_size = cap_get_psize(frame);
    if (roundup2(dirent->file_size, fat->cluster_bytes) > frame_size) {
        return FS_ERR_INDEX_BOUNDS;
    }

    uint32_t cluster = get_first_cluster_num(dirent);
    size_t bytes_remaining = roundup2(dirent->file_size, fat->cluster_bytes);

    while (cluster_num_is_valid(cluster)) {
//        DEBUG_PRINTF("READING cluster %u , bytes_remaining %d\n", cluster, bytes_remaining);
        size_t chunk_bytes = fat->cluster_bytes;
        errval_t err = read_from_sd_to_paddr(&fat->sd, addr, cluster_to_sector(fat, cluster), chunk_bytes);
        RETURN_IF_ERR(err);

        bytes_remaining -= chunk_bytes;
        addr += fat->cluster_bytes;
        err = get_next_cluster_num(fat, cluster, &cluster);
        RETURN_IF_ERR(err);
    }
    DATA_BARRIER;
    INSTR_BARRIER;
    *ret_bytes = dirent->file_size - bytes_remaining;

    return SYS_ERR_OK;
}

// TODO: Handle errors gracefully.
errval_t fat32_write(struct fat32_file_system *fat, struct dir_entry *dir_entry,
                     void *buf, size_t pos, size_t bytes, size_t *ret_bytes)
{
//    DEBUG_PRINTF("writing to file\n");

    errval_t err;
    struct FAT_DIRENT *dirent = &dir_entry->entry;
    if (is_dir(dirent)) {
        return FS_ERR_NOTFILE;
    }
    if (bytes == 0)
        return SYS_ERR_OK;
    size_t offset = pos;

    assert(offset <= dirent->file_size);

    uint32_t cluster_num = get_first_cluster_num(dirent);
//    DEBUG_PRINTF("first cluster num: %x\n", cluster_num);

    // If the file is empty.
    if (cluster_num == 0 || !cluster_num_is_valid(cluster_num)) {
        assert(dirent->file_size == 0 && "No blocks are allocated, filesize must be 0.");
        err = alloc_cluster(fat, &cluster_num);
        RETURN_IF_ERR(err);
        set_first_cluster_num(dirent, cluster_num);
//        DEBUG_PRINTF("Setting first cluster to: %x\n", cluster_num);
    }

    uint32_t prev_cluster_num = cluster_num;
    while (offset >= fat->cluster_bytes) {
//        DEBUG_PRINTF("walking to through the file: cluster_num : %x\n", cluster_num);
        assert(cluster_num_is_valid(cluster_num));

        prev_cluster_num = cluster_num;
        err = get_next_cluster_num(fat, prev_cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
        offset -= fat->cluster_bytes;
    }
//    DEBUG_PRINTF("reached write position - cluster: %x, start writing\n", cluster_num);

    size_t bytes_written = 0;

    while (bytes_written < bytes) {
        if (!cluster_num_is_valid(cluster_num)) {
//            DEBUG_PRINTF("Cluster not valid, allocing new entry\n");
            err = alloc_cluster(fat, &cluster_num);
            RETURN_IF_ERR(err);
//            DEBUG_PRINTF("Set fat entry for %x to %x\n", prev_cluster_num, cluster_num);
            err = set_fat_entry(fat, prev_cluster_num, cluster_num);
            RETURN_IF_ERR(err);
        }

        size_t chunk_bytes = MIN(bytes - bytes_written, fat->cluster_bytes - offset);
//        DEBUG_PRINTF("Write %u bytes to cluster %x with offset %u\n",  chunk_bytes, cluster_num, offset);
        err = fat32_write_to_cluster(fat, cluster_num, offset, buf + bytes_written,
                                     chunk_bytes);
        RETURN_IF_ERR(err);
        bytes_written += chunk_bytes;
        offset -= offset;

        prev_cluster_num = cluster_num;
        err = get_next_cluster_num(fat, prev_cluster_num, &cluster_num);
        RETURN_IF_ERR(err);
    }

    if (ret_bytes) {
        *ret_bytes = bytes_written;
    }

    dir_entry->entry.file_size = MAX(dir_entry->entry.file_size, pos + bytes_written);

//    DEBUG_PRINTF("write back dir entry\n");
    err = write_back_dir_entry(fat, dir_entry);
    RETURN_IF_ERR(err);

//    DEBUG_PRINTF("done writing\n");
    return SYS_ERR_OK;
}

errval_t fat32_trunc(struct fat32_file_system *fat, struct dir_entry *dir_entry,
                     size_t bytes ) {
    errval_t err;
    if (is_dir(&dir_entry->entry)) {
        return FS_ERR_NOTFILE;
    }
    if (dir_entry->entry.file_size < bytes) {
        return FS_ERR_INDEX_BOUNDS;
    }
    if (roundup2(dir_entry->entry.file_size, fat->cluster_bytes) == roundup2(bytes, fat->cluster_bytes)) {
        dir_entry->entry.file_size = bytes;
        err = write_back_dir_entry(fat, dir_entry);
        return err;
    }

    uint32_t first_cluster = get_first_cluster_num(&dir_entry->entry);

    if (bytes == 0) {
        if (cluster_num_is_valid(first_cluster)) {
            err = free_cluster_chain(fat, first_cluster);
            RETURN_IF_ERR(err);
        }
        set_first_cluster_num(&dir_entry->entry, EOC_INDICATOR);
        dir_entry->entry.file_size = bytes;
        err = write_back_dir_entry(fat, dir_entry);
        return err;
    }

    dir_entry->entry.file_size = bytes;

    uint32_t cluster = first_cluster;
    size_t offset = bytes;
    while (offset > fat->cluster_bytes) {
        assert(cluster_num_is_valid(cluster));
        err = get_next_cluster_num(fat, cluster, &cluster);
        RETURN_IF_ERR(err);
        offset -= fat->cluster_bytes;
    }
    uint32_t first_unused_cluster;
    err = get_next_cluster_num(fat, cluster, &first_unused_cluster);
    RETURN_IF_ERR(err);

    err = free_cluster_chain(fat, first_unused_cluster);
    RETURN_IF_ERR(err);

    err = set_fat_entry(fat, cluster, EOC_INDICATOR);
    RETURN_IF_ERR(err);

    err = write_back_dir_entry(fat, dir_entry);
    return err;
}

static struct dir_entry create_dot_dir_entry(struct dir_entry *self) {
    uint32_t own_cluster = get_first_cluster_num(&self->entry);
    struct dir_entry ret = (struct dir_entry) {
        .cluster = own_cluster,
        .index = 0,
        .entry = self->entry,
    };
    memcpy(ret.entry.name, ".          ", 11);
    return ret;
}

static struct dir_entry create_dot_dot_dir_entry(struct dir_entry *self, struct dir_entry *parent) {
    uint32_t own_cluster = get_first_cluster_num(&self->entry);
    struct dir_entry ret = (struct dir_entry) {
            .cluster = own_cluster,
            .index = 1,
            .entry = parent->entry,
    };
    memcpy(ret.entry.name, "..         ", 11);
    return ret;
}

static bool fat_name_is_reserved(char fat_name[11]) {
    return (memcmp(fat_name, ".           ", 11) == 0) || (memcmp(fat_name, "..         ", 11) == 0);
}

errval_t fat32_create_file(struct fat32_file_system *fat, struct dir_entry *parent,
                           char *name, uint8_t attr, struct dir_entry *ret)
{
    errval_t err;
    if (!is_dir(&parent->entry)) {
        return FS_ERR_NOTDIR;
    }

    err = str_to_fat_name(ret->entry.name, name);
    RETURN_IF_ERR(err);
    if (fat_name_is_reserved(ret->entry.name)) {
        return FS_ERR_PERMISSION_DENIED;
    }
//    DEBUG_PRINTF("Creating: \'%s\' :: \'%.11s\'\n", name, ret->entry.name);

    ret->entry.attr = attr;
    ret->entry.ntr_es = 0;          // Reserved for windows NT
    ret->entry.crt_time_tenth = 0;  // TODO
    //    ret->entry.reserved
    //    ret->entry.fst_clus_hi
    ret->entry.wrt_time = 0;  // TODO
    ret->entry.wrt_date = 0;  // TODO
    //    ret->entry.fst_clus_lo
    ret->entry.file_size = 0;

    if (attr & FAT_ATTR_DIRECTORY) {
        uint32_t first_cluster;
        err = alloc_cluster(fat, &first_cluster);
        RETURN_IF_ERR(err);
        set_first_cluster_num(&ret->entry, first_cluster);

        err = fat32_zero_cluster(fat, first_cluster);
        RETURN_IF_ERR(err);

        struct dir_entry dot = create_dot_dir_entry(ret);
        err = write_back_dir_entry(fat, &dot);
        RETURN_IF_ERR(err);
        struct dir_entry dot_dot = create_dot_dot_dir_entry(ret, parent);
        err = write_back_dir_entry(fat, &dot_dot);
        RETURN_IF_ERR(err);
    } else {
        set_first_cluster_num(&ret->entry, EOC_INDICATOR);
    }

    return write_dirent_to_empty_slot(fat, parent, ret);
}

errval_t fat32_delete_file(struct fat32_file_system *fat, struct dir_entry *parent,
                           struct dir_entry *dir_entry)
{
    if (fat_name_is_reserved(dir_entry->entry.name)) {
        return FS_ERR_PERMISSION_DENIED;
    }

//    DEBUG_PRINTF("Deleting %.11s\n", dir_entry->entry.name);

    errval_t err;
    if (is_dir(&dir_entry->entry)) {
        char *name = NULL;
        if ((dir_entry->cluster == 0) && (dir_entry->index == 0)) {
//            DEBUG_PRINTF("Can't delete root\n");
            return FS_ERR_PERMISSION_DENIED;
        }
        // Parent only has dot dirs if it is not the root.
        err = read_next_dir_after_offset(fat, dir_entry, 2, &name, NULL);
        if (err_no(err) != FS_ERR_INDEX_BOUNDS) {
            if (name) {
//                DEBUG_PRINTF("Still contains: %.11s\n", name);
            }
            return FS_ERR_NOTEMPTY;
        }
        free(name);
    }

    // Free all clusters
    err = free_cluster_chain(fat, get_first_cluster_num(&dir_entry->entry));
    RETURN_IF_ERR(err);

    dir_entry->entry.file_size = 0;
    set_first_cluster_num(&dir_entry->entry, 0x0fffffff);

    dir_entry->entry.name[0] = 0xE5;

    err = write_back_dir_entry(fat, dir_entry);
    RETURN_IF_ERR(err);

    dir_entry->index = 0;
    dir_entry->cluster = 0;

    err = dir_entry_cleanup(fat, parent);
    return err;
}
