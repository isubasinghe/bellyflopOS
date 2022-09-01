//
// Created by fooris on 18.05.22.
//

#ifndef BF_AOS_FAT32_INTERNAL_H
#define BF_AOS_FAT32_INTERNAL_H

#include "util.h"

#define FAT_DIRENT_FREE 0xe5
#define FAT_DIRENT_LAST_FREE 0x00

/****** BPB *****************************************************************************/

struct BPB {
    uint8_t bs_jmpBoot[3];
    char bs_oem_name[8];
    uint16_t bytes_per_sec;
    uint8_t sec_per_clus;
    uint16_t rsvd_sec_cnt;
    uint8_t num_fats;
    uint16_t root_ent_cnt;
    uint16_t tot_sec16;  // must be 0 for fat32
    uint8_t media;
    uint16_t fat_sz16;
    uint16_t sec_per_trk;
    uint16_t num_heads;
    uint32_t hidd_sec;  // count of hidden sectors preceding this partition.
    uint32_t tot_sec32;

    // ebpb32
    uint32_t fat_sz32;
    uint16_t ext_flags;
    uint16_t fs_ver;
    uint32_t root_clus;
    uint16_t fs_info;
    uint16_t bk_boot_sec;
    uint8_t reserved[12];
    uint8_t bs_drv_num;
    uint8_t bs_reserved1[1];
    uint8_t bs_boot_sig;
    uint32_t bs_vol_id;
    uint8_t bs_vol_lab[11];
    char bs_fil_sys_type[8];
} __attribute__((packed));
static_assert(sizeof(struct BPB) == 90);

struct FS_INFO {
    uint32_t lead_sig;  // 0x41614242
    uint8_t reserved[480];
    uint32_t struc_sig;   // 0x61417272
    uint32_t free_count;  // if 0xFFFFFFFF: unknown
    uint32_t nxt_free;
    char reserved1[12];
} __attribute__((packed));
static_assert(sizeof(struct FS_INFO) == 508);

/****** FAT32 Directory entries *********************************************************/

struct FAT_DIRENT {
    char name[11];  // name[0] = 0xe5 -> free, 0x00 free & last, 0x05 -> 0xe5
    uint8_t attr;
    uint8_t ntr_es;
    uint8_t crt_time_tenth;
    uint8_t reserved[6];
    uint16_t fst_clus_hi;
    uint16_t wrt_time;
    uint16_t wrt_date;
    uint16_t fst_clus_lo;
    uint32_t file_size;
} __attribute__((packed));
static_assert(sizeof(struct FAT_DIRENT) == 32);

#define DIRENT_PER_SECTOR (SECTOR_SIZE / sizeof(struct FAT_DIRENT))

__unused static bool is_dir(struct FAT_DIRENT *dir)
{
    return (dir->attr & 0x10) != 0;
}

__unused static bool is_end_of_dir(struct FAT_DIRENT *dir)
{
    return dir->name[0] == 0;
}

__unused static bool is_free(struct FAT_DIRENT *dir)
{
    return dir->name[0] == 0xE5 || dir->name[0] == 0;
}

__unused static uint32_t get_first_cluster_num(struct FAT_DIRENT *dir)
{
    return ((uint32_t)dir->fst_clus_hi << 16) | (uint32_t)dir->fst_clus_lo;
}

__unused static void set_first_cluster_num(struct FAT_DIRENT *dir, uint32_t val)
{
    dir->fst_clus_hi = val >> 16;
    dir->fst_clus_lo = val & ((1 << 16) - 1);
}

static bool forbidden_char_map[256] = {
    [0x22] = 1, [0x2a] = 1, 1, 1, [0x2e] = 1, 1, [0x3a] = 1, 1,
    1,          1,          1, 1, [0x5b] = 1, 1, 1,  // 0,0,
    [0x7c] = 1,
};

__unused static errval_t str_to_fat_name(char *fat_name, const char *str_in)
{
    memset(fat_name, ' ', 11);
    if (strcmp(str_in, "..") == 0) {
        fat_name[0] = '.';
        fat_name[1] = '.';
        return SYS_ERR_OK;
    } else if (strcmp(str_in, ".") == 0) {
        fat_name[0] = '.';
        return SYS_ERR_OK;
    }
    int i;
    for (i = 0; str_in[i] != '\0' && str_in[i] != '.'; i++) {
        if (i >= 8)
            return LIB_ERR_STRING_TOO_LONG;
        char c = str_in[i];
        if (forbidden_char_map[(uint8_t)c]) {
            DEBUG_PRINTF(">> STR TO FAT: character in forbidden map\n");
            return LIB_ERR_STRING_INVALID;
        }
        if (c == 0x05) {
            c = 0xe5;
        }
        fat_name[i] = char_to_upper(c);
    }
    if (fat_name[0] == ' ') {
        DEBUG_PRINTF(">> STR TO FAT: string starts with SPACE\n");
        return LIB_ERR_STRING_INVALID;
    }
    if (str_in[i] == '.') {
        i++;
        for (int j = 0; str_in[i] != '\0' && i < 12 && j < 3; i++, j++) {
            fat_name[8 + j] = char_to_upper(str_in[i]);
        }
    }
    if (str_in[i] != '\0') {
        DEBUG_PRINTF(">> STR TO FAT: string does not end here. was: %d\n", str_in[i]);
        return LIB_ERR_STRING_INVALID;
    }
    return SYS_ERR_OK;
}

__unused static char* fat_name_to_str(char fat_name[11]) {
    char *ret = malloc(13);
    int j = 0;
    for (int i = 0; i < 8; i++) {
        char c = fat_name[i];
        if (c != ' '){
            ret[j++] = c;
        }
    }
    if (fat_name[8] != ' ') {
        ret[j++] = '.';
        ret[j++] = fat_name[8];
    }
    if (fat_name[9] != ' ') {
        ret[j++] = fat_name[9];
    }
    if (fat_name[10] != ' ') {
        ret[j++] = fat_name[10];
    }
    ret[j] = '\0';

    return ret;
}

/****** FAT32 FAT entries ***************************************************************/

typedef uint32_t fat_entry_t;

#define FATENT_PER_SEC (SECTOR_SIZE / sizeof(fat_entry_t))
#define BAD_CLUSTER 0x0FFFFFF7
// If fat_entry is larger than this it is the last entry.
#define EOC_INDICATOR 0x0FFFFFF8

__unused static bool cluster_num_is_valid(uint32_t c)
{
    return (c > 0) && (c < EOC_INDICATOR);
}


#endif  // BF_AOS_FAT32_INTERNAL_H
