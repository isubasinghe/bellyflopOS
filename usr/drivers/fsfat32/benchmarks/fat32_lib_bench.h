//
// Created by fooris on 01.06.22.
//

#ifndef BF_AOS_FAT32_LIB_BENCH_H
#define BF_AOS_FAT32_LIB_BENCH_H

#include <aos/aos.h>
#include <aos/test_utils.h>
#include <aos/systime.h>

#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>

#define DATA_BARRIER __asm volatile("dmb sy\n")
#define INSTR_BARRIER __asm volatile("isb sy\n")

#undef TIME
#define TIME(t) do {                    \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
    *(t) = systime_now();                 \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
} while(0)

#define NUM_ITERATIONS 30

static struct server_state *fat32_bench_state;

static void setup_fat32_lib_bench(struct server_state *state) {
    fat32_bench_state = state;
}

CREATE_TEST(read_one_cluster, fat32_lib_bench, {
    DEBUG_PRINTF(YELLOW "START %s\n" COLOR_RESET, __func__);
    struct fat32_file_system *fat = &fat32_bench_state->fat;

    DEBUG_PRINTF("reading one cluster: %llu bytes\n", fat->cluster_bytes);

    volatile void *buffer = malloc(fat->cluster_bytes);

    DEBUG_PRINTF("i \t first read in ns \t second read in ns\n");
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        struct dir_entry entry;
        char name[30];
        sprintf(name, "/bench/input%d.txt", i);
        fat32_resolve_path(fat, name, &entry);

        systime_t start_time;
        systime_t end_time;
        size_t ret_bytes;
        TIME(&start_time);
        fat32_read(fat, &entry, (void*) buffer, 0, fat->cluster_bytes, &ret_bytes);
        TIME(&end_time);
        uint64_t diff_first = systime_to_ns(end_time) - systime_to_ns(start_time);

        TIME(&start_time);
        fat32_read(fat, &entry, (void*) buffer, 0, fat->cluster_bytes, &ret_bytes);
        TIME(&end_time);
        uint64_t diff_second = systime_to_ns(end_time) - systime_to_ns(start_time);

        DEBUG_PRINTF("%02d: %llu; %llu;\n", i, diff_first, diff_second);
    }

    free((void*) buffer);
    DEBUG_PRINTF(YELLOW "END %s\n" COLOR_RESET, __func__);
})

//CREATE_TEST(read_large_file, fat32_lib_bench, {
//    DEBUG_PRINTF(YELLOW "START %s\n" COLOR_RESET, __func__);
//    struct fat32_file_system *fat = &fat32_bench_state->fat;
//
//    errval_t err;
//    struct dir_entry entry;
//    err = fat32_resolve_path(fat, "/bench/input.txt", &entry);
//    TEST_REQUIRE_OK(err);
//    TEST_REQUIRE(entry.entry.file_size >= 5 * fat->cluster_bytes);
//    DEBUG_PRINTF("reading file size: %llu bytes\n", entry.entry.file_size);
//
//    volatile void *buffer = malloc(entry.entry.file_size);
//    TEST_REQUIRE(buffer != NULL);
//
//    for (int i = 0; i < NUM_ITERATIONS; i++) {
//        systime_t start_time;
//        systime_t end_time;
//        size_t ret_bytes;
//
//        TIME(&start_time);
//        fat32_read(fat, &entry, (void*) buffer, 0, entry.entry.file_size, &ret_bytes);
//        TIME(&end_time);
//        DEBUG_PRINTF("%d: %llu ns\n", i, systime_to_ns(end_time) - systime_to_ns(start_time));
//    }
//
//
//    free((void*) buffer);
//    DEBUG_PRINTF(YELLOW "END %s\n" COLOR_RESET, __func__);
//})
//
//CREATE_TEST(create_append_delete_file, fat32_lib_bench, {
//    DEBUG_PRINTF(YELLOW "START %s\n" COLOR_RESET, __func__);
//    struct fat32_file_system *fat = &fat32_bench_state->fat;
//
//    errval_t err;
//    struct dir_entry parent;
//    err = fat32_resolve_path(fat, "bench", &parent);
//    DEBUG_IF_ERR(err, "resolving path\n");
//    TEST_REQUIRE_OK(err);
//
//    char buf[8192] = {1};
//
//    DEBUG_PRINTF("i  \t creation time in ns \t append time in ns \t find file time in ns\t deletion time in ns\n");
//    for (int i = 0; i < NUM_ITERATIONS; i++) {
//        systime_t start_time;
//        systime_t end_time;
//        char name[40];
//        sprintf(name, "test_%d.txt", i);
//        struct dir_entry entry;
//        struct dir_entry second_entry;
//
//        TIME(&start_time);
//        err |= fat32_create_file(fat, &parent, name, 0, &entry);
//        TIME(&end_time);
//        uint64_t diff_create = systime_to_ns(end_time) - systime_to_ns(start_time);
//
//        TIME(&start_time);
//        err |= fat32_write(fat, &entry, buf, 0, fat->cluster_bytes, NULL);
//        TIME(&end_time);
//        uint64_t diff_append = systime_to_ns(end_time) - systime_to_ns(start_time);
//
//        TIME(&start_time);
//        err |= fat32_find_dirent(fat, &parent, name, &second_entry);
//        TIME(&end_time);
//        uint64_t diff_find = systime_to_ns(end_time) - systime_to_ns(start_time);
//
//        TIME(&start_time);
//        err |= fat32_delete_file(fat, &parent, &entry);
//        TIME(&end_time);
//        uint64_t diff_delete = systime_to_ns(end_time) - systime_to_ns(start_time);
//
//        DEBUG_PRINTF("%02d:\t%015lu;\t%015lu;\t%015lu;\t%015lu\n", i, diff_create, diff_append, diff_find, diff_delete);
//    }
//
//    TEST_REQUIRE_OK(err);
//
//    DEBUG_PRINTF(YELLOW "END %s\n" COLOR_RESET, __func__);
//})


#endif //BF_AOS_FAT32_LIB_BENCH_H
