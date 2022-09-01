#ifndef BF_AOS_FILESYSTEM_TEST_H
#define BF_AOS_FILESYSTEM_TEST_H

#include <aos/test_utils.h>

#define SIZE 8000

char input[SIZE];
char output[SIZE];

//CREATE_TEST(create_write_read_large_file, fs_test, {
//    for (int i = 0; i < SIZE; i++) {
//        input[i] = 'a' + (i % ('z' - 'a' + 1));
//    }
//    memset(output, 0, 8000);
//
//    char *filename = "/sdcard/test2.txt";
//    FILE *f = fopen(filename, "w+");
//    TEST_REQUIRE(f != NULL);
//
//    size_t written = fwrite(input, 1, SIZE, f);
//    TEST_REQUIRE(written == SIZE);
//
//    DEBUG_PRINTF("writing done, now reading\n");
//
//    rewind(f);
//
//    size_t read = fread(output, 1, SIZE, f);
//    DEBUG_PRINTF("READ: %d\n", read);
//    TEST_REQUIRE(read == SIZE);
//
//    TEST_REQUIRE(memcmp(input, output, SIZE) == 0);
//
//    DEBUG_PRINTF("Closing file\n", read);
//    int res = fclose(f);
//    TEST_REQUIRE(res == 0);
//
//    rm(filename);
//})

#define TESTDIR "/sdcard/testdir"
#define NUM_FILES 2

CREATE_TEST(create_many_files, fs_test, {
    errval_t err;
    err = rmdir(TESTDIR);
    TEST_REQUIRE_FAIL_WITH(err, FS_ERR_NOTFOUND);

    err = mkdir(TESTDIR);
    TEST_REQUIRE_OK(err);

    err = mkdir(TESTDIR);
    TEST_REQUIRE_FAIL_WITH(err, FS_ERR_EXISTS);

    char name [60] = {0};
    for (int i = 0; i < NUM_FILES; i++) {
        sprintf(name, TESTDIR "/%02d_%s", i, "file.txt");
        FILE *f = fopen(name, "w");
        fwrite(name, 1, strlen(name), f);
        fclose(f);
    }

    fs_dirhandle_t handle;
    opendir(TESTDIR, &handle);
    char *filename;

    err = readdir(handle, &filename);
    TEST_REQUIRE_OK(err);
    free(filename);
    err = readdir(handle, &filename);
    TEST_REQUIRE_OK(err);
    free(filename);

    for (int i = 0; i < NUM_FILES; i++) {
        err = readdir(handle, &filename);
        TEST_REQUIRE_OK(err);
        DEBUG_PRINTF("filename = %s\n", filename);
        sprintf(name, TESTDIR "/%s", filename);
        DEBUG_PRINTF("path = %s", name);
        rm(name);
        free(filename);
    }

    filename = NULL;
    err = readdir(handle, &filename);
    TEST_REQUIRE_FAIL_WITH(err, FS_ERR_INDEX_BOUNDS);
    free(filename);

    closedir(handle);

    err = rmdir(TESTDIR);
    TEST_REQUIRE_OK(err);
})

CREATE_TEST(create_dot_file, fs_test, {
    errval_t err;
    err = mkdir("/sdcard/.");
    TEST_REQUIRE_FAIL_WITH(err, FS_ERR_PERMISSION_DENIED);

    err = mkdir("/sdcard/..");
    TEST_REQUIRE_FAIL_WITH(err, FS_ERR_PERMISSION_DENIED);

    FILE *f = fopen("/sdcard/..", "w");
    TEST_REQUIRE(f == NULL);
})

#include <fs/fatfs.h>
#include "aos/cache.h"
//CREATE_TEST(_hello_read_to_frame, fs_test, {
//    struct capref frame;
//    size_t ret_bytes;
//    errval_t err = frame_alloc(&frame, 800 * 1024, &ret_bytes);
//    TEST_REQUIRE_OK(err);
//    TEST_REQUIRE(ret_bytes >= 800 * 1024);
//
//    err = fatfs_read_file_to_frame(_st, "/sdcard/hello", frame, &ret_bytes);
//    TEST_REQUIRE_OK(err);
//
//    volatile uint16_t *buf;
//    paging_map_frame_complete(get_current_paging_state(), (void**) &buf, frame);
//    DATA_BARRIER;
//    cpu_dcache_wbinv_range((lvaddr_t)buf, ret_bytes);
//
//    for (int i = 0 ; i < (ret_bytes/2 - 8); i+=8) {
//        uint64_t offset = i * 2;
//        DEBUG_PRINTF("%07x %04x %04x %04x %04x %04x %04x %04x %04x\n", offset, buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
//    }
//
//
//})

//CREATE_TEST(_hello_, fs_test, {
//    DEBUG_PRINTF("Running test %s\n", __func__);
//    char *filename = "/sdcard/hello";
//    FILE *f = fopen(filename, "r");
//    TEST_REQUIRE(f != NULL);
//
//    fseek(f, 0, SEEK_END);
//
//    int filesize = ftell(f);
//    rewind(f);
//    DEBUG_PRINTF("filesize: %d\n", filesize);
//
//    volatile uint16_t * buf = malloc(filesize);
//
//    fread((void*) buf, 1, filesize, f);
//
//    for (int i = 0 ; i < (filesize/2 - 8); i+=8) {
//        uint64_t offset = i * 2;
//        DEBUG_PRINTF("%07x %04x %04x %04x %04x %04x %04x %04x %04x\n", offset, buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
//    }
//    fclose(f);
//})


#endif //BF_AOS_FILESYSTEM_TEST_H
