/**
 * \file
 * \brief file system test application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/systime.h>
#include <fs/fs.h>
#include <fs/dirent.h>

__unused static uint64_t systime_to_ms(systime_t time){
    return systime_to_us(time) / 1000;
}

#define ENABLE_LONG_FILENAME_TEST 1

/* reading */
#define MOUNTPOINT     "/sdcard"
#define SUBDIR         "/parent"
#define SUBDIR_LONG    "/parent-directory"
#define DIR_NOT_EXIST  "/not-exist"
#define FILENAME       "/myfile2.txt"
#define LONGFILENAME   "/mylongfilenamefile.txt"
#define LONGFILENAME2  "/mylongfilenamefilesecond.txt"
#define FILE_NOT_EXIST "/not-exist.txt"

#define TEST_PREAMBLE(arg) \
    DEBUG_PRINTF("\n-------------------------------\n"); \
    DEBUG_PRINTF("%s(%s)\n", __FUNCTION__, arg);

#define TEST_END \
    DEBUG_PRINTF("-------------------------------\n");

#define EXPECT_SUCCESS(err, test, _time) \
    do{ \
        if(err_is_fail(err)){ \
            DEBUG_ERR(err, test); \
        } else { \
            DEBUG_PRINTF("SUCCESS: " test " took %" PRIu64 " ms\n", _time);\
        }\
   } while(0);\

#define EXPECT_FAILURE(err, _test, _time) \
    do{ \
        if(err_is_fail(err)){ \
            DEBUG_PRINTF("SUCCESS: failure expected " _test " took %" PRIu64 " ms\n", _time);\
        } else { \
            DEBUG_ERR(err, "FAILURE: failure expected, but test succeeded" _test); \
        }\
   } while(0);\

#define run_test(fn, arg) \
    do { \
        tstart = systime_now(); \
        err = fn(arg); \
        tend = systime_now(); \
        EXPECT_SUCCESS(err, #fn, systime_to_ms(tend-tstart)); \
        TEST_END \
    } while(0); \

#define run_test_fail(fn, arg) \
    do { \
        tstart = systime_now(); \
        err = fn(arg); \
        tend = systime_now(); \
        EXPECT_FAILURE(err, #fn, systime_to_ms(tend-tstart)); \
        TEST_END \
    } while(0); \




__unused static errval_t test_read_dir(char *dir)
{
    errval_t err;

    TEST_PREAMBLE(dir)

    fs_dirhandle_t dh;
    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err;
    }

    assert(dh);

    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            goto err_out;
        }
        DEBUG_PRINTF("%s\n", name);
    } while(err_is_ok(err));

    return closedir(dh);
    err_out:
    return err;
}

__unused static errval_t test_fread(char *file)
{
    int res = 0;

    TEST_PREAMBLE(file)

    FILE *f = fopen(file, "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }

    /* obtain the file size */
    res = fseek (f , 0 , SEEK_END);
    if (res) {
        return FS_ERR_INVALID_FH;
    }

    size_t filesize = ftell (f);
    rewind (f);

    DEBUG_PRINTF("File size is %zu\n", filesize);

    char *buf = calloc(filesize + 2, sizeof(char));
    if (buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    size_t read = fread(buf, 1, filesize, f);

    DEBUG_PRINTF("read: %s\n", buf);

    if (read != filesize) {
        return FS_ERR_READ;
    }

    rewind(f);

    size_t nchars = 0;
    int c;
    do {
        c = fgetc (f);
        nchars++;
    } while (c != EOF);

    if (nchars < filesize) {
        return FS_ERR_READ;
    }

    free(buf);
    res = fclose(f);
    if (res) {
        return FS_ERR_CLOSE;
    }

    return SYS_ERR_OK;
}

__unused static errval_t test_fwrite(char *file)
{
    int res = 0;
    TEST_PREAMBLE(file)

    FILE *f = fopen(file, "w");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }

    const char *inspirational_quote = "I love deadlines. I like the whooshing "
        "sound they make as they fly by.";

    size_t written = fwrite(inspirational_quote, 1, strlen(inspirational_quote),
            f);
    DEBUG_PRINTF("wrote %zu bytes\n", written);

    if (written != strlen(inspirational_quote)) {
        return FS_ERR_READ;
    }

    res = fclose(f);
    if (res) {
        return FS_ERR_CLOSE;
    }

    return SYS_ERR_OK;
}




//#define BENCHMARK

#ifndef BENCHMARK
#include "filesystem_test.h"
#else
#include "filesystem_bench.h"
#endif

#include "aos/deferred.h"

int main(int argc, char *argv[])
{
    errval_t err;
//    uint64_t tstart, tend;

    barrelfish_usleep(8000000);
    DEBUG_PRINTF("Filereader test\n");

    DEBUG_PRINTF("initializing filesystem...\n");
    err = filesystem_init();
    EXPECT_SUCCESS(err, "fs init", 0);
//
//    run_test(test_read_dir, MOUNTPOINT "/");
//
//    run_test_fail(test_read_dir, DIR_NOT_EXIST);
//
//    run_test(test_fwrite, MOUNTPOINT FILENAME);
//
//    run_test(test_fread, MOUNTPOINT FILENAME);
#ifndef BENCHMARK
    RUN_TESTS(fs_test);
#else
    RUN_TESTS(fs_bench);
#endif

    return EXIT_SUCCESS;
}
