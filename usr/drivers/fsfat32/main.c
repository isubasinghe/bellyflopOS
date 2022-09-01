/**
 * \file
 * \brief File Subsystem.
 */

/*
 * Copyright (c) 2007, 2008, 2010, 2011, 2012,2020 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/nameserver.h>
#include <aos/macros.h>
#include <collections/hash_table.h>
#include <fcntl.h>

#include "fat32_file_system.h"

#ifdef FS_TESTS
#    include "tests.h"
#endif

#define MOUNTPOINT "/sdcard"
#define MOUNTPOINT_LEN 7

struct file_handle {
    char *path;
    struct dir_entry dir_entry;
    uint32_t num_accessors;
    bool has_writer;
};

static bool is_dir_handle(struct file_handle *file_handle)
{
    return is_dir(&file_handle->dir_entry.entry);
}

static struct file_handle *new_handle(const char *path)
{
    struct file_handle *handle = malloc(sizeof(struct file_handle));
    *handle = (struct file_handle) {
        .path = strdup(path),
        //        .dir_entry
        .num_accessors = 0,
        .has_writer = false,
    };
    return handle;
}

static void free_handle(void *file_handle)
{
    struct file_handle *h = file_handle;
    free(h->path);
    free(h);
}

static bool access_permitted(struct file_handle *handle, bool write)
{
    return !handle->has_writer && !(write && handle->num_accessors > 0);
}

static void add_access(struct file_handle *handle, bool write)
{
    handle->num_accessors += 1;
    handle->has_writer = write;
}

static uint32_t remove_access(struct file_handle *handle)
{
    assert(handle->num_accessors > 0);
    handle->num_accessors -= 1;
    handle->has_writer = false;

    return handle->num_accessors;
}

// TODO: Implement me.
static bool flags_is_write(int flags)
{
    return true;
}

struct server_state {
    bool up;
    struct fat32_file_system fat;
    collections_hash_table *open_files;  //
};

static unsigned long sdbm(const char *str)
{
    const unsigned char *s = (const unsigned char *)str;
    unsigned int hash = 0;
    int c;

    while ((c = *s++))
        hash = c + (hash << 6) + (hash << 16) - hash;

    return hash;
}

/*
 * Returns NULL if not found.
 * Internal: Sets key to where to try and insert the value into the hashmap.
 */
static struct file_handle *find_file_by_name(struct server_state *state, const char *path,
                                             uint64_t *key)
{
    uint64_t hash = sdbm(path);
    struct file_handle *res = collections_hash_find(state->open_files, hash);
    while (res != NULL) {
        if (strcmp(path, res->path) == 0) {
            break;
        }
        hash++;
        res = collections_hash_find(state->open_files, hash);
    }
    *key = hash;
    return res;
}

__unused static struct file_handle *find_file_by_key(struct server_state *state,
                                                     uint64_t key)
{
    return collections_hash_find(state->open_files, key);
}

// Panics if key already inserted.
// handle needs to be created with new_handle().
static void insert_file_handle(struct server_state *state, uint64_t key,
                               struct file_handle *handle)
{
    collections_hash_insert(state->open_files, key, handle);
}

static void delete_file_handle(struct server_state *state, uint64_t key)
{
    collections_hash_delete(state->open_files, key);
}

static errval_t handle_fs_open(struct server_state *state, const char *path, int flags,
                               uint64_t *fd, uint32_t *size)
{
    errval_t err;
//    DEBUG_PRINTF("handle fs open:\n");

    uint64_t key;
    // If not found, key is set to the next insertion point.
    struct file_handle *handle = find_file_by_name(state, path, &key);
    if (handle) {
//        DEBUG_PRINTF("handle fs open: found file\n");
        if (is_dir(&handle->dir_entry.entry))
            return FS_ERR_NOTFILE;

        if (access_permitted(handle, flags_is_write(flags))) {
            add_access(handle, flags_is_write(flags));
            *fd = key;
            *size = handle->dir_entry.entry.file_size;
            return SYS_ERR_OK;
        }
        return FS_ERR_BUSY;
    }
//    DEBUG_PRINTF("handle fs open: did not find file in open files\n");

    // Try to find the file.
    struct dir_entry file_dir_entry;
//    DEBUG_PRINTF("handle fs open: resolving path\n");
    err = fat32_resolve_path(&state->fat, path, &file_dir_entry);
    RETURN_IF_ERR(err);

    if (is_dir(&file_dir_entry.entry))
        return FS_ERR_NOTFILE;

    if (flags & O_TRUNC) {
//        DEBUG_PRINTF("handle fs open: truncating\n");
        err = fat32_trunc(&state->fat, &file_dir_entry, 0);
        RETURN_IF_ERR(err);
    }

    // Create new file handle and add to open_files.
//    DEBUG_PRINTF("handle fs open: create and insert new handle\n");
    handle = new_handle(path);
    handle->dir_entry = file_dir_entry;
    add_access(handle, flags_is_write(flags));
    insert_file_handle(state, key, handle);

    *fd = key;
    *size = handle->dir_entry.entry.file_size;
//    DEBUG_PRINTF("handle fs open: returning (fd %lu, size %lu)\n", *fd, *size);
    return SYS_ERR_OK;
}

static errval_t split_path(char *path, char **dir_path, char **filename){
    *filename = strrchr(path, '/');
    if (*filename == NULL) {
        return FS_ERR_BAD_PATH;
    }
    **filename = '\0';
    (*filename)++;
    *dir_path = path;
    return SYS_ERR_OK;
}

static errval_t handle_fs_create(struct server_state *state, const char *path, int flags,
                                 uint64_t *fd, bool dir)
{
    errval_t err;
    struct dir_entry file_dir_entry;
    err = fat32_resolve_path(&state->fat, path, &file_dir_entry);
    if (err_is_ok(err)) {
//        DEBUG_PRINTF("FS CREATE: File exists\n");
        return FS_ERR_EXISTS;
    }
    if (err_no(err) != FS_ERR_NOTFOUND) {
//        DEBUG_ERR(err, "some other error");
        return err;
    }

    char *path_copy = strdup(path);

    char *filename;
    char *dir_path;
    err = split_path(path_copy, &dir_path, &filename);
    GOTO_IF_ERR(err, cleanup);

    struct dir_entry parent;
    err = fat32_resolve_path(&state->fat, dir_path, &parent);
    GOTO_IF_ERR(err, cleanup);

    if (dir) {
        // Create Directory and return.
        uint8_t attr = FAT_ATTR_DIRECTORY;
        err = fat32_create_file(&state->fat, &parent, filename, attr, &file_dir_entry);
        goto cleanup;
    }

    // Create File and open it.
    uint8_t attr = 0;
    err = fat32_create_file(&state->fat, &parent, filename, attr, &file_dir_entry);
    GOTO_IF_ERR(err, cleanup);


    // Create new file handle and add to open_files.
    uint64_t key;
    // If not found, key is set to the next insertion point.
    struct file_handle *handle = find_file_by_name(state, path, &key);
    assert(handle == NULL);         // Yes we WANT handle to BE EQUAL to NULL.

    *fd = key;
    handle = new_handle(path);
    handle->dir_entry = file_dir_entry;
    add_access(handle, true);
    insert_file_handle(state, key, handle);

cleanup:
    free(path_copy);
    return err;
}


static errval_t handle_fs_delete_file(struct server_state *state, const char *path)
{
    errval_t err;
//    DEBUG_PRINTF("handle fs delete file: %s\n", path);

    uint64_t key;
    struct file_handle *handle = find_file_by_name(state, path, &key);
    if (handle != NULL) {
        return FS_ERR_BUSY;
    }
//    DEBUG_PRINTF("file is not busy, ... proceeding with deletion\n");

    char *path_copy = strdup(path);
    char *dir_path;
    char *filename;
    err = split_path(path_copy, &dir_path, &filename);
    GOTO_IF_ERR(err, cleanup);

//    DEBUG_PRINTF("dir_path: %s, filename: %s\n", dir_path, filename);

    struct dir_entry parent;
    struct dir_entry entry;
    err = fat32_resolve_path(&state->fat, dir_path, &parent);
    GOTO_IF_ERR(err, cleanup);

//    DEBUG_PRINTF("found parent directory: %.11s\n", parent.entry.name);

    err = fat32_find_dirent(&state->fat, &parent, filename, &entry);
    GOTO_IF_ERR(err, cleanup);

//    DEBUG_PRINTF("found file to delete: %.11s\n", entry.entry.name);

    err = fat32_delete_file(&state->fat, &parent, &entry);
//    DEBUG_IF_ERR(err, "fat32_delete_file");
//    DEBUG_PRINTF("Done\n");

cleanup:
    free(path_copy);
    return err;
}


static errval_t handle_fs_close(struct server_state *state, uint64_t fd)
{
    struct file_handle *handle = find_file_by_key(state, fd);
    RETURN_ERR_IF_NULL(handle, FS_ERR_NOTFOUND);

    if (remove_access(handle) == 0) {
        delete_file_handle(state, fd);
    }

    return SYS_ERR_OK;
}

static errval_t handle_fs_read(struct server_state *state, uint64_t key, size_t offset,
                               size_t bytes, uint8_t *buf, size_t *ret_bytes)
{
    errval_t err;
    struct file_handle *handle = find_file_by_key(state, key);
    RETURN_ERR_IF_NULL(handle, FS_ERR_NOTFOUND);
//    DEBUG_PRINTF("Reading %lu bytes from %s at offset %lu\n", bytes, handle->path, offset);

    err = fat32_read(&state->fat, &handle->dir_entry, buf, offset, bytes, ret_bytes);
    return err;
}

static errval_t handle_fs_readfile_to_frame(struct server_state *state, const char *path, struct capref frame, size_t *ret_bytes) {
    errval_t err;
    uint64_t key;
    struct file_handle *handle = find_file_by_name(state, path, &key);
    if (handle) {
//        DEBUG_PRINTF("handle fs open: found file\n");
        if (is_dir(&handle->dir_entry.entry))
            return FS_ERR_NOTFILE;

        if (!access_permitted(handle, false)) {
            return FS_ERR_BUSY;
        }
        err = fat32_readfile_to_frame(&state->fat, &handle->dir_entry, frame, ret_bytes);
        return err;
    }

    struct dir_entry file_dir_entry;
//    DEBUG_PRINTF("handle fs read file to frame: resolving path\n");
    err = fat32_resolve_path(&state->fat, path, &file_dir_entry);
    RETURN_IF_ERR(err);

    if (is_dir(&file_dir_entry.entry))
        return FS_ERR_NOTFILE;

    err = fat32_readfile_to_frame(&state->fat, &file_dir_entry, frame, ret_bytes);
    return err;
}

static errval_t handle_fs_write(struct server_state *state, uint64_t key, size_t offset,
                                size_t bytes, uint8_t *buf, size_t *ret_bytes)
{
    errval_t err;
    struct file_handle *handle = find_file_by_key(state, key);
    RETURN_ERR_IF_NULL(handle, FS_ERR_NOTFOUND);

    if (!handle->has_writer) {
        return FS_ERR_PERMISSION_DENIED;
    }

    err = fat32_write(&state->fat, &handle->dir_entry, buf, offset, bytes, ret_bytes);
    return err;
}

static errval_t handle_fs_trunc(struct server_state *state, uint64_t key, size_t bytes)
{
    errval_t err;
    struct file_handle *handle = find_file_by_key(state, key);
    RETURN_ERR_IF_NULL(handle, FS_ERR_NOTFOUND);

    if (!handle->has_writer) {
        return FS_ERR_PERMISSION_DENIED;
    }

    err = fat32_trunc(&state->fat, &handle->dir_entry, bytes);
    return err;
}

static errval_t handle_fs_opendir(struct server_state *state, const char *path,
                                  uint64_t *fd)
{
    errval_t err;

    uint64_t key;
    // If not found, key is set to the next insertion point.
    struct file_handle *handle = find_file_by_name(state, path, &key);
    if (handle) {
        if (!is_dir(&handle->dir_entry.entry))
            return FS_ERR_NOTDIR;

        if (access_permitted(handle, false)) {
            add_access(handle, false);
            *fd = key;
            return SYS_ERR_OK;
        }
        return FS_ERR_BUSY;
    }

    // Try to find the file.
    struct dir_entry file_dir_entry;
    err = fat32_resolve_path(&state->fat, path, &file_dir_entry);
    RETURN_IF_ERR(err);

    if (!is_dir(&file_dir_entry.entry))
        return FS_ERR_NOTDIR;

    // Create new file handle and add to open_files.
    handle = new_handle(path);
    handle->dir_entry = file_dir_entry;
    add_access(handle, false);
    insert_file_handle(state, key, handle);

    *fd = key;
    return SYS_ERR_OK;
}

static errval_t handle_fs_readnextdir(struct server_state *state, uint64_t fd,
                                      uint64_t idx, char **ret_buffer, uint64_t *ret_idx)
{
    struct file_handle *handle = find_file_by_key(state, fd);
    RETURN_ERR_IF_NULL(handle, FS_ERR_NOTFOUND);

    if (!is_dir_handle(handle)) {
        return FS_ERR_NOTDIR;
    }

    return read_next_dir_after_offset(&state->fat, &handle->dir_entry, idx, ret_buffer, ret_idx);
}

static const char *sanitize_raw_path(const char *path)
{
    if (strncmp(path, MOUNTPOINT "/", MOUNTPOINT_LEN + 1) != 0) {
        return NULL;
    }
    return path + MOUNTPOINT_LEN;
}

static errval_t fs_handler(void *server_state, RpcMethod method,
                           RpcRequestWrap *request_wrap, struct capref request_cap,
                           RpcResponseWrap *response_wrap, struct capref *response_cap)
{
    errval_t err;
    struct server_state *state = server_state;
    if (!state->up) {
        return FS_ERR_NOTFOUND;
    }

    switch (method) {
    case RPC_METHOD__FS_OPEN: {
//        DEBUG_PRINTF(YELLOW "FS OPEN CALLED\n" COLOR_RESET);
        const char *path = sanitize_raw_path(request_wrap->fs_open->path);
        RETURN_ERR_IF_NULL(path, FS_ERR_BAD_PATH);

//        DEBUG_PRINTF(YELLOW "FS OPEN path: %s\n" COLOR_RESET, path);

        uint64_t fd;
        uint32_t size;
        err = handle_fs_open(state, path, request_wrap->fs_open->flags, &fd, &size);
//        DEBUG_IF_ERR(err, "handle_fs_open\n");
        RETURN_IF_ERR(err);
        response_wrap->fs_open = malloc(sizeof(FSOpenResponse));
        fsopen_response__init(response_wrap->fs_open);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_OPEN;
        response_wrap->fs_open->fd = fd;
        response_wrap->fs_open->size = size;
        return SYS_ERR_OK;
    }
    case RPC_METHOD__FS_CREATE: {
//        DEBUG_PRINTF(YELLOW "FS CREATE CALLED\n" COLOR_RESET);
        const char *path = sanitize_raw_path(request_wrap->fs_open->path);
        RETURN_ERR_IF_NULL(path, FS_ERR_BAD_PATH);

        uint64_t fd = 0;
        err = handle_fs_create(state, path, request_wrap->fs_create->flags, &fd, request_wrap->fs_create->dir);
//        DEBUG_IF_ERR(err, "handle_fs_create\n");
        RETURN_IF_ERR(err);

        assert((!!request_wrap->fs_create->dir) ^ (!!fd));

        response_wrap->fs_create = malloc(sizeof(FSCreateResponse));
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_CREATE;
        fscreate_response__init(response_wrap->fs_create);
        response_wrap->fs_create->fd = fd;
        return SYS_ERR_OK;
    }
    case RPC_METHOD__FS_DELETE: {
//        DEBUG_PRINTF(YELLOW "FS DELETE CALLED\n" COLOR_RESET);
        const char *path = sanitize_raw_path(request_wrap->fs_delete->path);
        RETURN_ERR_IF_NULL(path, FS_ERR_BAD_PATH);

        err = handle_fs_delete_file(state, path);
//        DEBUG_IF_ERR(err, "handle_fs_delete\n");
        return err;
    }
    case RPC_METHOD__FS_CLOSE: {
//        DEBUG_PRINTF(YELLOW "FS CLOSE CALLED\n" COLOR_RESET);
        err = handle_fs_close(state, request_wrap->fs_close->fd);
//        DEBUG_IF_ERR(err, "handle_fs_close\n");
        return err;
    }
    case RPC_METHOD__FS_READ: {
//        DEBUG_PRINTF(YELLOW "FS READ CALLED\n" COLOR_RESET);
        uint8_t *data = malloc(request_wrap->fs_read->size);
        size_t len;
        err = handle_fs_read(state, request_wrap->fs_read->fd,
                             request_wrap->fs_read->offset, request_wrap->fs_read->size,
                             data, &len);
//        DEBUG_IF_ERR(err, "handle_fs_read\n");
        if (err_is_fail(err)) {
            free(data);
            return err;
        }
        response_wrap->fs_read = malloc(sizeof(FSReadResponse));
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_READ;
        fsread_response__init(response_wrap->fs_read);
        response_wrap->fs_read->raw_bytes.data = data;
        response_wrap->fs_read->raw_bytes.len = len;
        return SYS_ERR_OK;
    }
    case RPC_METHOD__FS_READFILE_TO_FRAME: {
        size_t len;
        struct capability c;
        err = cap_direct_identify(request_cap, &c);
        RETURN_IF_ERR(err);
        assert(c.type == ObjType_Frame);

//        DEBUG_PRINTF(YELLOW "FS READ FILE TO FRAME CALLED\n" COLOR_RESET);
        const char *path = sanitize_raw_path(request_wrap->fs_read_file_to_frame->path);
        RETURN_ERR_IF_NULL(path, FS_ERR_BAD_PATH);

//        DEBUG_PRINTF(YELLOW "FS read_file_to_frame path: %s\n" COLOR_RESET, path);

        err = handle_fs_readfile_to_frame(state, path, request_cap, &len);
//        DEBUG_IF_ERR(err, "handle_fs_readfile_to_frame\n");
        RETURN_IF_ERR(err);

        response_wrap->fs_read_file_to_frame = malloc(sizeof(FSReadFileToFrameResponse));
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_READ_FILE_TO_FRAME;
        fsread_file_to_frame_response__init(response_wrap->fs_read_file_to_frame);
        response_wrap->fs_read_file_to_frame->bytes = len;
        return SYS_ERR_OK;
    }

    case RPC_METHOD__FS_WRITE: {
//        DEBUG_PRINTF(YELLOW "FS WRITE CALLED\n" COLOR_RESET);
        size_t len;
        err = handle_fs_write(state, request_wrap->fs_write->fd,
                              request_wrap->fs_write->offset,
                              request_wrap->fs_write->raw_bytes.len,
                              request_wrap->fs_write->raw_bytes.data, &len);
//        DEBUG_IF_ERR(err, "handle_fs_write\n");
        RETURN_IF_ERR(err);

        response_wrap->fs_write = malloc(sizeof(FSWriteResponse));
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_WRITE;
        fswrite_response__init(response_wrap->fs_write);
        response_wrap->fs_write->bytes = len;
        return SYS_ERR_OK;
    }
    case RPC_METHOD__FS_TRUNC: {
//        DEBUG_PRINTF(YELLOW "FS TRUNC CALLED\n" COLOR_RESET);
        err = handle_fs_trunc(state, request_wrap->fs_trunc->fd,
                              request_wrap->fs_trunc->bytes);
//        DEBUG_IF_ERR(err, "handle_fs_trunc\n");
        return err;
    }
    case RPC_METHOD__FS_OPENDIR: {
//        DEBUG_PRINTF(YELLOW "FS OPENDIR CALLED\n" COLOR_RESET);
        const char *path = sanitize_raw_path(request_wrap->fs_open->path);
        RETURN_ERR_IF_NULL(path, FS_ERR_BAD_PATH);

        uint64_t fd;
        err = handle_fs_opendir(state, path, &fd);
//        DEBUG_IF_ERR(err, "handle_fs_opendir\n");
        RETURN_IF_ERR(err);
        response_wrap->fs_open = malloc(sizeof(FSOpenResponse));
        fsopen_response__init(response_wrap->fs_open);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_OPEN;
        response_wrap->fs_open->fd = fd;
        response_wrap->fs_open->size = 0;
        return SYS_ERR_OK;
    }
    case RPC_METHOD__FS_READNEXTDIR: {
        char *name;
        uint64_t ret_idx;
        err = handle_fs_readnextdir(state, request_wrap->fs_readnextdir->fd,
                                    request_wrap->fs_readnextdir->pos, &name, &ret_idx);
//        DEBUG_IF_ERR(err, "handle_fs_readnextdir\n");
        RETURN_IF_ERR(err);
        response_wrap->fs_readnextdir = malloc(sizeof(FSReadNextDirResponse));
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_FS_READNEXTDIR;
        fsread_next_dir_response__init(response_wrap->fs_readnextdir);
        response_wrap->fs_readnextdir->name = name;
        response_wrap->fs_readnextdir->idx = ret_idx;
        return SYS_ERR_OK;
    }
    default:
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    return SYS_ERR_OK;
}

//#define BENCHMARK

#ifdef BENCHMARK
#include "benchmarks/sd_card_bench.h"
//#include "benchmarks/fat32_lib_bench.h"
#endif

int main(void)
{
    errval_t err;

    struct server_state *state = malloc(sizeof(struct server_state));

//    DEBUG_PRINTF(MAGENTA "SETTING UP FILESYSTEM SERVER\n" COLOR_RESET);

    err = init_fat32_file_system(&state->fat);
    if (err_is_fail(err)) {
//        USER_PANIC_ERR(err, "Failed to init file system\n");
        state->up = false;
    } else {

#ifdef BENCHMARK
    setup_sd_bench(&state->fat.sd);
    RUN_TESTS(sd_bench);

//    setup_fat32_lib_bench(state);
//    RUN_TESTS(fat32_lib_bench);
#endif

        collections_hash_create(&state->open_files, free_handle);
        state->up = true;
    }



    err = nameservice_register_proto("FS" MOUNTPOINT, fs_handler, state);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Failed to register nameservice\n");
    }

//    DEBUG_PRINTF(MAGENTA "SETTING UP FILESYSTEM SERVER DONE\n" COLOR_RESET);

    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }

    return 0;
}
