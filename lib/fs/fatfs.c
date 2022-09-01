#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>

#include <fs/fs.h>
#include <fs/fatfs.h>
#include <string.h>
#include <fcntl.h>

#include "fs_internal.h"
#include "aos/deferred.h"

/**
 * @brief a handle to the open fatfs file
 */
struct fatfs_handle {
    char *path;
    uint64_t fd;
    size_t size;

    bool is_dir;
    size_t pos;
};

errval_t fatfs_open(void *st, const char *path, int flags, fatfs_handle_t *rethandle)
{
    errval_t err;
    nameservice_chan_t chan = st;
    FSOpenRequest req = FSOPEN_REQUEST__INIT;
    req.path = (char *)path;
    req.flags = flags;

    REQUEST_WRAP(req_wrap, fs_open, FS_OPEN, &req);
    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_OPEN, &req_wrap, NULL_CAP, &response,
                                NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_OPEN);

    struct fatfs_handle *handle = malloc(sizeof(struct fatfs_handle));

    handle->path = strdup(path);
    handle->fd = response->fs_open->fd;
    handle->size = response->fs_open->size;
    handle->is_dir = false;
    handle->pos = 0;

    *rethandle = handle;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);

    return err;
}

errval_t fatfs_create(void *st, const char *path, int flags, fatfs_handle_t *rethandle)
{
//    DEBUG_PRINTF("FATFS CREATE\n");
    errval_t err;
    assert(flags & O_CREAT);

    nameservice_chan_t chan = st;
    FSCreateRequest req = FSCREATE_REQUEST__INIT;
    req.path = (char *)path;
    req.flags = flags;
    req.dir = false;

    REQUEST_WRAP(req_wrap, fs_create, FS_CREATE, &req);
    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_CREATE, &req_wrap, NULL_CAP,
                                &response, NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_CREATE);

    struct fatfs_handle *handle = malloc(sizeof(struct fatfs_handle));

    handle->path = strdup(path);
    handle->fd = response->fs_create->fd;
    handle->size = 0;
    handle->is_dir = false;
    handle->pos = 0;

    *rethandle = handle;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);

    return err;
}

errval_t fatfs_close(void *st, fatfs_handle_t inhandle)
{
    struct fatfs_handle *handle = inhandle;
    if (handle->is_dir) {
        return FS_ERR_NOTFILE;
    }

    nameservice_chan_t chan = st;
    FSCloseRequest req = FSCLOSE_REQUEST__INIT;
    req.fd = handle->fd;

    REQUEST_WRAP(req_wrap, fs_close, FS_CLOSE, &req);
    errval_t err = nameservice_rpc_proto(chan, RPC_METHOD__FS_CLOSE, &req_wrap, NULL_CAP,
                                         NULL, NULL);
    RETURN_IF_ERR(err_pop(err));
    RETURN_IF_ERR(err);

    free(handle->path);
    free(handle);

    return SYS_ERR_OK;
}

errval_t fatfs_remove(void *st, const char *path)
{
    errval_t err;

    nameservice_chan_t chan = st;
    FSDeleteRequest req = FSDELETE_REQUEST__INIT;
    req.path = (char *)path;
    REQUEST_WRAP(req_wrap, fs_delete, FS_DELETE, &req);

    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_DELETE, &req_wrap, NULL_CAP, NULL, NULL);
    RETURN_IF_ERR(err_pop(err));
    return err;
}

errval_t fatfs_read(void *st, fatfs_handle_t h, void *buffer, size_t bytes,
                    size_t *bytes_read)
{
    errval_t err;
    struct fatfs_handle *handle = h;
//    DEBUG_PRINTF("\nfatfs_read called with - name: \"%s\" pos: %d, bytes: %d\n", handle->path, handle->pos, bytes);

//    DEBUG_PRINTF("FILE SIZE: %d\n", handle->size);

    size_t remaining_bytes = (handle->size - handle->pos);
    if (remaining_bytes == 0) {
        *bytes_read = 0;
        return SYS_ERR_OK;
    }
    if (remaining_bytes < bytes) {
        bytes = remaining_bytes;
    }

    nameservice_chan_t chan = st;
    FSReadRequest req = FSREAD_REQUEST__INIT;
    req.fd = handle->fd;
    req.offset = handle->pos;
    req.size = bytes;

    REQUEST_WRAP(req_wrap, fs_read, FS_READ, &req);
    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_READ, &req_wrap, NULL_CAP, &response,
                                NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_READ);
    memcpy(buffer, response->fs_read->raw_bytes.data, response->fs_read->raw_bytes.len);

    handle->pos += response->fs_read->raw_bytes.len;
    *bytes_read = response->fs_read->raw_bytes.len;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);
    return err;
}

errval_t fatfs_read_file_to_frame(fatfs_mount_t st, const char *path, struct capref frame, size_t *bytes_read)
{
    errval_t err;
//    DEBUG_PRINTF("\nfatfs_read called with - name: \"%s\" pos: %d, bytes: %d\n", handle->path, handle->pos, bytes);
//    DEBUG_PRINTF("FILE SIZE: %d\n", handle->size);

    struct capability c;
    err = cap_direct_identify(frame, &c);
    RETURN_IF_ERR(err);
    assert(c.type == ObjType_Frame);
    nameservice_chan_t chan = st;


    FSReadFileToFrameRequest req = FSREAD_FILE_TO_FRAME_REQUEST__INIT;
    req.path = (char *) path;

    REQUEST_WRAP(req_wrap, fs_read_file_to_frame, FS_READ_FILE_TO_FRAME, &req);
    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_READFILE_TO_FRAME, &req_wrap, frame, &response,
            NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_READ_FILE_TO_FRAME);

    *bytes_read = response->fs_read_file_to_frame->bytes;

    err = SYS_ERR_OK;
    cleanup:
    RESPONSE_WRAP_DESTROY(response);
    return err;
}

errval_t fatfs_write(void *st, fatfs_handle_t handle, const void *buffer, size_t bytes,
                     size_t *bytes_written)
{
    errval_t err;
    struct fatfs_handle *h = handle;
//    DEBUG_PRINTF("\nfatfs_write called with - name: \"%s\" bytes: %d, pos: %d\n", h->path, bytes, h->pos);

    nameservice_chan_t chan = st;
    FSWriteRequest req = FSWRITE_REQUEST__INIT;
    req.fd = h->fd;
    req.offset = h->pos;
    req.raw_bytes.data = (uint8_t *) buffer;
    req.raw_bytes.len = bytes;
    REQUEST_WRAP(req_wrap, fs_write, FS_WRITE, &req);

    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_WRITE, &req_wrap, NULL_CAP, &response,
        NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_WRITE);

    h->pos += response->fs_write->bytes;
    h->size = MAX(h->size, h->pos);
    *bytes_written = response->fs_write->bytes;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);
    return err;
}

errval_t fatfs_truncate(void *st, fatfs_handle_t handle, size_t bytes)
{
    errval_t err;
    struct fatfs_handle *h = handle;

    if (bytes >= h->size) {
        return SYS_ERR_OK;
    }

    nameservice_chan_t chan = st;
    FSTruncRequest req = FSTRUNC_REQUEST__INIT;
    req.fd = h->fd;
    req.bytes = bytes;
    REQUEST_WRAP(req_wrap, fs_trunc, FS_TRUNC, &req);

    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_TRUNC, &req_wrap, NULL_CAP, NULL,
        NULL);
    RETURN_IF_ERR(err_pop(err));
    RETURN_IF_ERR(err);


    h->size = bytes;
    h->pos = MIN(h->pos, h->size);

    return SYS_ERR_OK;
}

errval_t fatfs_tell(void *st, fatfs_handle_t handle, size_t *pos)
{
    struct fatfs_handle *h = handle;
    if (h->is_dir) {
        *pos = 0;
    } else {
        *pos = h->pos;
    }
    return SYS_ERR_OK;
}

errval_t fatfs_stat(void *st, fatfs_handle_t handle, struct fs_fileinfo *info)
{
    if (!info) {
        return SYS_ERR_OK;
    }

    struct fatfs_handle *h = handle;

    info->size = h->size;
    info->type = h->is_dir ? FS_DIRECTORY : FS_FILE;
    return SYS_ERR_OK;
}

errval_t fatfs_seek(void *st, fatfs_handle_t handle, enum fs_seekpos whence, off_t offset)
{
    struct fatfs_handle *h = handle;

    size_t new_pos;
    switch (whence) {
    case FS_SEEK_SET:
        new_pos = offset;
        break;
    case FS_SEEK_CUR:
        new_pos = h->pos + offset;
        break;
    case FS_SEEK_END:
        if (h->is_dir) {
            assert(!"NYI");
        }
        new_pos = h->size + offset;
        break;
    default:
        return ERR_INVALID_ARGS;
    }
    if (!h->is_dir && new_pos > h->size)
        return FS_ERR_INDEX_BOUNDS;

    h->pos = new_pos;
    return SYS_ERR_OK;
}

errval_t fatfs_opendir(void *st, const char *path, fatfs_handle_t *rethandle)
{
    errval_t err;
    nameservice_chan_t chan = st;
    // Just reuse fs_open messages for this.
    FSOpenRequest req = FSOPEN_REQUEST__INIT;
    req.path = (char *)path;
    req.flags = 0;

    REQUEST_WRAP(req_wrap, fs_open, FS_OPEN, &req);
    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_OPENDIR, &req_wrap, NULL_CAP, &response,
        NULL);
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_OPEN);

    struct fatfs_handle *handle = malloc(sizeof(struct fatfs_handle));

    handle->path = strdup(path);
    handle->fd = response->fs_open->fd;

    assert(response->fs_open->size == 0);
    handle->size = 0;
    handle->is_dir = true;
    handle->pos = 0;

    *rethandle = handle;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);
    return err;
}

errval_t fatfs_dir_read_next(void *st, fatfs_handle_t handle, char **retname,
                             struct fs_fileinfo *info)
{
    errval_t err;
    struct fatfs_handle *h = handle;

    nameservice_chan_t chan = st;
    FSReadNextDirRequest req = FSREAD_NEXT_DIR_REQUEST__INIT;
    req.fd = h->fd;
    req.pos = h->pos;
    REQUEST_WRAP(req_wrap, fs_readnextdir, FS_READNEXTDIR, &req);

    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_READNEXTDIR, &req_wrap, NULL_CAP, &response,
        NULL);

    if (err_pop(err) == FS_ERR_INDEX_BOUNDS) {
        h->pos = 0;
        err = FS_ERR_INDEX_BOUNDS;
        goto cleanup;
    }
    if (err_is_fail(err_pop(err))) {
        err = err_pop(err);
        goto cleanup;
    }
    GOTO_IF_ERR(err, cleanup);

    assert(response->data_case == RPC_RESPONSE_WRAP__DATA_FS_READNEXTDIR);
    h->pos = response->fs_readnextdir->idx + 1;
    *retname = response->fs_readnextdir->name;
    response->fs_readnextdir->name = NULL;

    err = SYS_ERR_OK;
cleanup:
    RESPONSE_WRAP_DESTROY(response);
    return err;
}

errval_t fatfs_closedir(void *st, fatfs_handle_t dhandle)
{
    struct fatfs_handle *handle = dhandle;
    if (!handle->is_dir) {
        return FS_ERR_NOTDIR;
    }

    nameservice_chan_t chan = st;
    FSCloseRequest req = FSCLOSE_REQUEST__INIT;
    req.fd = handle->fd;

    REQUEST_WRAP(req_wrap, fs_close, FS_CLOSE, &req);
    errval_t err = nameservice_rpc_proto(chan, RPC_METHOD__FS_CLOSE, &req_wrap, NULL_CAP,
        NULL, NULL);
    RETURN_IF_ERR(err_pop(err));
    RETURN_IF_ERR(err);

    free(handle->path);
    free(handle);

    return SYS_ERR_OK;
}

errval_t fatfs_mkdir(void *st, const char *path)
{
//    DEBUG_PRINTF("FATFS MKDIR\n");
    errval_t err;

    nameservice_chan_t chan = st;
    FSCreateRequest req = FSCREATE_REQUEST__INIT;
    req.path = (char *)path;
    req.flags = 0;
    req.dir = true;
    REQUEST_WRAP(req_wrap, fs_create, FS_CREATE, &req);

    RpcResponseWrap *response = NULL;
    err = nameservice_rpc_proto(chan, RPC_METHOD__FS_CREATE, &req_wrap, NULL_CAP,
        &response, NULL);
    RESPONSE_WRAP_DESTROY(response);
    RETURN_IF_ERR(err_pop(err));
    return err;
}

errval_t fatfs_rmdir(void *st, const char *path)
{
    return fatfs_remove(st, path);
}

errval_t fatfs_mount(const char *uri, fatfs_mount_t *retst)
{
    errval_t err;
    char *name = malloc(strlen(uri) + 3);
    name = strcpy(name, "FS");
    name = strcat(name, uri);

    nameservice_chan_t chan;

    err = nameservice_lookup(name, &chan);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_NAMESERVICE_UNKNOWN_NAME);
    *retst = chan;
    return SYS_ERR_OK;
}
