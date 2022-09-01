#ifndef BF_AOS_FATFS_H
#define BF_AOS_FATFS_H

#include <fs/fs.h>
#include <aos/nameserver.h>

typedef void *fatfs_handle_t;
typedef nameservice_chan_t fatfs_mount_t;

errval_t fatfs_open(void *st, const char *path, int flags, fatfs_handle_t *rethandle);

errval_t fatfs_create(void *st, const char *path, int flags, fatfs_handle_t *rethandle);

errval_t fatfs_remove(void *st, const char *path);

errval_t fatfs_read(void *st, fatfs_handle_t handle, void *buffer, size_t bytes,
                    size_t *bytes_read);

errval_t fatfs_read_file_to_frame(fatfs_mount_t st, const char *path, struct capref frame, size_t *bytes_read);

errval_t fatfs_write(void *st, fatfs_handle_t handle, const void *buffer, size_t bytes,
                     size_t *bytes_written);

errval_t fatfs_truncate(void *st, fatfs_handle_t handle, size_t bytes);

errval_t fatfs_tell(void *st, fatfs_handle_t handle, size_t *pos);

errval_t fatfs_stat(void *st, fatfs_handle_t inhandle, struct fs_fileinfo *info);

errval_t fatfs_seek(void *st, fatfs_handle_t handle, enum fs_seekpos whence, off_t offset);

errval_t fatfs_close(void *st, fatfs_handle_t inhandle);

errval_t fatfs_opendir(void *st, const char *path, fatfs_handle_t *rethandle);

errval_t fatfs_dir_read_next(void *st, fatfs_handle_t inhandle, char **retname,
                             struct fs_fileinfo *info);

errval_t fatfs_closedir(void *st, fatfs_handle_t dhandle);

errval_t fatfs_mkdir(void *st, const char *path);

errval_t fatfs_rmdir(void *st, const char *path);

errval_t fatfs_mount(const char *uri, fatfs_mount_t *retst);

#endif  // BF_AOS_FATFS_H
