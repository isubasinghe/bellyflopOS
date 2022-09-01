//
// Created by fooris on 24.05.22.
//

#ifndef BF_AOS_TESTS_H
#define BF_AOS_TESTS_H

__unused static void test()
{
    errval_t err;
    DEBUG_PRINTF(YELLOW "Hello, world from fs fat32!\n" COLOR_RESET);
    struct fat32_file_system fat;
    err = init_fat32_file_system(&fat);
    DEBUG_IF_ERR(err, "init fat failed");
    assert(err_is_ok(err));

    DEBUG_PRINTF("FATSz32: %d\n", fat.bpb.fat_sz32);

    struct dir_entry entry = { 0 };
    err = fat32_resolve_path(&fat, "t_folder/", &entry);
    DEBUG_IF_ERR(err, "resolve path failed");
    assert(err_is_ok(err));

    char *buf = malloc(4096);

    fat32_read_from_cluster(&fat, buf, get_first_cluster_num(&entry.entry), 0,
                            fat.cluster_bytes);
    for (int i = 0; i < 512; i += 1) {
        char v = buf[i];
        if (' ' <= v && v <= 'z') {
            printf("\'%c\' ", v);
        } else {
            printf("X%02x ", v);
        }
        if (i % 16 == 15) {
            printf("\n");
        }
    }

    struct dir_entry new_file = { 0 };
    err = fat32_create_file(&fat, &entry, "newFile.txt", 0, &new_file);
    DEBUG_IF_ERR(err, "fat32 create file failed");
    assert(err_is_ok(err));

    fat32_read_from_cluster(&fat, buf, get_first_cluster_num(&entry.entry), 0,
                            fat.cluster_bytes);
    for (int i = 0; i < 512; i += 1) {
        char v = buf[i];
        if (' ' <= v && v <= 'z') {
            printf("\'%c\' ", v);
        } else {
            printf("X%02x ", v);
        }
        if (i % 16 == 15) {
            printf("\n");
        }
    }

    err = fat32_delete_file(&fat, &entry, &new_file);
    DEBUG_IF_ERR(err, "fat32 delete file failed");
    assert(err_is_ok(err));

    fat32_read_from_cluster(&fat, buf, get_first_cluster_num(&entry.entry), 0,
                            fat.cluster_bytes);
    for (int i = 0; i < 512; i += 1) {
        char v = buf[i];
        if (' ' <= v && v <= 'z') {
            printf("\'%c\' ", v);
        } else {
            printf("X%02x ", v);
        }
        if (i % 16 == 15) {
            printf("\n");
        }
    }


    //    struct dir_entry entry = {0};
    //    err = fat32_resolve_path(&fat, "t_folder/test.txt", &entry);
    //    DEBUG_IF_ERR(err, "resolve path failed");
    //    assert(err_is_ok(err));
    //
    //    DEBUG_PRINTF("dir_entry points to: %s\n", entry.entry.name);
    //
    //    char *buf = malloc(8 * 1024);
    //    memset(buf, ' ', 8 * 1024);
    //
    //    DEBUG_PRINTF("memset done\n");
    //
    //    size_t bytes_written = 0;
    //    char * string =
    //    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    //    err = fat32_write(&fat, &entry, string, 0, strlen(string), &bytes_written);
    //    DEBUG_IF_ERR(err, "fat32 write failed");
    //    assert(err_is_ok(err));

    //    /* READ */
    //    size_t bytes_read = 0;
    //    err = fat32_read(&fat, &entry, buf, 0, entry.entry.file_size, &bytes_read);
    //    DEBUG_IF_ERR(err, "fat32 read failed");
    //    assert(err_is_ok(err));
    //
    //    DEBUG_PRINTF("bytes_read: %d\n", bytes_read);
    //    for (int i = 0; i < bytes_read; i+=256) {
    //        DEBUG_PRINTF("%d: %.400\n", i, &buf[i]);
    //    }
    //
    //    memset(buf, 'a', 2*1024);
    //
    //    /* WRITE */
    //    for (int i = 0; i < 3; ++i) {
    //        bytes_written = 0;
    ////        string = "HELLO FROM THE WRITER! ";
    //        err = fat32_write(&fat, &entry, buf, MAX((int)entry.entry.file_size - 1, 0),
    //        2*1024 , &bytes_written); DEBUG_IF_ERR(err, "fat32 write failed");
    //        assert(err_is_ok(err));
    //    }
    //
    //
    //    /* READ AGAIN */
    //    bytes_read = 0;
    //    err = fat32_read(&fat, &entry, buf, 0, entry.entry.file_size, &bytes_read);
    //    DEBUG_IF_ERR(err, "fat32 read failed");
    //    assert(err_is_ok(err));
    //
    //    DEBUG_PRINTF("bytes_read: %d\n", bytes_read);
    //
    //    for (int i = 0; i < bytes_read; i+=256) {
    //        DEBUG_PRINTF("%d: %.256s\n", i, &buf[i]);
    //    }
    //
    //    /** Create file and write to it. */
    //    err = fat32_resolve_path(&fat, "t_folder", &entry);
    //    DEBUG_IF_ERR(err, "fat32 read failed");
    //    assert(err_is_ok(err));
    //
    //    struct dir_entry new_file = {0};
    //    err = fat32_create_file(&fat, &entry, "fromBF.txt", 0, &new_file);
    //    DEBUG_IF_ERR(err, "fat32 read failed");
    //    assert(err_is_ok(err));
    //
    //    err = fat32_write(&fat, &new_file, "Hello World", 0, 11, NULL);
    //    DEBUG_IF_ERR(err, "fat32 read failed");
    //    assert(err_is_ok(err));
}
#endif  // BF_AOS_TESTS_H
