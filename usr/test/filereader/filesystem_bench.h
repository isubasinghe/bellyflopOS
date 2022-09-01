#ifndef BF_AOS_FILESYSTEM_BENCH_H
#define BF_AOS_FILESYSTEM_BENCH_H

#include <aos/test_utils.h>

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

CREATE_TEST(open_read_close_file, fs_bench, {
    DEBUG_PRINTF(YELLOW "START %s\n" COLOR_RESET, __func__);

    char buf[8192] = {1};

    DEBUG_PRINTF("write / read 4096 bytes to beginning of file\n");
    DEBUG_PRINTF("i  \t open to write in ns \t append time in ns \t read file in ns\t close file in ns\n");
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        systime_t start_time;
        systime_t end_time;
        char name[40];
        sprintf(name, "/sdcard/test%d.txt", i);

        TIME(&start_time);
        FILE *f = fopen(name, "w+");
        TIME(&end_time);
        uint64_t diff_open_to_write = systime_to_ns(end_time) - systime_to_ns(start_time);

        TIME(&start_time);
        fwrite(buf, 1, 4096, f);
        TIME(&end_time);
        uint64_t diff_append = systime_to_ns(end_time) - systime_to_ns(start_time);

        rewind(f);

        TIME(&start_time);
        fread(buf + 4096, 1, 4096, f);
        TIME(&end_time);
        uint64_t diff_read = systime_to_ns(end_time) - systime_to_ns(start_time);

        TIME(&start_time);
        fclose(f);
        TIME(&end_time);
        uint64_t diff_close = systime_to_ns(end_time) - systime_to_ns(start_time);



        DEBUG_PRINTF("%02d:\t%015lu;\t%015lu;\t%015lu;\t%015lu\n", i, diff_open_to_write, diff_append, diff_read, diff_close);
    }


    DEBUG_PRINTF(YELLOW "END %s\n" COLOR_RESET, __func__);
})


#endif //BF_AOS_FILESYSTEM_BENCH_H
