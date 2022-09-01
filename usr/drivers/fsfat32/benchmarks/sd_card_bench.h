#ifndef BF_AOS_SD_CARD_BENCH_H
#define BF_AOS_SD_CARD_BENCH_H

#include <aos/aos.h>
#include <aos/test_utils.h>
#include <aos/systime.h>

#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include "aos/cache.h"

#define DATA_BARRIER __asm volatile("dmb sy\n")
#define INSTR_BARRIER __asm volatile("isb sy\n")

#define TIME(t) do {                    \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
    *t = systime_now();                 \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
} while(0)

struct sd_wrapper *___bench_sd;

static void setup_sd_bench(struct sd_wrapper *sd) {
    ___bench_sd = sd;
}



// Measure end to end performance of reading and writing blocks.

#define NUM_MEASUREMENTS 30
CREATE_TEST(sd_card_read, sd_bench,
        {
            DEBUG_PRINTF(YELLOW "Running BENCHMARK: %s \n" COLOR_RESET, __func__);

            errval_t err = SYS_ERR_OK;
            lpaddr_t base_paddr = cap_get_paddr(___bench_sd->buf_frame_cap);

            for (int i = 0; i < NUM_MEASUREMENTS; i++) {
                systime_t t_start;
                systime_t t_end;
                TIME(&t_start);
                err |= sdhc_read_block(___bench_sd->sd, i, base_paddr);
                TIME(&t_end);
                uint64_t read_block_ns = systime_to_ns(t_end) -systime_to_ns(t_start);

                TIME(&t_start);
                err |= sdhc_write_block(___bench_sd->sd, i, base_paddr);
                TIME(&t_end);
                uint64_t write_block_ns = systime_to_ns(t_end) -systime_to_ns(t_start);

                DEBUG_PRINTF(" %d: %lu, %lu \n", SDHC_BLOCK_SIZE, read_block_ns, write_block_ns);
            }
            TEST_REQUIRE_OK(err);

            for (int i = 0; i < 100; i++){
                err = sdhc_test(___bench_sd->sd, (void*)___bench_sd->buf, base_paddr);
                TEST_REQUIRE_OK(err);
            }

            DEBUG_PRINTF(YELLOW "END BENCHMARK: %s \n" COLOR_RESET, __func__);

        })

#endif //BF_AOS_SD_CARD_BENCH_H
