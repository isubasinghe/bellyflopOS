#include <aos/aos_rpc_lmp.h>
#include <aos/macros.h>
#include <aos/rpc/rpcs.pb-c.h>


static errval_t recv_single_lmp_msg_blocking(struct lmp_chan *chan,
                                             struct lmp_recv_msg *rcvbuf,
                                             struct capref *capref)
{
    errval_t err;
    do {
        err = lmp_chan_recv(chan, rcvbuf, capref);
    } while (err == LIB_ERR_NO_LMP_MSG);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LMP_CHAN_RECV);
    return SYS_ERR_OK;
}

static errval_t send_single_lmp_msg(struct lmp_chan *chan, bool should_yield_thread,
                                    struct capref send_cap, uintptr_t arg1,
                                    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
    errval_t err;
    // Retry until we dont get a SYS_ERR_LMP_BUF_OVERFLOW.
    do {
        err = lmp_chan_send4(
            chan, (should_yield_thread) ? LMP_FLAG_YIELD | LMP_FLAG_SYNC : LMP_FLAG_YIELD,
            send_cap, arg1, arg2, arg3, arg4);
    } while (err == SYS_ERR_LMP_BUF_OVERFLOW);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LMP_CHAN_SEND);

    return SYS_ERR_OK;
}

errval_t aos_rpc_lmp_recv_blocking(struct lmp_chan *chan, uint8_t **buf_uint8,
                                   size_t *buflen, struct capref *cap)
{
    return aos_rpc_lmp_recv_blocking_with_empty_slot(chan, buf_uint8, buflen, cap,
                                                     NULL_CAP);
}

errval_t aos_rpc_lmp_recv_blocking_with_empty_slot(struct lmp_chan *chan,
                                                   uint8_t **buf_uint8, size_t *buflen,
                                                   struct capref *cap,
                                                   struct capref empty_slot)
{
    assert(buf_uint8 != NULL && buflen != NULL && cap != NULL);

    errval_t err;
    struct lmp_recv_msg rcvbuf = LMP_RECV_MSG_INIT;
    err = recv_single_lmp_msg_blocking(chan, &rcvbuf, cap);
    RETURN_IF_ERR(err);

    if (!capref_is_null(*cap)) {
        if (capref_is_null(empty_slot)) {
            lmp_chan_alloc_recv_slot(chan);
        } else {
            lmp_chan_set_recv_slot(chan, empty_slot);
        }
    }

    if (*buflen < rcvbuf.words[0]) {
        *buf_uint8 = malloc(rcvbuf.words[0]);
    }
    *buflen = rcvbuf.words[0];

    uintptr_t *buf_uptr = (uintptr_t *)*buf_uint8;
    size_t buf_uptr_len = *buflen / sizeof(uintptr_t);

    // First word was already used for the header.
    memcpy(buf_uptr, rcvbuf.words + 1, MIN(*buflen, 3 * sizeof(uintptr_t)));
    size_t i;
    for (i = 3; i + 3 < buf_uptr_len; i += 4) {
        rcvbuf = (struct lmp_recv_msg)LMP_RECV_MSG_INIT;
        err = recv_single_lmp_msg_blocking(chan, &rcvbuf, NULL);
        RETURN_IF_ERR(err);
        memcpy(buf_uptr + i, rcvbuf.words, sizeof(uintptr_t) * 4);
    }
    // Receive the overhang.
    if (*buflen > i * sizeof(uintptr_t)) {
        rcvbuf = (struct lmp_recv_msg)LMP_RECV_MSG_INIT;
        err = recv_single_lmp_msg_blocking(chan, &rcvbuf, NULL);
        RETURN_IF_ERR(err);
        size_t missing_char_count = *buflen - (i * sizeof(uintptr_t));
        memcpy(buf_uptr + i, rcvbuf.words, missing_char_count);
    }

    if (!capref_is_null(*cap)) {
        // A hack to support bootstraping LMP channels :)
        // DEBUG_PRINTF("Deducing magic: %p %p %p", buf_uptr[0], buf_uptr[1], buf_uptr[2]);
        if (buf_uptr[0] == 0x120908) {
            assert(!capref_is_null(*cap));
            assert(capref_is_null(chan->remote_cap));
            chan->remote_cap = *cap;
        }
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_lmp_send(struct lmp_chan *chan, uint8_t *buf_uint8, size_t buflen,
                          struct capref cap)
{
    errval_t err;

    uintptr_t *buf_uptr = (uintptr_t *)buf_uint8;
    size_t buf_uptr_len = buflen / sizeof(uintptr_t);

    // First uintptr_t of the message contains buflen.
    uintptr_t words[4] = { 0 };
    words[0] = buflen;
    memcpy(words + 1, buf_uptr, MIN(3 * sizeof(uint64_t), buflen));

    bool is_last_msg = (buflen <= 3 * sizeof(uint64_t));
    err = send_single_lmp_msg(chan, is_last_msg, cap, words[0], words[1], words[2],
                              words[3]);
    RETURN_IF_ERR(err);

    size_t i;
    for (i = 3; i + 3 < buf_uptr_len; i += 4) {
        is_last_msg = (buflen == (i + 4) * sizeof(uintptr_t));
        err = send_single_lmp_msg(chan, is_last_msg, NULL_CAP, buf_uptr[i + 0],
                                  buf_uptr[i + 1], buf_uptr[i + 2], buf_uptr[i + 3]);
        RETURN_IF_ERR(err);
    }

    // Send the overhang.
    if (buflen > i * sizeof(uintptr_t)) {
        size_t missing_char_count = buflen - i * sizeof(uintptr_t);
        memcpy(words, buf_uptr + i, missing_char_count);
        err = send_single_lmp_msg(chan, /*should_yield_thread=*/true, NULL_CAP, words[0],
                                  words[1], words[2], words[3]);
        RETURN_IF_ERR(err);
    }

    return SYS_ERR_OK;
}