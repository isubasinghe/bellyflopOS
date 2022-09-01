#ifndef UMP_CHAN_H
#define UMP_CHAN_H

#include <aos/ump_ringbuffer.h>
#include <aos/waitset.h>

enum ump_chan_buf_layout {
    UMP_CHAN_BUF_LAYOUT_SEND_RECV,
    UMP_CHAN_BUF_LAYOUT_RECV_SEND,
};

// Not thread-safe.
struct ump_chan {
    struct ump_ringbuffer send_rb;
    struct ump_ringbuffer recv_rb;

    // This is waitset-specific state to enable UMP polling from waitset.
    struct waitset_chanstate waitset_state;
};

errval_t ump_create_frame(void **urpc, size_t frame_size,
                          struct frame_identity *urpc_frame_id, 
                          struct capref *urpc_cap_res);

// Accepts a buffer which is split into two (for sending and receiving), depending on
// `buf_layout` argument.
void ump_chan_init(struct ump_chan *chan, void *buf_write, size_t buflen_write,
                   void *buf_read, size_t buflen_read);

void ump_chan_init_split(struct ump_chan *chan, void *buf, size_t buflen,
                         enum ump_chan_buf_layout buf_layout);

bool ump_chan_can_recv(struct ump_chan *chan);
errval_t ump_chan_can_send(struct ump_chan *chan, size_t bytes);

errval_t ump_chan_send(struct ump_chan *chan, uint8_t *buf, size_t buflen,
                       struct capref cap);

// If *buf is not NULL and *buflen is big enough for the incoming message, the provided
// *buf will be used. Otherwise the buffer is allocated dynamically.
errval_t ump_chan_recv_blocking(struct ump_chan *chan, uint8_t **buf, size_t *buflen,
                                struct capref *cap);

errval_t ump_chan_register_recv(struct ump_chan *chan, struct waitset *ws,
                                struct event_closure closure);
errval_t ump_chan_deregister_recv(struct ump_chan *chan);

#endif  // UMP_CHAN_H
