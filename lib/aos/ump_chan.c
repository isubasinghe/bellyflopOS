#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/waitset_chan.h>
#include <aos/ump_chan.h>
#include <aos/macros.h>
#include <aos/ump_ringbuffer.h>
#include <assert.h>
#include <aos/kernel_cap_invocations.h>

#define DATA_PAD_BYTE ('*')

errval_t ump_create_frame(void **urpc, size_t frame_size, 
                          struct frame_identity *urpc_frame_id,
                          struct capref *urpc_cap_res)
{
    errval_t err;
    // Alloc URPC page
    struct capref urpc_cap;
    size_t urpc_cap_size;
    err = frame_alloc_aligned(&urpc_cap, frame_size, CACHE_LINE_SIZE, &urpc_cap_size);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    if (urpc_frame_id != NULL) {
        *urpc_frame_id = (struct frame_identity) {
            .base = cap_get_paddr(urpc_cap),
            .bytes = urpc_cap_size,
            .pasid = disp_get_core_id(),
        };
    }

    // Map in the URCP page
    err = paging_map_frame_complete(get_current_paging_state(), urpc, urpc_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);
    // Needed so that all underlying ringbuffer statuses are initialized to 0.
    memset(*urpc, 0, frame_size);

    if (urpc_cap_res != NULL) {
        *urpc_cap_res = urpc_cap;
    }

    return SYS_ERR_OK;
}


void ump_chan_init(struct ump_chan *chan, void *buf_write, size_t buflen_write,
                   void *buf_read, size_t buflen_read)
{
    ump_ringbuffer_init(&chan->send_rb, UMP_RINGBUFFER_MODE_WRITER, buf_write,
                        buflen_write);
    ump_ringbuffer_init(&chan->recv_rb, UMP_RINGBUFFER_MODE_READER, buf_read, buflen_read);

    waitset_chanstate_init(&chan->waitset_state, CHANTYPE_UMP_IN);
    chan->waitset_state.data = chan;
}

void ump_chan_init_split(struct ump_chan *chan, void *buf, size_t buflen,
                         enum ump_chan_buf_layout buf_layout)
{
    size_t total_lines = buflen / CACHE_LINE_SIZE;
    assert(total_lines >= 2);

    size_t first_lines = total_lines / 2;

    // ump_ringbuffer buffers must be cache aligned.
    void *first_buf = buf;
    size_t first_buflen = first_lines * CACHE_LINE_SIZE;
    void *second_buf = (uint8_t *)buf + first_buflen;
    size_t second_buflen = (total_lines - first_lines) * CACHE_LINE_SIZE;

    switch (buf_layout) {
    case UMP_CHAN_BUF_LAYOUT_SEND_RECV:
        ump_chan_init(chan, first_buf, first_buflen, second_buf, second_buflen);
        break;
    case UMP_CHAN_BUF_LAYOUT_RECV_SEND:
        ump_chan_init(chan, second_buf, second_buflen, first_buf, first_buflen);
        break;
    default:
        DEBUG_PRINTF("Unknown buf_layout %d\n", buf_layout);
        assert(0);
    }
}

bool ump_chan_can_recv(struct ump_chan *chan)
{
    return ump_ringbuffer_can_read(&chan->recv_rb);
}

errval_t ump_chan_can_send(struct ump_chan *chan, size_t bytes)
{
    size_t block_count = (bytes + (DATA_SIZE_B - 1)) / DATA_SIZE_B;
    return ump_ringbuffer_can_write(&chan->send_rb, block_count);
}

// Sends buf with the following format, each row below carries DATA_SIZE_B data.
// Header:      buflen has_frame_cap [frame.base, frame.bytes, coreid] 0...
// Buf 0:       buf[0 : DATA_SIZE_B]
// Buf 1:       buf[DATA_SIZE_B : 2 * DATA_SIZE_B]
//              ...
// Buf n-1:     buf[(n-2) * DATA_SIZE_B : (n-1) * DATA_SIZE_B]
// Buf n:       buf[(n-1) * DATA_SIZE_B: buflen] 0 ...
errval_t ump_chan_send(struct ump_chan *chan, uint8_t *buf, size_t buflen,
                       struct capref cap)
{
    assert(DATA_SIZE_B >= 24);  // To fit the header.

    errval_t err;

    // ----- Send header and capability ------
    // Note: The current format is wasting almost a full cacheline of bytes.
    uint8_t header[DATA_SIZE_B] = { 0 };
    uint64_t *header_uptr = (uintptr_t *)header;
    header_uptr[0] = buflen;

    struct capability c;
    if (!capref_is_null(cap)) {
        err = cap_direct_identify(cap, &c);
        assert(err_is_ok(err));
        assert(c.type == ObjType_Frame);
        header_uptr[1] = 1;  // has_frame_cap
        header_uptr[2] = (uintptr_t)c.u.frame.base;
        header_uptr[3] = (uintptr_t)c.u.frame.bytes;
        header_uptr[4] = (uintptr_t)disp_get_core_id();
    }

    ump_ringbuffer_write(&chan->send_rb, header, DATA_SIZE_B);

    // ----- Send full data blocks ------
    size_t full_blocks_cnt = buflen / DATA_SIZE_B;
    for (size_t i = 0; i < full_blocks_cnt; ++i) {
        ump_ringbuffer_write(&chan->send_rb, &buf[i * DATA_SIZE_B], DATA_SIZE_B);
    }

    // ----- Send last data block ------
    if (buflen % DATA_SIZE_B == 0) {
        return SYS_ERR_OK;
    }

    uint8_t last_line[DATA_SIZE_B] = { 0 };
    size_t last_line_idx = 0;
    for (size_t i = full_blocks_cnt * DATA_SIZE_B; i < buflen; ++i) {
        last_line[last_line_idx++] = buf[i];
    }

    assert(last_line_idx < DATA_SIZE_B);
    ump_ringbuffer_write(&chan->send_rb, last_line, DATA_SIZE_B);

    return SYS_ERR_OK;
}

errval_t ump_chan_recv_blocking(struct ump_chan *chan, uint8_t **buf, size_t *buflen,
                                struct capref *cap)
{
    // ----- Recv header ------
    uint8_t header[DATA_SIZE_B];
    uintptr_t *header_uptr = (uintptr_t *)header;
    errval_t err = ump_ringbuffer_read(&chan->recv_rb, header, DATA_SIZE_B,
                                       /*is_blocking=*/true);
    RETURN_IF_ERR(err);

    size_t recv_len = header_uptr[0];
    bool has_frame_cap = header_uptr[1];
    genpaddr_t frame_base = header_uptr[2];
    gensize_t frame_bytes = header_uptr[3];
    coreid_t coreid = header_uptr[4];

    if (has_frame_cap && cap != NULL) {
        slot_alloc(cap);
        err = frame_forge(*cap, frame_base, frame_bytes, coreid);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_FORGE);
    }

    // Malloc buffer if needed.
    if (recv_len > *buflen || *buf == NULL) {
        *buf = malloc(recv_len);
    }
    *buflen = recv_len;

    uint8_t *buf_bytes = *buf;

    // ----- Recv full data blocks ------
    size_t full_blocks_cnt = recv_len / DATA_SIZE_B;
    for (size_t i = 0; i < full_blocks_cnt; ++i) {
        err = ump_ringbuffer_read(&chan->recv_rb, &buf_bytes[i * DATA_SIZE_B],
                                  DATA_SIZE_B, true);
        RETURN_IF_ERR(err);
    }

    // ----- Recv last data block ------
    if (recv_len % DATA_SIZE_B == 0) {
        return SYS_ERR_OK;
    }

    uint8_t last_line[DATA_SIZE_B];
    err = ump_ringbuffer_read(&chan->recv_rb, last_line, DATA_SIZE_B, true);
    RETURN_IF_ERR(err);

    for (size_t i = full_blocks_cnt * DATA_SIZE_B; i < recv_len; ++i) {
        buf_bytes[i] = last_line[i % DATA_SIZE_B];
    }

    return SYS_ERR_OK;
}

errval_t ump_chan_register_recv(struct ump_chan *chan, struct waitset *ws,
                                struct event_closure closure)
{
    return waitset_chan_register_polled(ws, &chan->waitset_state, closure);
}

errval_t ump_chan_deregister_recv(struct ump_chan *chan)
{
    return waitset_chan_deregister(&chan->waitset_state);
}
