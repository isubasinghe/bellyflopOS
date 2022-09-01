#include <aos/aos.h>
#include <aos/ump_ringbuffer.h>
#include <string.h>
#include <assert.h>

void ump_ringbuffer_init(struct ump_ringbuffer *rb, enum ump_ringbuffer_mode mode,
                         void *buf, size_t buflen)
{
    assert((uintptr_t)buf % CACHE_LINE_SIZE == 0);

    rb->start = buf;
    rb->num_slots = buflen / SLOT_SIZE_B;
    // TODO (hack explained): This inits the index with the second cache line because in the
    //       first one we pass data when spawning a new core. With some bad luck, we might
    //       interpret these data as UMP messages. A fix would be to pass these data as a
    //       UMP message.
    rb->index = CACHE_LINE_SIZE / SLOT_SIZE_B;
    rb->mode = mode;

    // We could just set the status slots.
    if (mode == UMP_RINGBUFFER_MODE_WRITER) {
        memset(buf, BUFFER_WAITING, buflen);
    }
}

static inline size_t get_next_index(struct ump_ringbuffer *rb)
{
    assert(rb->index < rb->num_slots);

    size_t new_index = rb->index + CACHE_LINE_SIZE / SLOT_SIZE_B;
    return unlikely(new_index >= rb->num_slots) ? 0 : new_index;
}

bool ump_ringbuffer_can_read(struct ump_ringbuffer *rb)
{
    assert(rb->mode == UMP_RINGBUFFER_MODE_READER);

    slot_type_t status = rb->start[rb->index + STATUS_OFFSET_B];
    assert(status == BUFFER_READY || status == BUFFER_WAITING);
    return (status == BUFFER_READY);
}

bool ump_ringbuffer_can_write(struct ump_ringbuffer *rb, size_t block_count) 
{
    assert(rb->mode == UMP_RINGBUFFER_MODE_WRITER);
    size_t index = rb->index;
    for(size_t i = 0; i < block_count; i++) {
        slot_type_t status = rb->start[index + STATUS_OFFSET_B];
        assert(status == BUFFER_READY || status == BUFFER_WAITING);
        size_t new_index = index + CACHE_LINE_SIZE / SLOT_SIZE_B;
        index = unlikely(new_index >= rb->num_slots) ? 0 : new_index;
        if (status == BUFFER_READY) {
            return false;
        }
    }
    return true;
}

void ump_ringbuffer_write(struct ump_ringbuffer *rb, void *data, size_t len)
{
    assert(len == DATA_SIZE_B);
    assert(rb->mode == UMP_RINGBUFFER_MODE_WRITER);

    slot_type_t *casted_data = (slot_type_t *)data;

    while (1) {
        // more likely than not to have this memory ready for writing (probably?)
        __builtin_prefetch((const void *)&rb->start[rb->index], 1, 3);
        // we want to read the last word
        // remember we have actually have CACHE_LINE_SIZE amount of data available with
        // DATA_SIZE_B data bytes and one word for a status flag
        slot_type_t status = rb->start[rb->index + STATUS_OFFSET_B];
        assert(status == BUFFER_READY || status == BUFFER_WAITING);

        DATA_BARRIER;
        INSTR_BARRIER;
        if (status == BUFFER_WAITING) {
            // we may perform our write, remember last WORD is for status flag
            // why not memcpy? the memcpy implementation is not as fast as this, we could
            // potentially get bigger speedup using vector registers
            for (int i = 0; i < STATUS_OFFSET_B; i++) {
                rb->start[rb->index + i] = casted_data[i];
            }

            // The barrier here ensures that status does not become BUFFER_READY before
            // all writes propagate.
            DATA_BARRIER;
            INSTR_BARRIER;
            rb->start[rb->index + STATUS_OFFSET_B] = BUFFER_READY;
            break;
        }
    }

    rb->index = get_next_index(rb);
}

errval_t ump_ringbuffer_read(struct ump_ringbuffer *rb, void *data, size_t len,
                             bool is_blocking)
{
    assert(len == DATA_SIZE_B);
    assert(rb->mode == UMP_RINGBUFFER_MODE_READER);

    slot_type_t *casted_data = (slot_type_t *)data;

    while (1) {
        // we are reading most of this data, but we do update the flag hence the value '1'
        __builtin_prefetch((const void *)&rb->start[rb->index], 1, 3);

        slot_type_t status = rb->start[rb->index + STATUS_OFFSET_B];
        assert(status == BUFFER_READY || status == BUFFER_WAITING);

        DATA_BARRIER;
        INSTR_BARRIER;
        if (status == BUFFER_READY) {
            for (int i = 0; i < STATUS_OFFSET_B; i++) {
                casted_data[i] = rb->start[rb->index + i];
            }

            // We need this barrier to ensure that status is changed only after all reads
            // propagate.
            DATA_BARRIER;
            INSTR_BARRIER;
            rb->start[rb->index + STATUS_OFFSET_B] = BUFFER_WAITING;
            break;
        }

        if (!is_blocking) {
            return LIB_ERR_NO_UMP_MSG;
        }
    }

    rb->index = get_next_index(rb);
    return SYS_ERR_OK;
}
