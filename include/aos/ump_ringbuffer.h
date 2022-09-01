#ifndef UMP_RINGBUFFER_H
#define UMP_RINGBUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// This should be defined already but just in case
#ifndef CACHE_LINE_SIZE
#    define CACHE_LINE_SIZE 64  // we have 64 bytes to play with
#endif

// dealing with the 64 bytes in chunks of 8, it makes dealing with the status register a
// simple array access
typedef uint64_t slot_type_t;

#define SLOT_SIZE_B sizeof(slot_type_t)
#define DATA_SIZE_B (CACHE_LINE_SIZE - SLOT_SIZE_B)
#define STATUS_OFFSET_B (DATA_SIZE_B / SLOT_SIZE_B)

#define DATA_BARRIER __asm volatile("dmb sy\n")
#define INSTR_BARRIER __asm volatile("isb sy\n")

#define BUFFER_WAITING 0
#define BUFFER_READY 1

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

_Static_assert(DATA_SIZE_B > 0, "Data size is less than one byte");
// we need this because we are copying SLOT_SIZE byte(s) at a time
_Static_assert(DATA_SIZE_B % SLOT_SIZE_B == 0, "Data size is not divisable by SLOT_SIZE, "
                                               "you may have to sacrifice some space");

enum ump_ringbuffer_mode {
    UMP_RINGBUFFER_MODE_READER,
    UMP_RINGBUFFER_MODE_WRITER,
};

// A single reader, single writer ringbuffer. Supports parallel reader and writer.
struct ump_ringbuffer {
    volatile slot_type_t *start;
    size_t index;
    size_t num_slots;
    enum ump_ringbuffer_mode mode;
};

// initialise a ump_ringbuffer
void ump_ringbuffer_init(struct ump_ringbuffer *rb, enum ump_ringbuffer_mode mode,
                         void *buf, size_t buflen);

bool ump_ringbuffer_can_read(struct ump_ringbuffer *rb);
bool ump_ringbuffer_can_write(struct ump_ringbuffer *rb, size_t block_count);

// write a DATA_SIZE_B block
void ump_ringbuffer_write(struct ump_ringbuffer *rb, void *data, size_t len);

// Returns LIB_ERR_NO_UMP_MSG if is_blocking is false and there's no new msg.
// read a DATA_SIZE_B block
errval_t ump_ringbuffer_read(struct ump_ringbuffer *rb, void *data, size_t len,
                             bool is_blocking);

#endif  // UMP_RINGBUFFER_H
