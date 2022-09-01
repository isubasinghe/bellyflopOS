#ifndef _LIB_BARRELFISH_AOS_RPC_LMP_H
#define _LIB_BARRELFISH_AOS_RPC_LMP_H

#include <aos/aos.h>
#include <errors/errno.h>

errval_t aos_rpc_lmp_recv_blocking(struct lmp_chan *chan, uint8_t **buf_uint8,
                                   size_t *buflen, struct capref *cap);

errval_t aos_rpc_lmp_send(struct lmp_chan *chan, uint8_t *buf, size_t buflen,
                          struct capref cap);

// Needed for memory server to avoid a nested RPC when allocating a new slot for recv_slot.
errval_t aos_rpc_lmp_recv_blocking_with_empty_slot(struct lmp_chan *chan, uint8_t **buf,
                                                   size_t *buflen, struct capref *cap,
                                                   struct capref empty_slot);

#endif  //_LIB_BARRELFISH_AOS_RPC_LMP_H
