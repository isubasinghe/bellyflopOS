/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>
#include <aos/ump_chan.h>
#include <aos/rpc/rpcs.pb-c.h>
#include <aos/rpc/protobuf-c.h>

#define REQUEST_WRAP(varname, method_low, method_up, request_ptr)                        \
    RpcRequestWrap varname = RPC_REQUEST_WRAP__INIT;                                     \
    varname.data_case = RPC_REQUEST_WRAP__DATA_##method_up;                              \
    varname.method_low = request_ptr;

#define RESPONSE_WRAP_DESTROY(res_wrap) rpc_response_wrap__free_unpacked(res_wrap, NULL);

typedef errval_t(aos_rpc_eventhandler_t)(void *server_state, RpcMethod method,
                                         RpcRequestWrap *request_wrap,
                                         struct capref request_cap,
                                         RpcResponseWrap *response_wrap,
                                         struct capref *response_cap);

enum aos_rpc_chan_type {
    AOS_RPC_CHAN_TYPE_UMP,
    AOS_RPC_CHAN_TYPE_LMP,
};

/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_rpc {
    enum aos_rpc_chan_type chan_type;

    union {
        struct lmp_chan lmp;
        struct ump_chan ump;
    } chan;

    // Mutex ensuring that at any point there's only at most one open rpc call.
    struct thread_mutex mutex;

    // Server-specific.
    struct waitset *ws;
    aos_rpc_eventhandler_t *eventhandler;
    void *server_state;
};

/**
 * \brief Initialize an aos_rpc struct for LMP server.
 */
errval_t aos_rpc_init_lmp_server(struct aos_rpc *rpc, struct waitset *waitset,
                                 aos_rpc_eventhandler_t eventhandler, void *server_state);

/**
 * \brief Creates local (child) endpoint and sends it to the init.
 */
errval_t aos_rpc_establish_lmp_client(struct aos_rpc *rpc, struct capref remote_ep);

errval_t aos_rpc_init_ump_server(struct aos_rpc *rpc, void *buf, size_t buflen,
                                 struct waitset *waitset,
                                 aos_rpc_eventhandler_t eventhandler, void *server_state);

void aos_rpc_init_ump_client(struct aos_rpc *rpc, void *buf, size_t buflen);

errval_t aos_rpc_call(struct aos_rpc *rpc, RpcMethod method, RpcRequestWrap *request,
                      struct capref request_cap, RpcResponseWrap **response,
                      struct capref *response_cap);


// ----------------- API from the handout +- -------------------
/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Reads specified bytes into buffer
 */
size_t aos_terminal_read(char *buf, size_t len);
/**
 * \bried Write specified bytes
 */
size_t aos_terminal_write(const char *buf, size_t len);

/**
 * \brief Writes an entire string
 */
errval_t aos_rpc_serial_put_string(struct aos_rpc *rpc, const char *str, size_t len);
/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes);


/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);


/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);

/**
 * \brief Request that the process manager start a new process
 * \arg cmdline the name of the process that needs to be spawned (without a
 *           path prefix) and optionally any arguments to pass to it
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *cmdline, coreid_t core,
                               domainid_t *newpid);


/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid, char **name);


/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan, domainid_t **pids,
                                      size_t *pid_count);


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H
