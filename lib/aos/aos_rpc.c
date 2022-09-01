/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/ump_chan.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/macros.h>
#include <aos/rpc/rpcs.pb-c.h>

// Not 4 because of the uintptr_t header in the aos_rpc_lmp layer.
#define MAX_SMALL_MSG_B (3 * sizeof(uintptr_t))

// Needs to be bigger than a few LMP messages to get a reasonable speed with bigger messages.
#define LMP_BUF_WORDS (10 * LMP_RECV_LENGTH)

#define GOTO_IF_MSG_IS_ERR(err, msg, label)                                              \
    do {                                                                                 \
        if ((msg).datatype == AOS_RPC_Err) {                                             \
            err = aos_rpc_msg_to_errval_t(&(msg));                                       \
            goto label;                                                                  \
        }                                                                                \
    } while (0)

// Function declarations so that we don't have to care about definition order.
static errval_t aos_rpc_init_lmp_client(struct aos_rpc *rpc, struct capref remote_ep);
static void aos_rpc_eventhandler(void *args);
static errval_t aos_rpc_send(struct aos_rpc *rpc, uint8_t *buf, size_t buflen,
                             struct capref cap);
static errval_t aos_rpc_send_msg(struct aos_rpc *rpc, RpcMessage *msg, struct capref cap);
static errval_t aos_rpc_recv_blocking(struct aos_rpc *rpc, uint8_t **buf, size_t *buflen,
                                      struct capref *cap);
static errval_t aos_rpc_recv_msg_blocking(struct aos_rpc *rpc, RpcMessage **msg,
                                          struct capref *cap);
static errval_t aos_rpc_register_recv(struct aos_rpc *rpc, struct waitset *ws,
                                      struct event_closure closure);

errval_t aos_rpc_init_lmp_server(struct aos_rpc *rpc, struct waitset *waitset,
                                 aos_rpc_eventhandler_t eventhandler, void *server_state)
{
    thread_mutex_init(&rpc->mutex);
    lmp_chan_init(&rpc->chan.lmp);

    rpc->chan_type = AOS_RPC_CHAN_TYPE_LMP;
    rpc->ws = waitset;
    rpc->eventhandler = eventhandler;
    rpc->server_state = server_state;
    errval_t err;

    rpc->chan.lmp.remote_cap = NULL_CAP;
    err = endpoint_create(LMP_BUF_WORDS, &rpc->chan.lmp.local_cap,
                          &rpc->chan.lmp.endpoint);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_ENDPOINT_CREATE);

    // Initialize receive slot.
    err = lmp_chan_alloc_recv_slot(&rpc->chan.lmp);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);

    // Register callback to receive the child endpoint.
    err = lmp_chan_register_recv(&rpc->chan.lmp, waitset,
                                 MKCLOSURE(&aos_rpc_eventhandler, rpc));
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CHAN_REGISTER_RECV);

    return SYS_ERR_OK;
}

static errval_t aos_rpc_init_lmp_client(struct aos_rpc *rpc, struct capref remote_ep)
{
    thread_mutex_init(&rpc->mutex);
    lmp_chan_init(&rpc->chan.lmp);

    rpc->chan_type = AOS_RPC_CHAN_TYPE_LMP;
    rpc->ws = NULL;
    rpc->server_state = NULL;
    rpc->eventhandler = NULL;
    errval_t err;

    // This is where the local endpoint is created and minted.
    err = lmp_chan_accept(&rpc->chan.lmp, LMP_BUF_WORDS, remote_ep);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LMP_CHAN_ACCEPT);

    // Initialize receive slot.
    err = lmp_chan_alloc_recv_slot(&rpc->chan.lmp);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);

    return SYS_ERR_OK;
}

errval_t aos_rpc_init_ump_server(struct aos_rpc *rpc, void *buf, size_t buflen,
                                 struct waitset *waitset,
                                 aos_rpc_eventhandler_t eventhandler, void *server_state)
{
    thread_mutex_init(&rpc->mutex);

    rpc->chan_type = AOS_RPC_CHAN_TYPE_UMP;
    rpc->ws = waitset;
    rpc->eventhandler = eventhandler;
    rpc->server_state = server_state;

    ump_chan_init_split(&rpc->chan.ump, buf, buflen, UMP_CHAN_BUF_LAYOUT_RECV_SEND);
    errval_t err = ump_chan_register_recv(&rpc->chan.ump, waitset,
                                          MKCLOSURE(&aos_rpc_eventhandler, rpc));
    return err;
}

void aos_rpc_init_ump_client(struct aos_rpc *rpc, void *buf, size_t buflen)
{
    thread_mutex_init(&rpc->mutex);

    rpc->chan_type = AOS_RPC_CHAN_TYPE_UMP;
    rpc->ws = NULL;
    rpc->server_state = NULL;
    rpc->eventhandler = NULL;

    ump_chan_init_split(&rpc->chan.ump, buf, buflen, UMP_CHAN_BUF_LAYOUT_SEND_RECV);
}

errval_t aos_rpc_register_recv(struct aos_rpc *rpc, struct waitset *ws,
                               struct event_closure closure)
{
    switch (rpc->chan_type) {
    case AOS_RPC_CHAN_TYPE_LMP:
        return lmp_chan_register_recv(&rpc->chan.lmp, ws, closure);
    case AOS_RPC_CHAN_TYPE_UMP:
        return ump_chan_register_recv(&rpc->chan.ump, ws, closure);
    default:
        DEBUG_PRINTF("Unknown chan_type: %d", rpc->chan_type);
        assert(0);
        return LIB_ERR_IMPOSSIBLE;
    }
}

static errval_t aos_rpc_send_local_lmp_ep(struct aos_rpc *rpc)
{
    thread_mutex_lock(&rpc->mutex);

    RpcRequestWrap wrap = RPC_REQUEST_WRAP__INIT;
    wrap.data_case = RPC_REQUEST_WRAP__DATA__NOT_SET;
    RpcMessage msg = RPC_MESSAGE__INIT;
    msg.method = RPC_METHOD__SEND_LOCAL_LMP_EP;
    msg.direction_case = RPC_MESSAGE__DIRECTION_REQUEST;
    msg.request = &wrap;

    errval_t err = aos_rpc_send_msg(rpc, &msg, rpc->chan.lmp.local_cap);
    GOTO_IF_ERR(err, end);
end:
    thread_mutex_unlock(&rpc->mutex);
    return err;
}

errval_t aos_rpc_establish_lmp_client(struct aos_rpc *rpc, struct capref remote_ep)
{
    errval_t err;

    err = aos_rpc_init_lmp_client(rpc, remote_ep);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_INIT);

    err = aos_rpc_send_local_lmp_ep(rpc);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_INIT);

    return SYS_ERR_OK;
}

static errval_t aos_rpc_send(struct aos_rpc *rpc, uint8_t *buf, size_t buflen,
                             struct capref cap)
{
    errval_t err = SYS_ERR_OK;
    switch (rpc->chan_type) {
    case AOS_RPC_CHAN_TYPE_LMP:
        err = aos_rpc_lmp_send(&rpc->chan.lmp, buf, buflen, cap);
        PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_LMP_SEND);
        break;
    case AOS_RPC_CHAN_TYPE_UMP:
        err = ump_chan_send(&rpc->chan.ump, buf, buflen, cap);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_UMP_CHAN_SEND);
        break;
    default:
        DEBUG_PRINTF("Unknown chan_type: %d", rpc->chan_type);
        assert(0);
    }

    return SYS_ERR_OK;
}

static errval_t aos_rpc_send_msg(struct aos_rpc *rpc, RpcMessage *msg, struct capref cap)
{
    errval_t err;

    size_t buflen = rpc_message__get_packed_size(msg);
    uint8_t *buf;
    // The small_buf is needed to bootstrap request memory server (and it's also a small
    // optimization).
    uint8_t small_buf[MAX_SMALL_MSG_B];
    if (buflen > MAX_SMALL_MSG_B) {
        buf = malloc(buflen);
    } else {
        buf = small_buf;
    }
    rpc_message__pack(msg, buf);

    err = aos_rpc_send(rpc, buf, buflen, cap);
    GOTO_IF_ERR(err, end);

end:
    if (buflen > MAX_SMALL_MSG_B) {
        free(buf);
    }
    return err;
}

static errval_t aos_rpc_recv_blocking(struct aos_rpc *rpc, uint8_t **buf, size_t *buflen,
                                      struct capref *cap)
{
    errval_t err;

    switch (rpc->chan_type) {
    case AOS_RPC_CHAN_TYPE_LMP:
        err = aos_rpc_lmp_recv_blocking(&rpc->chan.lmp, buf, buflen, cap);
        PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_LMP_RECV_BLOCKING);
        break;
    case AOS_RPC_CHAN_TYPE_UMP:
        err = ump_chan_recv_blocking(&rpc->chan.ump, buf, buflen, cap);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_UMP_CHAN_RECV);
        break;
    default:
        DEBUG_PRINTF("Unknown chan_type: %d", rpc->chan_type);
        assert(0);
    }

    return SYS_ERR_OK;
}

static errval_t aos_rpc_recv_msg_blocking(struct aos_rpc *rpc, RpcMessage **msg,
                                          struct capref *cap)
{
    assert(cap != NULL && msg != NULL);
    errval_t err;

    uint8_t small_buf[MAX_SMALL_MSG_B];
    uint8_t *buf = small_buf;
    size_t buflen = sizeof(small_buf);

    err = aos_rpc_recv_blocking(rpc, &buf, &buflen, cap);
    RETURN_IF_ERR(err);

    *msg = rpc_message__unpack(NULL, buflen, buf);

    if (buflen > MAX_SMALL_MSG_B) {
        free(buf);
    }
    return err;
}

errval_t aos_rpc_call(struct aos_rpc *rpc, RpcMethod method, RpcRequestWrap *request,
                      struct capref request_cap, RpcResponseWrap **response,
                      struct capref *response_cap)
{
    thread_mutex_lock(&rpc->mutex);
    errval_t err;

    RpcRequestWrap empty_req_wrap = RPC_REQUEST_WRAP__INIT;

    // Send request.
    RpcMessage req_msg = RPC_MESSAGE__INIT;
    req_msg.method = method;
    req_msg.direction_case = RPC_MESSAGE__DIRECTION_REQUEST;
    req_msg.request = (request != NULL) ? request : &empty_req_wrap;

    err = aos_rpc_send_msg(rpc, &req_msg, request_cap);
    GOTO_IF_ERR(err, end);

    // Receive response.
    RpcMessage *res_msg = NULL;
    struct capref response_cap_nonnull = NULL_CAP;
    err = aos_rpc_recv_msg_blocking(rpc, &res_msg, &response_cap_nonnull);
    assert(res_msg->method == req_msg.method);
    assert(res_msg->direction_case == RPC_MESSAGE__DIRECTION_RESPONSE);
    GOTO_IF_ERR(err, end);

    // Take response from the malloced res_msg and clean up. Don't stack multiple
    // AOS_ERR_RPC_REMOTE_ERRs.
    err = res_msg->response->err;
    if (err_pop(err) == AOS_ERR_RPC_REMOTE_ERR) {
        GOTO_IF_ERR(err, end);
    } else {
        PUSH_GOTO_IF_ERR(err, AOS_ERR_RPC_REMOTE_ERR, end);
    }

    if (response != NULL) {
        *response = res_msg->response;
        res_msg->direction_case = RPC_MESSAGE__DIRECTION__NOT_SET;
        res_msg->response = NULL;
    }
    if (response_cap != NULL) {
        *response_cap = response_cap_nonnull;
    }

end:
    thread_mutex_unlock(&rpc->mutex);
    rpc_message__free_unpacked(res_msg, NULL);
    return err;
}

static void aos_rpc_eventhandler(void *args)
{
    errval_t err;

    struct aos_rpc *rpc = (struct aos_rpc *)args;

    RpcMessage *req_msg = NULL;
    struct capref req_cap = NULL_CAP;
    err = aos_rpc_recv_msg_blocking(rpc, &req_msg, &req_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_recv_blocking failed.");
    }

    assert(req_msg->direction_case == RPC_MESSAGE__DIRECTION_REQUEST);
    RpcResponseWrap *res = malloc(sizeof(RpcResponseWrap));
    rpc_response_wrap__init(res);
    struct capref res_cap = NULL_CAP;

    // Handle low-level LMP establishing specially, i.e., don't send response.
    if (req_msg->method == RPC_METHOD__SEND_LOCAL_LMP_EP) {
        goto end;
    }

    err = rpc->eventhandler(rpc->server_state, req_msg->method, req_msg->request, req_cap,
                            res, &res_cap);
    // Error is send as part of the response.
    res->err = err_is_fail(err) ? err : SYS_ERR_OK;

    RpcMessage res_msg = RPC_MESSAGE__INIT;
    res_msg.method = req_msg->method;
    res_msg.direction_case = RPC_MESSAGE__DIRECTION_RESPONSE;
    res_msg.response = res;

    err = aos_rpc_send_msg(rpc, &res_msg, res_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Sending response failed.");
    }

end:
    rpc_message__free_unpacked(req_msg, NULL);
    rpc_response_wrap__free_unpacked(res, NULL);

    err = aos_rpc_register_recv(rpc, rpc->ws, MKCLOSURE(&aos_rpc_eventhandler, args));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_register_recv failed.");
    }
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    InitSendNumberRequest req = INIT_SEND_NUMBER_REQUEST__INIT;
    req.number = num;
    REQUEST_WRAP(req_wrap, init_send_number, INIT_SEND_NUMBER, &req);
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_SEND_NUMBER, &req_wrap, NULL_CAP,
                                NULL, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    InitSendStringRequest req = INIT_SEND_STRING_REQUEST__INIT;
    // I don't like the cast, but they do the same in protobuf-c wiki examples.
    req.str = (char *)string;
    REQUEST_WRAP(req_wrap, init_send_string, INIT_SEND_STRING, &req);
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_SEND_STRING, &req_wrap, NULL_CAP,
                                NULL, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);
    return err;
}

// A custom allocator from static memory just so that we can unpack the message
// of aos_rpc_get_ram_cap() without using malloc.
struct static_alloc_data {
    void *buf;
    size_t buflen;
    size_t next_free;
};

static void *static_alloc(void *allocator_data, size_t size)
{
    struct static_alloc_data *d = (struct static_alloc_data *)allocator_data;
    if (d->next_free + size > d->buflen) {
        return NULL;
    }

    void *ret = (uint8_t *)d->buf + d->next_free;
    d->next_free += size;
    return ret;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // We need to call `slot_alloc()` from outside of the RPC mutex because it might cause
    // a nested call. Note that the default slot allocator, twolevel_slot_alloc, already has
    // a refilling logic inside of it -- it holds an extra page of slots as a "reserve".
    struct capref empty_slot;
    errval_t err;
    err = slot_alloc(&empty_slot);
    RETURN_IF_ERR(err);

    thread_mutex_lock(&rpc->mutex);

    // Send request. A looot of boilerplate unfortunately.
    MemGetRamCapRequest req = MEM_GET_RAM_CAP_REQUEST__INIT;
    req.bytes = bytes;
    req.alignment = alignment;

    RpcRequestWrap wrap = RPC_REQUEST_WRAP__INIT;
    wrap.data_case = RPC_REQUEST_WRAP__DATA_MEM_GET_RAM_CAP;
    wrap.mem_get_ram_cap = &req;

    RpcMessage req_msg = RPC_MESSAGE__INIT;
    req_msg.method = RPC_METHOD__MEM_GET_RAM_CAP;
    req_msg.direction_case = RPC_MESSAGE__DIRECTION_REQUEST;
    req_msg.request = &wrap;

    err = aos_rpc_send_msg(rpc, &req_msg, NULL_CAP);
    PUSH_GOTO_IF_ERR(err, AOS_ERR_RPC_LMP_SEND, end);

    // Receive response.
    uint8_t buf_small[MAX_SMALL_MSG_B];
    uint8_t *buf = buf_small;
    size_t buflen = sizeof(buf_small);

    err = aos_rpc_lmp_recv_blocking_with_empty_slot(&rpc->chan.lmp, &buf, &buflen,
                                                    ret_cap, empty_slot);
    PUSH_GOTO_IF_ERR(err, AOS_ERR_RPC_LMP_RECV_BLOCKING, end);
    // No ret_bytes yet, add custom proto allocator from static memory maybe?
    // The problem is that we cannot unpack the message because the rpc->allocator uses malloc.
    uint8_t alloc_buf[150];
    struct static_alloc_data alloc_data = {
        .buf = alloc_buf,
        .buflen = sizeof(alloc_buf),
        .next_free = 0,
    };
    struct ProtobufCAllocator allocator = {
        .alloc = static_alloc,
        .free = NULL,
        .allocator_data = &alloc_data,
    };

    RpcMessage *res_msg = rpc_message__unpack(&allocator, buflen, buf);
    assert(res_msg->direction_case == RPC_MESSAGE__DIRECTION_RESPONSE);
    err = res_msg->response->err;
    PUSH_GOTO_IF_ERR(err, AOS_ERR_RPC_REMOTE_ERR, end);

    if (ret_bytes != NULL) {
        assert(res_msg->response->data_case == RPC_RESPONSE_WRAP__DATA_MEM_GET_RAM_CAP);
        *ret_bytes = res_msg->response->mem_get_ram_cap->allocated_bytes;
    }
end:
    thread_mutex_unlock(&rpc->mutex);
    return err;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    RpcResponseWrap *res = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_SERIAL_GETCHAR, NULL, NULL_CAP,
                                &res, NULL);
    RETURN_IF_ERR(err);
    assert(res->data_case == RPC_RESPONSE_WRAP__DATA_INIT_SERIAL_GETCHAR);
    *retc = (char)res->init_serial_getchar->value;

    RESPONSE_WRAP_DESTROY(res);

    return SYS_ERR_OK;
}


__attribute__((__used__)) size_t aos_terminal_write(const char *buf, size_t len)
{
    errval_t err = aos_rpc_serial_put_string(aos_rpc_get_init_channel(), buf, len);
    if (err_is_fail(err)) {
        return 0;
    }
    return len;
}

__attribute__((__used__)) size_t aos_terminal_read(char *buf, size_t len)
{
    size_t read = 0;
    while (read != len) {
        char c;
        errval_t err = aos_rpc_serial_getchar(aos_rpc_get_init_channel(), &c);
        if (err_is_fail(err)) {
            debug_printf("Unable to getchar\n");
            return read;
        }
        buf[read] = c;
        read++;
    }
    return read;
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    InitSerialPutcharRequest req = INIT_SERIAL_PUTCHAR_REQUEST__INIT;
    req.value = c;
    REQUEST_WRAP(req_wrap, init_serial_putchar, INIT_SERIAL_PUTCHAR, &req);
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_SERIAL_PUTCHAR, &req_wrap, NULL_CAP,
                                NULL, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_put_string(struct aos_rpc *rpc, const char *str, size_t len)
{
    InitSerialPutStringRequest req = INIT_SERIAL_PUT_STRING_REQUEST__INIT;
    req.str = (char *)str;
    REQUEST_WRAP(req_wrap, init_serial_put_string, INIT_SERIAL_PUT_STRING, &req);
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_SERIAL_PUT_STRING, &req_wrap,
                                NULL_CAP, NULL, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    errval_t err;

    InitProcessSpawnRequest req = INIT_PROCESS_SPAWN_REQUEST__INIT;
    req.core = core;
    req.cmdline = cmdline;
    REQUEST_WRAP(req_wrap, init_process_spawn, INIT_PROCESS_SPAWN, &req);
    RpcResponseWrap *res_wrap = NULL;
    err = aos_rpc_call(rpc, RPC_METHOD__INIT_PROCESS_SPAWN, &req_wrap, NULL_CAP,
                       &res_wrap, NULL);

    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    assert(res_wrap->data_case == RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_SPAWN);
    if (newpid != NULL) {
        *newpid = res_wrap->init_process_spawn->pid;
    }
    RESPONSE_WRAP_DESTROY(res_wrap);

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    assert(name != NULL);

    InitProcessGetNameRequest req = INIT_PROCESS_GET_NAME_REQUEST__INIT;
    req.pid = pid;
    REQUEST_WRAP(req_wrap, init_process_get_name, INIT_PROCESS_GET_NAME, &req);
    RpcResponseWrap *res = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_PROCESS_GET_NAME, &req_wrap,
                                NULL_CAP, &res, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);
    assert(res->data_case == RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_GET_NAME);

    *name = res->init_process_get_name->name;
    res->init_process_get_name->name = NULL;
    RESPONSE_WRAP_DESTROY(res);

    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    assert(pids != NULL && pid_count != NULL);
 
    InitProcessGetAllPidsRequest req = INIT_PROCESS_GET_ALL_PIDS_REQUEST__INIT;
    req.should_query = true;
    
    REQUEST_WRAP(req_wrap, init_process_get_all_pids, INIT_PROCESS_GET_ALL_PIDS, &req);

    RpcResponseWrap *res = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_METHOD__INIT_PROCESS_GET_ALL_PIDS, &req_wrap,
                                NULL_CAP, &res, NULL);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    assert(res->data_case == RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_GET_ALL_PIDS);
    *pids = res->init_process_get_all_pids->pids;
    *pid_count = res->init_process_get_all_pids->n_pids;
    
    // Cleanup
    res->init_process_get_all_pids = NULL;
    res->data_case = RPC_RESPONSE_WRAP__DATA__NOT_SET;
    RESPONSE_WRAP_DESTROY(res);

    return SYS_ERR_OK;
}


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    return get_mem_server_rpc();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    return get_init_rpc();
}
