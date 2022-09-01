#include <aos/terminal.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/thread_sync.h>
#include <aos/aos_rpc.h>
#include <errno.h>
#include <limits.h>

struct aos_terminal *aos_terminal_init(void)
{
    struct aos_terminal *term = malloc(sizeof(struct aos_terminal));
    errval_t err;
    err = nameservice_lookup("terminal", &term->chan);
    if (err_is_fail(err)) {
        free(term);
        return NULL;
    }
    term->curr_pid = disp_get_domain_id();
    return term;
}

char *aos_terminal_readline(struct aos_terminal *term)
{
    char *buffer = NULL;
    TermReadStringRequest req;
    term_read_string_request__init(&req);
    req.pid = term->curr_pid;
    REQUEST_WRAP(req_wrap, term_read_str, TERM_READ_STR, &req);

    RpcResponseWrap *res_wrap;
    errval_t err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_READ_STRING,
                                         &req_wrap, NULL_CAP, &res_wrap, NULL);
    if (err_is_fail(err)) {
        return NULL;
    }
    buffer = strdup(res_wrap->term_read_str->str);
    RESPONSE_WRAP_DESTROY(res_wrap);
    return buffer;
}

void aos_terminal_writebuf(struct aos_terminal *term, char *s, uint64_t len) 
{
    errval_t err = SYS_ERR_OK;
    TermWriteStringRequest req = TERM_WRITE_STRING_REQUEST__INIT;
    req.pid = term->curr_pid;
    req.str = s;
    req.try_write = true;
    req.len = len;

    REQUEST_WRAP(req_wrap, term_write, TERM_WRITE, &req);

    RpcResponseWrap *res_wrap;
    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_WRITE_STRING, &req_wrap,
                                NULL_CAP, &res_wrap, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to write");
    }
    RESPONSE_WRAP_DESTROY(res_wrap);
}

bool aos_terminal_lock(struct aos_terminal *term)
{
    errval_t err = SYS_ERR_OK;
    TermAcquireLockRequest req = TERM_ACQUIRE_LOCK_REQUEST__INIT;
    req.pid = term->curr_pid;
    REQUEST_WRAP(req_wrap, term_acquire_lock, TERM_ACQUIRE_LOCK, &req);
    RpcResponseWrap *resp_wrap;
    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_ACQUIRE_LOCK, &req_wrap,
                                NULL_CAP, &resp_wrap, NULL);
    if (err_is_fail(err)) {
        return false;
    }
    int64_t status = resp_wrap->term_acquire_lock->status;
    
    RESPONSE_WRAP_DESTROY(resp_wrap);


    if(status == ALREADY_LOCK || status == STATUS_OK) {
        return true;
    }

    return false;
}

void aos_terminal_release(struct aos_terminal *term)
{
    errval_t err = SYS_ERR_OK;
    TermReleaseLockRequest req = TERM_RELEASE_LOCK_REQUEST__INIT;
    req.pid = term->curr_pid;
    REQUEST_WRAP(req_wrap, term_release_lock, TERM_RELEASE_LOCK, &req);
    RpcResponseWrap *resp_wrap;
    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_RELEASE_LOCK, &req_wrap,
                                NULL_CAP, &resp_wrap, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to release");
    }

    RESPONSE_WRAP_DESTROY(resp_wrap);
}

void aos_terminal_register(struct aos_terminal *term, bool lock)
{
    errval_t err = SYS_ERR_OK;
    TermRegisterClientRequest req = TERM_REGISTER_CLIENT_REQUEST__INIT;
    req.pid = term->curr_pid;
    req.lock = lock;

    REQUEST_WRAP(req_wrap, term_register_client, TERM_REGISTER_CLIENT, &req);

    RpcResponseWrap *res_wrap;
    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_REGISTER_CLIENT, &req_wrap,
                                NULL_CAP, &res_wrap, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to write");
    }
    RESPONSE_WRAP_DESTROY(res_wrap);
}

signed char aos_terminal_putc(struct aos_terminal *term, signed char c) {
    errval_t err = SYS_ERR_OK;
    TermWriteCharRequest req;
    term_write_char_request__init(&req);

    req.pid = term->curr_pid;
    req.chr = c;
    req.try_write = true;

    REQUEST_WRAP(req_wrap, term_putc, TERM_PUTC, &req);

    RpcResponseWrap *res_wrap;

    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_WRITE_CHAR, &req_wrap, NULL_CAP, &res_wrap, NULL);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "unable to write");
        RESPONSE_WRAP_DESTROY(res_wrap);
        return EOF;
    }
    if(res_wrap->term_putc->status != STATUS_OK) {
        RESPONSE_WRAP_DESTROY(res_wrap);
        return EOF;
    }
    
    RESPONSE_WRAP_DESTROY(res_wrap);
    return c;
}

signed char aos_terminal_getc(struct aos_terminal *term, bool block) {
    errval_t err = SYS_ERR_OK;
    TermReadCharRequest req;
    term_read_char_request__init(&req);
    
    req.pid = term->curr_pid;
    req.block = block;
    REQUEST_WRAP(req_wrap, term_getc, TERM_GETC, &req);
    RpcResponseWrap *res_wrap;
    err = nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_READ_CHAR, &req_wrap, NULL_CAP, &res_wrap, NULL);
    if(err_is_fail(err)) {
        RESPONSE_WRAP_DESTROY(res_wrap);
        return EOF;
    }
    if(res_wrap->term_getc->status != STATUS_OK) {
        RESPONSE_WRAP_DESTROY(res_wrap);
        return EOF;
    }
    RESPONSE_WRAP_DESTROY(res_wrap);
    return res_wrap->term_getc->chr;
}

struct aos_terminal *get_default_terminal(void) {
    while(__default_term == NULL) {
        __default_term = aos_terminal_init();
        aos_terminal_register(__default_term, false);
    }
    return __default_term;
}

void aos_terminal_debug(struct aos_terminal *term) {
    TermDebugRequest req;
    term_debug_request__init(&req);

    REQUEST_WRAP(req_wrap, term_debug, TERM_DEBUG, &req);
    RpcResponseWrap *res_wrap;
    nameservice_rpc_proto(term->chan, RPC_METHOD__TERM_DEBUG, &req_wrap, NULL_CAP, &res_wrap, NULL);

    RESPONSE_WRAP_DESTROY(res_wrap);
}
