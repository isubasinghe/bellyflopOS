/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/macros.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/paging_state_rebase.h>
#include <aos/aos_rpc.h>
#include <aos/nameserver.h>
#include <aos/terminal.h>
#include <aos/rpc/rpcs.pb-c.h>

#include "threads_priv.h"
#include "init.h"

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;
struct lmp_endpoint *domain_endpoint;

// RPC to init and mem server.
static struct aos_rpc init_rpc;
static struct aos_rpc mem_rpc;

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);


static bool hotfix__first_exit = false;

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    
    if(!hotfix__first_exit) {
        hotfix__first_exit = true;
        struct aos_terminal *term = get_default_terminal();
        aos_terminal_release(term);
        if(term != NULL) {
            free(term);
        }
    }
    

    InitProcessInformDeathRequest req = INIT_PROCESS_INFORM_DEATH_REQUEST__INIT;
    req.pid = disp_get_domain_id();

    REQUEST_WRAP(req_wrap, init_process_inform_death, INIT_PROCESS_INFORM_DEATH, &req);

    errval_t err = aos_rpc_call(get_init_rpc(), RPC_METHOD__INIT_PROCESS_INFORM_DEATH, &req_wrap, NULL_CAP, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to inform init of death");
    }


    //debug_printf("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {
    }
}

static void libc_assert(const char *expression, const char *file, const char *function,
                        int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf),
                   "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN, disp_name(), expression, function,
                   file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__)) static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if (len) {
        errval_t err = sys_print(buf, len);
        if (err_is_fail(err)) {
            return 0;
        }
    }
    return len;
}

__attribute__((__used__)) static size_t dummy_terminal_read(char *buf, size_t len)
{
    debug_printf("Terminal read NYI!\n");
    return 0;
}


__unused static size_t terminal_write(const char *s, size_t len) {  
    struct aos_terminal *term = get_default_terminal();
    aos_terminal_writebuf(term, (char *)s, len);
    return len;
}

__unused static size_t terminal_read(char *buf, size_t len) {
    struct aos_terminal *term = get_default_terminal();
    size_t i = 0;
    signed char c = aos_terminal_getc(term, true);
    buf[i] = c;
    i++;
    while(i!=len) {
        c = aos_terminal_getc(term, false);
        if(c == EOF) {
            break;
        }
        buf[i] = c;
        i++;
    }
    return i;
}


/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{  
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = terminal_read;
    _libc_terminal_write_func = terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    if (init_domain) {
        _libc_terminal_write_func = syscall_terminal_write;
        _libc_terminal_read_func = dummy_terminal_read;
    }
    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}


/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // Initialize ram_alloc state
    ram_alloc_init();
    /* All domains use smallcn to initialize */
    err = ram_alloc_set(ram_alloc_fixed);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }

    lmp_endpoint_init();

    // HINT: Use init_domain to check if we are the init domain.

    // TODO MILESTONE 3: register ourselves with init

    if (init_domain) {
        // Create the endpoint for init domain. Currently it's not minted.
        err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_RETYPE);
    } else {
        err = aos_rpc_establish_lmp_client(&mem_rpc, cap_memep);
        RETURN_IF_ERR(err);
        set_mem_server_rpc(&mem_rpc);

        err = aos_rpc_establish_lmp_client(&init_rpc, cap_initep);
        RETURN_IF_ERR(err);
        set_init_rpc(&init_rpc);

        err = ram_alloc_set(NULL);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_RAM_ALLOC_SET);

        ram_free_set(NULL);

        // If not on nameserver domain, establish a connection to the nameserver.
        nameservice_chan_t nschan = NULL;
        if (sid_from(disp_get_domain_id(), 0) != NAMESERVER_SERVICEID) {
            err = nameservice_connect(NAMESERVER_SERVICEID, &nschan);
            PUSH_RETURN_IF_ERR(err, LIB_ERR_NAMESERVICE_CONNECT);
        }
        set_nameserver_chan(nschan);
    }

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here
    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
