#include <stdio.h>
#include <stdlib.h>
#include <aos/terminal.h>
#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>
#include <aos/inthandler.h>
#include <driverkit/driverkit.h>
#include <maps/imx8x_map.h>
#include <aos/macros.h>
#include <aos/rpc/rpcs.pb-c.h>
#include <aos/dispatcher_arch.h>
#include <aos/nameserver.h>
#include <collections/hash_table.h>
#include <aos/thread_sync.h>
#include <aos/threads.h>

static struct lpuart_s *driver;
static struct gic_dist_s *gic;
static struct ump_chan ump_chan;

enum buffer_type { String, Char };

typedef errval_t (*putchar_func_t)(char c);
typedef errval_t (*putstring_func_t)(const char* str, size_t len, size_t* written);
typedef errval_t (*getchar_func_t)(char *c);

// LPUART Device
static errval_t putchar_lqart(char c) {
    if(c == '\n') {
        lpuart_putchar(driver, '\r');
    }
    return lpuart_putchar(driver, c);
}

static errval_t putstring_lqart(const char* str, size_t len, size_t* ret_written) {
    errval_t err = SYS_ERR_OK;
    size_t written = 0;
    while (written != len) {
        if(*str=='\n') {
            err = putchar_lqart('\r');
            RETURN_IF_ERR(err);
            GOTO_IF_ERR(err, end);
        }
        err = putchar_lqart(*str);
        GOTO_IF_ERR(err, end);
        str++;
        written++;
    }
end:
    *ret_written = written;
    return err;
}

static errval_t getchar_lqart(char *c) {
    return lpuart_getchar(driver, c);
}

// UMP Device

static errval_t putchar_ump(char c)
{
    return ump_chan_send(&ump_chan,(uint8_t*) &c, 1, NULL_CAP);
}

static errval_t do_nothing(char c)
{
    return SYS_ERR_OK;
}

static errval_t putstring_ump(const char* c, size_t len, size_t *written)
{
    errval_t err =  ump_chan_send(&ump_chan,(uint8_t*) c, len, NULL_CAP);
    if(err_is_fail(err)) {
        *written = 0;
        return err;
    }
    *written = len;
    return SYS_ERR_OK;
}

static char* cur_network_buf = NULL;
static size_t cur_network_buf_size = 0;
static size_t cur_network_buf_pos = 0;

putchar_func_t putchar_func = &putchar_lqart;
putchar_func_t repeat_input_func = &putchar_lqart;
putstring_func_t putstring_func = &putstring_lqart;
getchar_func_t getchar_func = &getchar_lqart;

static errval_t getchar_ump(char *c)
{
    if (cur_network_buf_pos < cur_network_buf_size) {
        *c = cur_network_buf[cur_network_buf_pos];
        cur_network_buf_pos++;
        return SYS_ERR_OK;
    }

    size_t buflen = 1;
    uint8_t* buf = (uint8_t*) c;
    errval_t err = ump_chan_recv_blocking(&ump_chan, &buf, &buflen, NULL);
    RETURN_IF_ERR(err);
    if(buflen == 0) {
        // That means the channel is closed.
        putchar_func = &putchar_lqart;
        repeat_input_func = &putchar_lqart;
        putstring_func = &putstring_lqart;
        getchar_func = &getchar_lqart;
        static char* get_back_string = "\nYou got the shell back!\n$> ";
        size_t written;
        putstring_func(get_back_string, strlen(get_back_string), &written);
        return SYS_ERR_OK;
    }
    if(buflen == 1){
        return SYS_ERR_OK;
    }
    free(cur_network_buf);
    cur_network_buf_size = buflen;
    cur_network_buf = (char*) buf;
    cur_network_buf_pos = 0;
    *c = cur_network_buf[cur_network_buf_pos];
    cur_network_buf_pos++;

    return SYS_ERR_OK;    
}


// Function pointers s.t. the output "device" can be changed.



struct io_buffer {
    enum buffer_type type;
    union {
        char *data;
        char c;
    } data;
};

struct node;

struct node {
    void *data;
    char should_free;
    struct node *prev;
    struct node *next;
};

struct linked_list {
    struct node *head;
    struct node *tail;
};

__unused static void linked_list_init(struct linked_list *llist)
{
    llist->head = NULL;
    llist->tail = NULL;
}

__unused static struct node *linked_list_insert(struct linked_list *llist, void *data,
                                                char should_free)
{
    if (llist->head == NULL) {
        llist->head = malloc(sizeof(struct node));
        llist->head->data = data;
        llist->head->next = NULL;
        llist->head->prev = NULL;
        llist->tail = llist->head;
        return llist->head;
    }


    struct node *new = malloc(sizeof(struct node));
    new->prev = llist->tail;
    new->next = NULL;
    new->data = data;
    new->should_free = should_free;

    llist->tail->next = new;
    llist->tail = new;

    return new;
}

static void free_node(struct node *node)
{
    if (node->should_free) {
        free(node->data);
    }
    free(node);
}

__unused static void linked_list_remove(struct linked_list *llist, struct node *node)
{
    if (llist->tail == node) {
        llist->tail = node->prev;
    }

    if (llist->head == node) {
        llist->head = NULL;
        llist->head->prev = NULL;
        llist->head->next = NULL;
        llist->tail = NULL;
        free_node(node);
        return;
    }


    struct node *prev = node->prev;
    struct node *next = node->next;
    prev->next = node;
    if (next != NULL) {
        next->prev = prev;
    }
    free_node(node);
}

__unused static struct node *linked_list_pop(struct linked_list *llist)
{
    if (llist->head == NULL) {
        return NULL;
    }
    struct node *n = llist->head;
    llist->head = n->next;
    // we popped off the last element so set tail
    if (n == llist->tail) {
        llist->tail = NULL;
    }

    return n;
}

struct terminal_client {
    struct linked_list write_buf;
    struct linked_list read_buf;
};

__unused static void terminal_client_init(struct terminal_client *c)
{
    linked_list_init(&c->write_buf);
    linked_list_init(&c->read_buf);
}

struct terminal_clients {
    collections_hash_table *clients;
    volatile int64_t owner;
    struct thread_mutex data_mutex;
    struct thread_mutex read_mutex;
    struct thread_mutex write_mutex;
};


static void terminal_clients_init(struct terminal_clients *tc)
{
    collections_hash_create(&tc->clients, free);
    tc->owner = NO_OWNER;
    thread_mutex_init(&tc->data_mutex);
    thread_mutex_init(&tc->read_mutex);
    thread_mutex_init(&tc->write_mutex);
}


static const char* secure_shell_banner = 
" _________________________________________________________ \n"   
"|         Welcome to the BellyFlop SeCuRe ShElL           |\n"
"|_________________________________________________________|\n$> ";                  
                                                                                                                                                                          

__unused static struct terminal_client *curr_client = NULL;

static errval_t server_handler(void *server_state, RpcMethod method,
                               RpcRequestWrap *req_wrap, struct capref req_cap,
                               RpcResponseWrap *res_wrap, struct capref *res_cap)
{
    struct terminal_clients *cl = server_state;
    assert(cl != NULL);
    assert(req_wrap != NULL);
    assert(res_wrap != NULL);
    assert(cl->clients != NULL);

    errval_t err = SYS_ERR_OK;
    switch (method) {
    case RPC_METHOD__TERM_SWITCH_TO_UMP: {  
        static char* exit_string = "The shell was taken over.\n"
                "You will gain access again when the remote closes its session.\n";
        size_t bytes_written;
        putstring_func(exit_string, strlen(exit_string), &bytes_written);
        assert(!capref_is_null(req_cap));
        struct frame_identity id;
        err = frame_identify(req_cap, &id);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_IDENTIFY);
        
        void *urpc_buf;
        size_t urpc_bytes = id.bytes;
        err = paging_map_frame_attr(get_current_paging_state(), &urpc_buf, urpc_bytes,
                                    req_cap, VREGION_FLAGS_READ_WRITE);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

        ump_chan_init_split(&ump_chan, urpc_buf, urpc_bytes, UMP_CHAN_BUF_LAYOUT_SEND_RECV);
        putchar_func = &putchar_ump;
        putstring_func = &putstring_ump;
        getchar_func = &getchar_ump;
        repeat_input_func = &do_nothing;
        
        //static const char *welcome_string = "Welcome to the BellyFlop SeCuRE ShElL server!\n$> ";
        size_t written;
        err = putstring_ump(secure_shell_banner, strlen(secure_shell_banner), &written);
        RETURN_IF_ERR(err);
        break;
    }
    case RPC_METHOD__TERM_REGISTER_CLIENT: {
        TermRegisterClientResponse *res = malloc(sizeof(TermRegisterClientResponse));
        term_register_client_response__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_REGISTER_CLIENT;
        res_wrap->term_register_client = res;

        // case client has already registered
        __unused domainid_t pid = req_wrap->term_register_client->pid;
        thread_mutex_lock(&cl->data_mutex);

        struct terminal_client *c = collections_hash_find(
            cl->clients, req_wrap->term_register_client->pid);
        if (c != NULL) {
            res->status = ALREADY_REGISTERED;
            res_wrap->term_register_client = res;
        }

        c = malloc(sizeof(struct terminal_client));
        terminal_client_init(c);
        collections_hash_insert(cl->clients, req_wrap->term_register_client->pid, c);


        // check if we can give lock away
        if (req_wrap->term_register_client->lock == 1) {
            // another has the lock
            if (cl->owner != -1) {
                res->status = OTHER_LOCK;
                thread_mutex_unlock(&cl->data_mutex);
                return SYS_ERR_OK;
            }
            // give the client the lock
            cl->owner = req_wrap->term_register_client->pid;
            curr_client = c;
        }

        thread_mutex_unlock(&cl->data_mutex);
        res->status = STATUS_OK;
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_REGISTER_CLIENT;
        return SYS_ERR_OK;
    } break;
    case RPC_METHOD__TERM_ACQUIRE_LOCK: {
        TermAcquireLockResponse *res = malloc(sizeof(TermAcquireLockResponse));
        term_acquire_lock_response__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_ACQUIRE_LOCK;
        res_wrap->term_acquire_lock = res;
        
        thread_mutex_lock(&cl->data_mutex);
        if (cl->owner != NO_OWNER) {
            if (cl->owner == req_wrap->term_acquire_lock->pid) {
                res->status = ALREADY_LOCK;
            } else {
                res->status = OTHER_LOCK;
            }
            thread_mutex_unlock(&cl->data_mutex);
            return SYS_ERR_OK;
        } 
        res->status = STATUS_OK;
        cl->owner = req_wrap->term_acquire_lock->pid;
        struct terminal_client *c = collections_hash_find(cl->clients, cl->owner);
        assert(c != NULL);
        curr_client = c;
        thread_mutex_unlock(&cl->data_mutex);

        return SYS_ERR_OK;
    } break;
    case RPC_METHOD__TERM_RELEASE_LOCK: {
        
        thread_mutex_lock(&cl->data_mutex);
        if (req_wrap->term_release_lock->pid == cl->owner) {
            cl->owner = NO_OWNER;
        }
        thread_mutex_unlock(&cl->data_mutex);
    } break;
    case RPC_METHOD__TERM_WRITE_STRING: {
        TermWriteStringResponse *res = malloc(sizeof(TermWriteStringResponse));
        term_write_string_response__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_WRITE;
        res_wrap->term_write = res;
        
        thread_mutex_lock(&cl->data_mutex);
        struct terminal_client *c = NULL;
        c = collections_hash_find(cl->clients, req_wrap->term_write->pid);
        if (c == NULL) {
            c = malloc(sizeof(struct terminal_client));
            terminal_client_init(c);
            collections_hash_insert(cl->clients, req_wrap->term_write->pid, c);
        }
        thread_mutex_unlock(&cl->data_mutex);
        
        thread_mutex_lock(&cl->write_mutex);
        err = putstring_func(req_wrap->term_write->str, req_wrap->term_write->len, &res->written);
        thread_mutex_unlock(&cl->write_mutex);

        return SYS_ERR_OK;
    } break;
    case RPC_METHOD__TERM_READ_CHAR: {
        TermReadCharRespnose *res = malloc(sizeof(TermReadCharRespnose));
        term_read_char_respnose__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_GETC;
        res_wrap->term_getc = res;

        if (req_wrap->term_getc->pid != cl->owner) {
            res->status = OTHER_LOCK;
            res->chr = EOF;
            return SYS_ERR_OK;
        }
        
        if (cl->owner == req_wrap->term_getc->pid) {
            // try read
            thread_mutex_lock(&cl->read_mutex);
            while(1) {
                char c;
                errval_t err1 = getchar_func(&c);
                if (err_is_fail(err1)) {
                    res->status = NO_DATA;
                    res->chr = EOF;
                    if(!(req_wrap->term_getc->block)) {
                        break;
                    }
                } else {
                    if(c == '\r') {
                        repeat_input_func('\n');
                    }else if(c==127) {
                        repeat_input_func('\b');
                        repeat_input_func(' ');
                        repeat_input_func('\b');
                        continue; 
                    }
                    
                    repeat_input_func(c);
                    res->chr = c;
                    res->status = STATUS_OK;
                    break;
                }
            }
            thread_mutex_unlock(&cl->read_mutex);
            res_wrap->term_getc = res;
            return SYS_ERR_OK;
        }
        return SYS_ERR_OK;
    } break;
    case RPC_METHOD__TERM_WRITE_CHAR: {
        TermWriteCharResponse *res = malloc(sizeof(TermWriteCharResponse));
        term_write_char_response__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_PUTC;
        res_wrap->term_putc = res;
        
        thread_mutex_lock(&cl->data_mutex);
        struct terminal_client *c = NULL;
        c = collections_hash_find(cl->clients, req_wrap->term_write->pid);
        if (c == NULL) {
            c = malloc(sizeof(struct terminal_client));
            terminal_client_init(c);
            collections_hash_insert(cl->clients, req_wrap->term_write->pid, c);
        }
        thread_mutex_unlock(&cl->data_mutex);

        if (cl->owner == req_wrap->term_putc->pid && req_wrap->term_putc->try_write) {
            thread_mutex_lock(&cl->write_mutex);
            errval_t err1 = putchar_func(req_wrap->term_putc->chr);
            if (err_is_fail(err1)) {
                res->status = LPUART_ERR;
            } else {
                res->status = STATUS_OK;
            }
            thread_mutex_unlock(&cl->write_mutex);
            return SYS_ERR_OK;
        }
        
        thread_mutex_lock(&cl->data_mutex);
        struct io_buffer *iobuf = malloc(sizeof(struct io_buffer));
        iobuf->type = Char;
        iobuf->data.c = req_wrap->term_putc->chr;
        linked_list_insert(&c->read_buf, iobuf, 1);
        res->status = STATUS_OK;
        thread_mutex_unlock(&cl->data_mutex);
        return SYS_ERR_OK;
    } break;
    case RPC_METHOD__TERM_READ_STRING: {
        TermReadStringResponse *res = malloc(sizeof(TermReadStringResponse));
        term_read_string_response__init(res);
        res_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TERM_READ_STR;
        res_wrap->term_read_str = res;

        if (req_wrap->term_read_str->pid != cl->owner) {
            return SYS_ERR_NOT_IMPLEMENTED;
        }

        thread_mutex_lock(&cl->data_mutex);
        struct terminal_client *c = NULL;
        c = collections_hash_find(cl->clients, req_wrap->term_read_str->pid);
        assert(curr_client == c && c != NULL);
        thread_mutex_unlock(&cl->data_mutex);

        int64_t *str_64 = malloc(sizeof(char) * 1024);
        for (size_t i = 0; i < (1024) / sizeof(int64_t); i++) {
            str_64[i] = 0;
        }

        char *str = (char *)str_64;
        size_t cap = 1024;
        size_t written = 0;


        struct node *n = linked_list_pop(&c->read_buf);
        while (n != NULL) {
            struct io_buffer *b = n->data;

            if (b->type == String) {
                size_t dlen = strlen(b->data.data);
                if (dlen >= cap) {
                    free(str);
                    str = strdup(b->data.data);
                } else {
                    strcpy(str, b->data.data);
                }
                res->str = str;
                free_node(n);
                return SYS_ERR_OK;

            } else if (b->type == Char) {
                if (b->data.c == '\n' || b->data.c == '\r') {
                    res->str = str;
                    return SYS_ERR_OK;
                }
                if (written + 2 > cap) {
                    str = realloc(str, cap * 2);
                    cap = cap * 2;
                }
                str[written] = b->data.c;
                written++;
            }
            free_node(n);
            n = linked_list_pop(&c->read_buf);
        }
        
        thread_mutex_lock(&cl->read_mutex);
        while (1) {
            char chr;
            errval_t lerr = getchar_func(&chr);
            if (err_is_fail(lerr)) {
                continue;
            }
            repeat_input_func(chr);

            if(chr == '\r') {
                repeat_input_func('\n');
            }else if(chr==127) {
                if(written > 0) {
                    str[written-1] = 0;
                    written--;

                    repeat_input_func('\b');
                    repeat_input_func(' ');
                    repeat_input_func('\b');
                }
                continue;
            }

            if (chr == '\n' || chr == '\r') {
                break;
            }
            if (written + 2 > cap) {
                str = realloc(str, cap * 2);
                cap = cap * 2;
            }
            str[written] = chr;
            written++;
        }

        res->str = str;
        thread_mutex_unlock(&cl->read_mutex);
        return SYS_ERR_OK;

    } break;
    case RPC_METHOD__TERM_DEBUG: {
        DEBUG_PRINTF("OWNER IS %ld\n", cl->owner);
    } break;
    default:
        return SYS_ERR_OK;
        break;
    }
    return err;
}


// this is not triggered and reads are done in the service handler
static void interrupt_handler(void *arg)
{
    char c;
    errval_t err;
    while (1) {
        err = getchar_func(&c);
        if (err_is_fail(err)) {
            break;
        }
        printf("GOT %c\n", c);
    }
}


int main(int argc, char *argv[])
{
    errval_t err;


    assert(disp_get_core_id() == 0);
    err = cap_copy(cap_irq, task_cap_argcn2);
    if (err_is_fail(err)) {
        printf("UNABLE TO COPY CAP_IRQ\n");
        return -1;
    }


    lvaddr_t gic_addr;
    struct capref c;
    err = map_device_register(IMX8X_GIC_DIST_BASE, IMX8X_GIC_DIST_SIZE, task_cap_argcn1,
                              &c, &gic_addr);
    if (err_is_fail(err)) {
        return -1;
    }
    err = gic_dist_init(&gic, (void *)gic_addr);
    if (err_is_fail(err)) {
        return -1;
    }

    lvaddr_t term_addr;
    struct capref lpuart_cap;
    err = map_device_register(IMX8X_UART0_BASE, IMX8X_UART_SIZE, task_cap_argcn0,
                              &lpuart_cap, &term_addr);
    if (err_is_fail(err)) {
        return -1;
    }
    err = lpuart_init(&driver, (void *)term_addr);
    if (err_is_fail(err)) {
        return -1;
    }

    struct capref irq_dest;
    err = inthandler_alloc_dest_irq_cap(IMX8X_UART0_INT, &irq_dest);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("FUCK FUCK FUCK\n\n\n");
        return -1;
    }

    err = inthandler_setup(irq_dest, get_default_waitset(),
                           MKCLOSURE(interrupt_handler, NULL));
    if (err_is_fail(err)) {
        DEBUG_PRINTF("INIT HANDLER SETUP FAILED\n");
        return -1;
    }
    DEBUG_PRINTF("SETUP HANDLER\n");


    err = gic_dist_enable_interrupt(gic, IMX8X_UART0_INT, 0, 5);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("IT FAILEDDD\n\n\n\n");
        return -1;
    }

    lpuart_enable_interrupt(driver);


    DEBUG_PRINTF("ENABLED INTERRUPTS\n");

    struct terminal_clients tc;

    terminal_clients_init(&tc);
    
    err = nameservice_register_proto("terminal", server_handler, &tc);

    if (err_is_fail(err)) {
        DEBUG_PRINTF("UNABLE TO RUN TERMINAL SERVICE\n\n\n\n\n\n\n\n\n\n\n");
        DEBUG_ERR(err, "TERMINAL ERR\n");
        return -1;
    }
    // Hang around.
    while (true) {
        ASSERT_ERR_OK(event_dispatch(get_default_waitset()));
    }
    return 0;
}
