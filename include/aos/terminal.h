#ifndef TERMINAL_H
#define TERMINAL_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include <aos/thread_sync.h>
#include <aos/threads.h>
#include <aos/nameserver.h>

#define NO_OWNER (-1)


#define STATUS_OK 1
#define ALREADY_LOCK 2
#define OTHER_LOCK 3
#define NO_LOCK 4
#define ALREADY_REGISTERED 5

#define LPUART_ERR 6

#define NO_DATA INT_MAX

__unused static struct aos_terminal *__default_term = NULL;

struct aos_terminal {
    nameservice_chan_t chan;
    domainid_t curr_pid;
};

struct aos_terminal *aos_terminal_init(void);

char *aos_terminal_readline(struct aos_terminal *term);

void aos_terminal_writebuf(struct aos_terminal *term, char *s, uint64_t len);

void aos_terminal_register(struct aos_terminal *term, bool lock);
bool aos_terminal_lock(struct aos_terminal *term);
void aos_terminal_release(struct aos_terminal *term);
signed char aos_terminal_putc(struct aos_terminal *term, signed char c);
signed char aos_terminal_getc(struct aos_terminal *term, bool block);

struct aos_terminal *get_default_terminal(void);
void aos_terminal_debug(struct aos_terminal *term);
#endif  // TERMINAL_H
