#ifndef INIT_SETUP_H
#define INIT_SETUP_H

#include <aos/aos.h>

errval_t setup_network_driver(void);
errval_t setup_filesystem(void);
errval_t setup_nameserver_bsp(void);
errval_t setup_nameserver_app(void);
errval_t setup_terminal_driver(void);
#endif  // INIT_SETUP_H
