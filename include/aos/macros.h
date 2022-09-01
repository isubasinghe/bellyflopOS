#ifndef BARRELFISH_MACROS_H
#define BARRELFISH_MACROS_H

#include <aos/debug.h>


#define DEBUG_IF_ERR(err, str)                                                           \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            DEBUG_ERR(tmp_err, (str));                                                   \
        }                                                                                \
    } while (0)

#define DEBUG_IF_ERR2(err, err2, str)                                                    \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            DEBUG_ERR(err_push(tmp_err, (err2)), (str));                                 \
        }                                                                                \
    } while (0)

#define ASSERT_ERR_OK(err)                                                               \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            DEBUG_ERR(tmp_err, "Err\n");                                                 \
            assert(0);                                                                   \
        }                                                                                \
    } while (0)

#define RETURN_ERR_IF_NULL(val, err)                                                     \
    do {                                                                                 \
        if (val == NULL) {                                                               \
            return err;                                                                  \
        }                                                                                \
    } while (0)

#define PUSH_RETURN_IF_ERR(err, err1)                                                    \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            return err_push(tmp_err, err1);                                              \
        }                                                                                \
    } while (0)

#define GOTO_IF_ERR(err, label)                                                          \
    do {                                                                                 \
        if (err_is_fail(err)) {                                                          \
            goto label;                                                                  \
        }                                                                                \
    } while (0)

#define PUSH_GOTO_IF_ERR(err, err1, label)                                               \
    do {                                                                                 \
        if (err_is_fail(err)) {                                                          \
            err = err_push(err, err1);                                                   \
            goto label;                                                                  \
        }                                                                                \
    } while (0)

#define RETURN_IF_ERR(err)                                                               \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            return tmp_err;                                                              \
        }                                                                                \
    } while (0)

#define RETURN_AND_DEBUG_IF_ERR(err, str)                                                \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            DEBUG_ERR(tmp_err, str);                                                     \
            return tmp_err;                                                              \
        }                                                                                \
    } while (0)

#define RETURN_AND_DEBUG_IF_ERR(err, str)                                                \
    do {                                                                                 \
        errval_t tmp_err = err;                                                          \
        if (err_is_fail(tmp_err)) {                                                      \
            DEBUG_ERR(tmp_err, str);                                                     \
            return tmp_err;                                                              \
        }                                                                                \
    } while (0)

#endif  // BARRELFISH_MACROS_H
