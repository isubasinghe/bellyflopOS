//
// Created by fooris on 18.05.22.
//

#ifndef BF_AOS_UTIL_H
#define BF_AOS_UTIL_H


__attribute__((unused)) static char char_to_upper(char c) {
    if ('a' <= c && c <= 'z') {
        c = c - 'a' + 'A';
    }
    return c;
}

#define MIN(a,b) (((a)<(b))?(a):(b))

#define DATA_BARRIER __asm volatile("dmb sy\n")
#define INSTR_BARRIER __asm volatile("isb sy\n")

#endif  // BF_AOS_UTIL_H
