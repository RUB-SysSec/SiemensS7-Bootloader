#include <stdint.h>

#include "stdlib.h"

void* memcpy(void *restrict dst, const void *restrict src, size_t n) {
    for (; n > 0; n--)
        *(uint8_t*)dst++ = *(uint8_t*)src++;
    return dst;
}

void* memset(void *b, int c, size_t len) {
    for (size_t i = 0; i < len; i++)
        ((uint8_t*)b)[i] = c;
    return b;
}