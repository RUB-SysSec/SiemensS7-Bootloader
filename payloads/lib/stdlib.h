#ifndef STDLIB_H
#define STDLIB_H

#include <stddef.h>

void* memcpy(void *restrict dst, const void *restrict src, size_t n);
void* memset(void *b, int c, size_t len);

#endif
