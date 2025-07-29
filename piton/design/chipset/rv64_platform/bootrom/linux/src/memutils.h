#ifndef MEMUTILS_H
#define MEMUTILS_H

#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t len);
void *memset(void *b, int c, int len);

#endif // MEMUTILS_H
