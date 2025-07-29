#ifndef _HWSHA3_DEV_H
#define _HWSHA3_DEV_H

#include <stdint.h>
#include <stddef.h>
#include <encoding.h>
#include "uart.h"

#define SHA3_BASE_ADDRESS 0xfff0e00000
#define SHA3_SIZE 0x1000

/* Register offsets */
#define SHA3_REG_DATA_0        0x00
#define SHA3_REG_DATA_1        0x04
#define SHA3_REG_STATUS        0x08
#define SHA3_REG_HASH_0        0x40

#define SHA3_REG(offset) _REG32(SHA3_BASE_ADDRESS, offset)
#define SHA3_REG64(offset) _REG64(SHA3_BASE_ADDRESS, offset)

typedef unsigned char byte;

void hwsha3_init();
void hwsha3_update(void* data, size_t size);
void hwsha3_final(byte* hash, void* data, size_t size);

#endif /* _HWSHA3_DEV_H */
