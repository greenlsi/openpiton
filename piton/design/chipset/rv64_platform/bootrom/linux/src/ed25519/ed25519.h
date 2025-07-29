#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <stdint.h>
#include "sc.h"
#include "hwsha3.h"
#include "platform.h"
#include "ge.h"
#include "uart.h"
#include "memutils.h"

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif

#define ED25519_BASE_ADDRESS 0xfff0f00000
#define ED25519_SIZE 0x1000

#define ED25519_REG_DATA_K        0x00
//#define ED25519_REG_DATA_K2       0x20
#define ED25519_REG_DATA_HKEY     0x20
#define ED25519_REG_DATA_HRAM     0x60
#define ED25519_REG_DATA_HSM      0xA0
#define ED25519_REG_DATA_QY       0xE0
//#define ED25519_REG_DATA_A        0x60
//#define ED25519_REG_DATA_B        0x80
//#define ED25519_REG_DATA_C        0xC0
#define ED25519_REG_DATA_SIGN     0x100
#define ED25519_REG_STATUS_3      0x120
//#define ED25519_REG_STATUS_2      0xFF8
#define ED25519_REG_STATUS        0x128

#define ED25519_REG(offset) _REG32(ED25519_BASE_ADDRESS, offset)
#define ED25519_REG64(offset) _REG64(ED25519_BASE_ADDRESS, offset)

// #ifndef ED25519_DIR
//     #define ED25519_REG_ADDR_K        0x04
//     #define ED25519_REG_ADDR_K2       0x24
//     #define ED25519_REG_ADDR_QY       0x44
// #endif

#ifndef ED25519_NO_SEED
    int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
#endif

void ED25519_DECLSPEC hw_ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ED25519_DECLSPEC hw_ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key, char red);
void ED25519_DECLSPEC ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ED25519_DECLSPEC ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);


#endif
