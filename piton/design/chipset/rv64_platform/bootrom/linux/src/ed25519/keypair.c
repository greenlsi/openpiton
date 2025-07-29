#include "ed25519.h"

void hw_ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    uint64_t k[4]; // Ahora sin const, ya que vamos a escribir en él.
    uint64_t *pub = (uint64_t*)public_key;
    uint64_t *priv = (uint64_t*)private_key;

    memcpy(k, seed, 32); // Copiamos los 32 bytes del seed a k.

    const uint64_t *ptr = k; // Usamos un puntero para recorrer k

    SHA3_REG(SHA3_REG_STATUS) = 1 << 24; // Reset, y poner tamaño en 0
    SHA3_REG64(SHA3_REG_DATA_0) = *ptr++; // 8 bytes
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    SHA3_REG64(SHA3_REG_DATA_0) = *ptr++; // 16 bytes
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    SHA3_REG64(SHA3_REG_DATA_0) = *ptr++; // 24 bytes
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    SHA3_REG64(SHA3_REG_DATA_0) = *ptr++; // 32 bytes
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    SHA3_REG(SHA3_REG_STATUS) = 3 << 16;

    while(SHA3_REG(SHA3_REG_STATUS) & (1 << 10)); // Esperar SHA3

    for(int i = 0; i < 4; i++) {
        if(i == 0)
            ED25519_REG64(ED25519_REG_DATA_K + i * 8) = *(priv + i) = *(((uint64_t*)(SHA3_BASE_ADDRESS + SHA3_REG_HASH_0)) + i) & 0xFFFFFFFFFFFFFFF8;
        else if(i == 3)
            ED25519_REG64(ED25519_REG_DATA_K + i * 8) = *(priv + i) = (*(((uint64_t*)(SHA3_BASE_ADDRESS + SHA3_REG_HASH_0)) + i) & 0x3FFFFFFFFFFFFFFF) | 0x4000000000000000;
        else
            ED25519_REG64(ED25519_REG_DATA_K + i * 8) = *(priv + i) = *(((uint64_t*)(SHA3_BASE_ADDRESS + SHA3_REG_HASH_0)) + i);
    }

    for(int i = 4; i < 8; i++) {
        *(priv + i) = *(((uint64_t*)(SHA3_BASE_ADDRESS + SHA3_REG_HASH_0)) + i);
    }

    ED25519_REG(ED25519_REG_STATUS) = 1; // Usar la memoria K
    while(!(ED25519_REG(ED25519_REG_STATUS) & 0x4)); // Esperar

    for(int i = 0; i < 4; i++) {
        pub[i] = ED25519_REG64(ED25519_REG_DATA_QY + i * 8);
    }
}