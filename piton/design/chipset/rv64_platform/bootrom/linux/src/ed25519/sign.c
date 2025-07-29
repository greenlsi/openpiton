#include "ed25519.h"

void hw_ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key, char red) {
    unsigned char hram[64];
    unsigned char r[64];
    unsigned char rred[64];
    uint64_t *sig = (uint64_t*)signature;
    
    // Remember that private_key is already hashed (hashkey)

    // Hash S and M (hashsm)
    hwsha3_init();
    hwsha3_update(private_key + 32, 32);
    hwsha3_final(r, message, message_len);
    for(int i = 0; i < 8; i++) {
        *(((uint64_t*)(rred)) + i) = *(((uint64_t*)(r)) + i);
    }
    if(red) sc_reduce(rred);

    for(int i = 0; i < 4; i++) {
        ED25519_REG64(ED25519_REG_DATA_K + i*8) = *(((uint64_t*)(r)) + i);
    }
    ED25519_REG(ED25519_REG_STATUS) = 1; // Use the K memory
    while(!(ED25519_REG(ED25519_REG_STATUS) & 0x4)); // Wait
    for(int i = 0; i < 4; i++) {
        sig[i] = ED25519_REG64(ED25519_REG_DATA_QY + i*8);
    }

    // Calculate the H(R, A, M)
    hwsha3_init();
    hwsha3_update(signature, 32);
    hwsha3_update(public_key, 32);
    hwsha3_final(hram, message, message_len);
    
    // Calculate the S part with the addmult in hw
    for(int i = 0; i < 8; i++) {
        ED25519_REG64(ED25519_REG_DATA_HKEY + i*8) = *(((uint64_t*)(private_key)) + i);
    }
    for(int i = 0; i < 8; i++) {
        ED25519_REG64(ED25519_REG_DATA_HRAM + i*8) = *(((uint64_t*)(hram)) + i);
    }
    for(int i = 0; i < 8; i++) {
        ED25519_REG64(ED25519_REG_DATA_HSM + i*8) = *(((uint64_t*)(r)) + i);
    }
    ED25519_REG(ED25519_REG_STATUS_3) = 1;
    while(!(ED25519_REG(ED25519_REG_STATUS_3) & 0x4)); // Wait
    for(int i = 0; i < 4; i++) {
        sig[i+4] = ED25519_REG64(ED25519_REG_DATA_SIGN + i*8);
    }
}

