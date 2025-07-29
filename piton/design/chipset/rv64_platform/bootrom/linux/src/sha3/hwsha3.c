#include "hwsha3.h"

void hwsha3_init() {
    SHA3_REG(SHA3_REG_STATUS) = 1 << 24; // Reset, and also put 0 in size
}
  
void hwsha3_update(void* data, size_t size) {
  uint64_t* d = (uint64_t*)data;
  SHA3_REG(SHA3_REG_STATUS) = 0;

  while(size >= 8) {
    SHA3_REG64(SHA3_REG_DATA_0) = *d;
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    size -= 8;
    d += 1;
  }
  if(size > 0) {
    SHA3_REG64(SHA3_REG_DATA_0) = *d;
    SHA3_REG(SHA3_REG_STATUS) = size & 0x7;
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
  }
}
  
void hwsha3_final(byte* hash, void* data, size_t size) {
  uint64_t* d = (uint64_t*)data;
  SHA3_REG(SHA3_REG_STATUS) = 0;
  while(size >= 8) {
    size -= 8;
    SHA3_REG64(SHA3_REG_DATA_0) = *d;
    SHA3_REG(SHA3_REG_STATUS) = 1 << 16;
    d += 1;
  }
  /*if(size > 0)*/ {
    if(size > 0) SHA3_REG64(SHA3_REG_DATA_0) = *d;
    SHA3_REG(SHA3_REG_STATUS) = size & 0x7;
    SHA3_REG(SHA3_REG_STATUS) = 3 << 16;

  }
  while(SHA3_REG(SHA3_REG_STATUS) & (1 << 10));
  for(int i = 0; i < 8; i++) {
    *(((uint64_t*)hash) + (7 - i)) = *(((uint64_t*)(SHA3_BASE_ADDRESS+SHA3_REG_HASH_0)) + i); //SHA3 output first byte in last reg
  }
}