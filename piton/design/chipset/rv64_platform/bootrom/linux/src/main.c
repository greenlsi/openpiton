#include "uart.h"
#include "spi.h"
#include "sd.h"
#include "gpt.h"
#include "info.h"
#include <stdint.h>
#include "sha3/hwsha3.h"
#include "ed25519/ed25519.h"
#include "memutils.h"

//SM parameters
typedef unsigned char byte;
byte* sanctum_m_public_key = (byte*)0x801ff000; //32B
byte* sanctum_dev_public_key = (byte*)0x801ff020; //32B
byte* sanctum_dev_secret_key = (byte*)0x801ff040; //64B 
unsigned int sanctum_sm_size = 0x1ff000; 
byte* sanctum_sm_hash = (byte*)0x801ff080; //64B         
byte* sanctum_sm_public_key = (byte*)0x801ff0C0; //32B  
byte* sanctum_sm_secret_key = (byte*)0x801ff0E0; //64B
byte* sanctum_sm_signature = (byte*)0x801ff120; //64B
#define DRAM_BASE 0x80000000

// /* Update this to generate valid entropy for target platform*/
inline byte random_byte(unsigned int i) {
//#warning Bootloader does not have entropy source, keys are for TESTING ONLY
  return 0xac + (0xdd ^ i);
}

void generate_SM_keys()
{
    //*sanctum_sm_size = 0x200;
    // Reserve stack space for secrets
    byte scratchpad[128];

    /* Gathering high quality entropy during boot on embedded devices is
    * a hard problem. Platforms taking security seriously must provide
    * a high quality entropy source available in hardware. Platforms
    * that do not provide such a source must gather their own
    * entropy. See the Keystone documentation for further
    * discussion. For testing purposes, we have no entropy generation.
    */

    // Create a random seed for keys and nonces from TRNG
    for (unsigned int i=0; i<32; i++) {
    scratchpad[i] = random_byte(i);
    }

    /* On a real device, the platform must provide a secure root device
    keystore. For testing purposes we hardcode a known private/public
    keypair */
    // TEST Device key
    /* These are known device TESTING keys, use them for testing on platforms/qemu */

    //#warning Using TEST device root key. No integrity guarantee.
    static const unsigned char _sanctum_dev_secret_key[] = {
    0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
    0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
    0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57, 0x6a, 0x9a, 0xb6,
    0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29, 0x85, 0x2f, 0xb9, 0x60,
    0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89, 0xec, 0x06, 0xa8, 0x72, 0x34,
    0x51, 0xaa, 0x0e, 0x4a
    };
    static const size_t _sanctum_dev_secret_key_len = 64;

    static const unsigned char _sanctum_dev_public_key[] = {
    0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96,
    0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46,
    0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
    };
    static const size_t _sanctum_dev_public_key_len = 32;

    memcpy(sanctum_dev_secret_key, _sanctum_dev_secret_key, _sanctum_dev_secret_key_len);
    __asm__ volatile ("fence" ::: "memory");

    memcpy(sanctum_dev_public_key, _sanctum_dev_public_key, _sanctum_dev_public_key_len);
    __asm__ volatile ("fence" ::: "memory");


    // Measure SM
    print_uart("Measuring SM...\r\n");
    hwsha3_init();
    hwsha3_update((void*)DRAM_BASE, sanctum_sm_size);
    hwsha3_final(sanctum_sm_hash, NULL, 0);

    // Combine SK_D and H_SM via a hash
    // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
    print_uart("Combining SK_D and H_SM...\r\n");
    hwsha3_init();
    hwsha3_update(sanctum_dev_secret_key, sizeof(*sanctum_dev_secret_key));
    hwsha3_update(sanctum_sm_hash, sizeof(*sanctum_sm_hash));
    hwsha3_final(scratchpad, NULL, 0);

    // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
    hw_ed25519_create_keypair(sanctum_sm_public_key, sanctum_sm_secret_key, scratchpad);

    // Endorse the SM
    print_uart("Endorsing SM...\r\n");
    memcpy(scratchpad, sanctum_sm_hash, 64);
    memcpy(scratchpad + 64, sanctum_sm_public_key, 32);
    // Sign (H_SM, PK_SM) with SK_D
    print_uart("Signing SM...\r\n");
    hw_ed25519_sign(sanctum_sm_signature, scratchpad, 64 + 32, sanctum_dev_public_key, sanctum_dev_secret_key, 0);

    print_uart("============ SM HASH =============\r\n");
    for (int i=0; i<64; i++)
    {
        print_uart_byte(sanctum_sm_hash[i]);
    }
    print_uart("\r\n");

    print_uart("============ PUBKEY =============\r\n");
	for(int i=0; i<32; i+=1)
	{
        print_uart_byte(sanctum_dev_public_key[i]);
		if(i%16==15) print_uart("\r\n");
	}
	print_uart("=================================\r\n");

	print_uart("=========== SIGNATURE ===========\r\n");
	for(int i=0; i<64; i+=1)
	{
        print_uart_byte(sanctum_sm_signature[i]);
		if(i%16==15) print_uart("\r\n");
	}
	print_uart("=================================\r\n");

    // Clean up
    // Erase SK_D
    memset((void*)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));

    // caller will clean core state and memory (including the stack), and boot.
    return;
}

int main()
{
    init_uart(UART_FREQ, 115200);
    print_uart(info);

    print_uart("sd initialized!\r\n");

    int res = gpt_find_boot_partition((uint8_t *)0x80000000UL, 2 * 32768);

    if (res == 0)
    {
       print_uart(" generating SM keys!\r\n");

       generate_SM_keys();
    } else {
        print_uart("failed to find boot partition!\r\n");
    }

    return 0;
}

void handle_trap(void)
{
    print_uart("trap\r\n");
}
