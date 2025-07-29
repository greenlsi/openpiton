# start sequence of the bootloader
# 
# 
#include <smp.h>
#define DRAM_BASE 0x80000000
#define STACK_TOP     0x84000000
#define STACK_BOTTOM  0x83c00000

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  smp_pause(s1, s2)
  li sp, STACK_TOP
  call main
  /* clear_stack_from_bottom */
  li t1, STACK_BOTTOM

clean_loop:
  beq t1, sp, clean_done
  sd x0, (t1)
  addi t1, t1, 8
  j clean_loop

clean_done:
  li t0, 1
  sd t0, 8(sp)
  fence
  
  // mv ra, x0 // also do not clear ra; we should return //do not clear s1, s2. Used in smp_resume
  mv gp, x0
  mv tp, x0
  mv t0, x0
  mv t1, x0
  mv t2, x0
  mv s0, x0
  mv a0, x0
  mv a1, x0
  mv a2, x0
  mv a3, x0
  mv a4, x0
  mv a5, x0
  mv a6, x0
  mv a7, x0
  mv s3, x0
  mv s4, x0
  mv s5, x0
  mv s6, x0
  mv s7, x0
  mv s8, x0
  mv s9, x0
  mv s10, x0
  mv s11, x0
  mv t3, x0
  mv t4, x0
  mv t5, x0
  mv t6, x0

  smp_resume(s1, s2)
  csrr a0, mhartid
  la a1, _dtb
  li s1, DRAM_BASE
  jr s1

  .section .dtb
  .globl _dtb
  .align 4, 0
_dtb:
  .incbin "rv64_platform.dtb"
