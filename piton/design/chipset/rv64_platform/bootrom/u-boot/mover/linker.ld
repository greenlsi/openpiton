SECTIONS
{
    ROM_BASE = 0x10000; /* ... but actually position independent */
/*ROM_BASE = 0x80000000;*/
    . = ROM_BASE;
    .text : ALIGN(4) { *(.text*) }
    . = ROM_BASE + 0x80;
    .rodata.spl : { *(.rodata.spl) }
}