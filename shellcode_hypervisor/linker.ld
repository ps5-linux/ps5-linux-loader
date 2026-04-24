/* linker.ld */
ENTRY(main)

SECTIONS
{
    . = 0x1000; /* 0x1000 to avoid warnings from linker */
    /* Place our custom header first */
    .shell_code :
    {
        *(.entry_point)
        *(.text)
        *(.text.*)
        *(.data*)
        *(.rodata*)
        *(.bss)
        *(.bss.*)
    }
}