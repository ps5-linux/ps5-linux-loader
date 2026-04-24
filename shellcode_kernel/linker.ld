/* linker.ld */
ENTRY(main)

SECTIONS
{
    . = 0x1000; /* 0x1000 to avoid warnings from linker */
    .text :
    {
        *(.entry_point)
        *(.text)
        *(.text.*)
        *(.data)
        *(.data.*)
        *(.rodata*)
        *(.bss)
        *(.bss.*)
    }
}