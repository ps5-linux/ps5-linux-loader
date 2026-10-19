ENTRY(shellcode)
SECTIONS
{
  . = 0;
  .text : {
    entry.o(.text .text.*)     /* entry MUST be first: it owns the +0xF00 param offset */
    *(.text .text.*)
  }
  .rodata : { *(.rodata .rodata.*) }
  .data   : { *(.data .data.*)   }
  /DISCARD/ : {
    *(.eh_frame .eh_frame_hdr)
    *(.note .note.*)
    *(.comment)
    *(.bss .bss.*)
  }
}
