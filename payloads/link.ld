OUTPUT_ARCH(arm)
ENTRY(_start)

SECTIONS {
    .text :
    {
        
        *(.text.entry)
        . = ALIGN(4);
        _stext = .;
        *(.text*)
        *(.rodata*)

        KEEP(*(.init))
        KEEP(*(.fini))

        . = ALIGN(4);
        _etext = .;
        *(.got)
    }

    _sidata = .;
    .data : AT(_sidata)
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        CONSTRUCTORS
        . = ALIGN(4);
        _edata = .;
    }

    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    }

    /DISCARD/ :
    {
        *(.gnu.linkonce.armexidx.*)
        *(.ARM.*)
        *(.comment)
    }
}
