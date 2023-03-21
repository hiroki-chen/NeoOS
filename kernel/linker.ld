ENTRY(_start)

KERNEL_BEGIN = 0xffffffff80000000;

SECTIONS {

  . = KERNEL_BEGIN;

  .rodata ALIGN(4K):
  {
    *(.rodata .rodata.*)
  }

  . = ALIGN(8);
  PROVIDE(__eh_frame = .);
  /* before .eh_frame rule */
  .eh_frame : { KEEP (*(.eh_frame)) *(.eh_frame.*) }

  .text ALIGN(4K):
  {
    /* Prevent invalid addresses. */
    __guard_bottom = .;
    _copy_user_start = .;
    *(.text.copy_user)
    _copy_user_end = .;
    *(.text .text.*)
    /* Prevent invalid addresses. */
    __guard_top = .;
  }

  .data ALIGN(4K):
  {
    *(.data .data.*)
    *(.sdata .sdata.*)
  }

  .got ALIGN(4K):
  {
    *(.got .got.*)
  }

  .bss ALIGN(4K):
  {
    *(.bss .bss.*)
    *(.sbss .sbss.*)
  }
}
