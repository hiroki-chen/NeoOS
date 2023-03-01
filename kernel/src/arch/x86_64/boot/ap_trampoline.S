; Before Application Processors are correctly initialized, they are woken up in *real* mode.
; So we must have this assembly code as a workaround to allow APs to have themselves set up (gdt, page tables, 
; etc.) so that they can jump to the kernel.
;
; So, this code snippet comes to aid. As you see, this is called `trampoline`, which means the AP can `jump` to
; protected mode (32bit) and finally come to the kernel space.
;
; This file is assembled by `nasm`. Make sure you have it installed.

org 0xf000
section .text
use16

__ap_trampoline:
    jmp short __ap_startup
    times 8 - ($ - __ap_trampoline) nop
    ; Metadata for the trampoline code.
    .page_table: dw 0
    .cpu_id: dw 0
    .ready: dw 0
    .stack_top: dw 0
    .stack_bottom: dw 0
    .trampoline_code: dw 0

__panic:
    mov ecx, 0
    wrmsr
    jmp __panic

__ap_startup:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0 ; clear stack pointer.
    mov edi, [__ap_trampoline.page_table]
    mov cr3, edi

    ; enable FP.
    mov eax, cr0
    and al, 11110011b
    or al, 00100010b
    mov cr0, eax

    mov eax, cr4
    or eax, 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4
    mov cr4, eax

    fninit

    lgdt [gdtr]

    ; Jump to long mode.
    ; Bit 0	System Call Extensions (SCE)
    ; Bits 1-7	Reserved
    ; Bit 8	Long Mode Enable (LME)
    ; Bit 9	Reserved
    ; Bit 10	Long Mode Active (LMA)
    ; Bit 11	No-Execute Enable (NXE)
    ; Bit 12	Secure Virtual Machine Enable (SVME)
    ; Bit 13	Long Mode Segment Limit Enable (LMSLE)
    ; Bit 14	fast FXSAVE/FXSTOR (FFXSR)
    ; Bit 15	Translation Cache Extension (TCE)
    mov ecx, 0xc0000080
    rdmsr
    or eax, 1 << 11 | 1 << 8
    wrmsr

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    hlt


gdt:
   dw 0x00000000
   dw 0x00000000

   ; Descriptor (0x9a, RW, Execute) (Code32)
   dw 0x0000ffff
   dw 0x00CF9A00

   ; Descriptor  (0x92, RW)  (Data32)
   dw 0x0000ffff
   dw 0x00cf9200

   ; Code16
   dw 0x0000ffff
   dw 0x000f9a00

   ; Data16
   dw 0x0000ffff
   dw 0x000f9200

gdt_end:

gdtr:
    dw gdt_end - gdt - 1
    dd gdt
