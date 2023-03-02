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
    .page_table: dq 0
    .cpu_id: dq 0
    .ready: dq 0
    .stack_top: dq 0
    .stack_bottom: dq 0
    .trampoline_code: dq 0
    times 56 - ($ - __ap_trampoline) nop

__gdt:
    dq 0x0000000000000000

    dw 0xFFFF
    dw 0
    db 0
    db 10011010b
    db 11001111b
    db 0

    dw 0xFFFF
    dw 0
    db 0
    db 10010010b
    db 11001111b
    db 0

__gdtr:
    dw __gdtr - __gdt - 1
    dd __gdt

__ap_startup:
    cli
    cld

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    lgdt [__gdtr]

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp 0x8:__ap_start_32

bits 32
__ap_start_32:
    mov ax, 0x8
    mov ds, ax
    mov es, ax
    mov ax, 0x0
    mov fs, ax
    mov gs, ax

    ; Set up initial page table.
    ; We cannot use kernel's page table because we are still in low-bit mode.
    hlt