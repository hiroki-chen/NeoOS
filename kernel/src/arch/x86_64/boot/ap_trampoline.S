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

; This field is filled by the BSP because it loads the code snippet at `0x10000`; so that
; the code here (in real mode) cannot access the GDT entries; as such, we need to 
gdt:
    dw 0
    dw 0 

    ; Descriptor (0x9a, RW, Execute) (Code32)
    dw 0
    dw 0

    ; Descriptor  (0x92, RW)  (Data32)
    dw 0
    dw 0

    ; Code16
    dw 0
    dw 0

    ; Data16
    dw 0
    dw 0
    ; Padding: do not elide zeros!
    times 40 - ($ - gdt) nop
gdtr:
    dw 0
    times 4 - ($ - gdtr) nop
    dd 0

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

    ; Now it works in long mode.
    ; Fresh CS by a long jump.

