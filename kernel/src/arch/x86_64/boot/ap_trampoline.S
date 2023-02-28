; Before Application Processors are correctly initialized, they are woken up in *real* mode.
; So we must have this assembly code as a workaround to allow APs to have themselves set up (gdt, page tables, 
; etc.) so that they can jump to the kernel.
;
; So, this code snippet comes to aid. As you see, this is called `trampoline`, which means the AP can `jump` to
; protected mode (32bit) and finally come to the kernel space.
;
; This file is assembled by `nasm`. Make sure you have it installed.

org 0x8000
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
    mov eax, 0xc0000080
    rdmsr
    or eax, 1 << 11 | 1 << 8
    wrmsr

    mov eax, cr0
    or eax, 1 << 31 | 1 << 16 | 1 << 0
    mov cr0, eax

    jmp gdt.kernel_code:__ap_startup_long

use64
__ap_startup_long:
    mov rax, gdt.kernel_data
    mov ds, rax
    mov es, rax
    mov fs, rax
    mov gs, rax
    mov ss, rax

    mov rcx, [__ap_trampoline.stack_bottom]
    lea rsp, [rcx - 256]

    mov rdi, __ap_trampoline.cpu_id

    mov rax, [__ap_trampoline.trampoline_code]
    mov qword [__ap_trampoline.ready], 1
    jmp rax


struc GDTEntry
    .limitl resw 1
    .basel resw 1
    .basem resb 1
    .attribute resb 1
    .flags__limith resb 1
    .baseh resb 1
endstruc

attrib:
    .present              equ 1 << 7
    .ring1                equ 1 << 5
    .ring2                equ 1 << 6
    .ring3                equ 1 << 5 | 1 << 6
    .user                 equ 1 << 4
;user
    .code                 equ 1 << 3
;   code
    .conforming           equ 1 << 2
    .readable             equ 1 << 1
;   data
    .expand_down          equ 1 << 2
    .writable             equ 1 << 1
    .accessed             equ 1 << 0
;system
;   legacy
    .tssAvailabe16        equ 0x1
    .ldt                  equ 0x2
    .tssBusy16            equ 0x3
    .call16               equ 0x4
    .task                 equ 0x5
    .interrupt16          equ 0x6
    .trap16               equ 0x7
    .tssAvailabe32        equ 0x9
    .tssBusy32            equ 0xB
    .call32               equ 0xC
    .interrupt32          equ 0xE
    .trap32               equ 0xF
;   long mode
    .ldt32                equ 0x2
    .tssAvailabe64        equ 0x9
    .tssBusy64            equ 0xB
    .call64               equ 0xC
    .interrupt64          equ 0xE
    .trap64               equ 0xF

flags:
    .granularity equ 1 << 7
    .available equ 1 << 4
;user
    .default_operand_size equ 1 << 6
;   code
    .long_mode equ 1 << 5
;   data
    .reserved equ 1 << 5

gdtr:
    dw gdt.end + 1  ; size
    dq gdt          ; offset

gdt:
.null equ $ - gdt
    dq 0

.kernel_code equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.code
    at GDTEntry.flags__limith, db flags.long_mode
    at GDTEntry.baseh, db 0
iend

.kernel_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
; AMD System Programming Manual states that the writeable bit is ignored in long mode, but ss can not be set to this descriptor without it
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.writable
    at GDTEntry.flags__limith, db 0
    at GDTEntry.baseh, db 0
iend

.end equ $ - gdt
