; x86_64 entry for Application Processors
;
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

bits 16
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

    ; Load the address of the page table in advance.
    mov edi, [__ap_trampoline.page_table]
    mov cr3, edi

    lgdt [__gdtr]

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; To load correct value of cs we must perform a long jump.
    jmp 0x8:__ap_start_32

bits 32
__ap_start_32:
    mov ax, 0x8
    mov ds, ax
    mov es, ax
    
    ; Flush fs and gs.
    xor ax, ax
    mov fs, ax
    mov gs, ax

    ; 9: FXSAVE/FXRSTOR
    ; 7: Page Global
    ; 5: Page Address Extension
    ; 4: Page Size Extension
    mov eax, cr4
    or eax, 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4
    mov cr4, eax

    ; Enable long mode.
    mov ecx, 0xc0000080
    rdmsr
    or eax, 1 << 11 | 1 << 8
    wrmsr

    ; Set up paging.
    mov eax, cr0
    or eax, 1 << 31 | 1 << 16 | 1
    mov cr0, eax

    ; Now that we're in long mode, there's one issue left: we are in the 32-bit compatibility submode and we actually
    ; wanted to enter 64-bit long mode. This isn't a hard thing to do. We should load just load a GDT with the 64-bit
    ; flags set in the code and data selectors.
    lgdt [__gdt64.pointer]

    ; Perform another long jump
    jmp __gdt64.code:__ap_start_prot_mode

bits 64
__ap_start_prot_mode:
    ; Set up the stack frames allocated by the BSP.
    mov rbx, [__ap_trampoline.stack_top]
    xor rbp, rbp
    lea rsp, [rbx - 256]

    ; Indicate the BSP that this AP is ready.
    mov qword [__ap_trampoline.ready], 1

    ; Enter the kernel.
    mov rax, [__ap_trampoline.trampoline_code]
    mov rdi, __ap_trampoline.page_table
    call rax

; Should never enter `__loop`.
__loop:
    jmp __loop

; Access bits
PRESENT        equ 1 << 7
NOT_SYS        equ 1 << 4
EXEC           equ 1 << 3
DC             equ 1 << 2
RW             equ 1 << 1
ACCESSED       equ 1 << 0
 
; Flags bits
GRAN_4K       equ 1 << 7
SZ_32         equ 1 << 6
LONG_MODE     equ 1 << 5

align 8 ; Prevent `init_gdt` from reading unaligned memories => panic!
__gdt64:
    .null: equ $ - __gdt64
        dq 0
    .code: equ $ - __gdt64
        dd 0xFFFF                                   ; Limit & Base (low, bits 0-15)
        db 0                                        ; Base (mid, bits 16-23)
        db PRESENT | NOT_SYS | EXEC | RW            ; Access
        db GRAN_4K | LONG_MODE | 0xF                ; Flags & Limit (high, bits 16-19)
        db 0                                        ; Base (high, bits 24-31)
    .data: equ $ - __gdt64
        dd 0xFFFF                                   ; Limit & Base (low, bits 0-15)
        db 0                                        ; Base (mid, bits 16-23)
        db PRESENT | NOT_SYS | RW                   ; Access
        db GRAN_4K | SZ_32 | 0xF                    ; Flags & Limit (high, bits 16-19)
        db 0                                        ; Base (high, bits 24-31)
    .pointer:
        dw $ - __gdt64 - 1
        dq __gdt64
