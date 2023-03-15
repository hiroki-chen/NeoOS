.intel_syntax noprefix
.text
.global _start

_start:
    // Test if stack pointer is ok.
    push 0
    pop rax

    xor rax, rax
    mov rcx, 100

// Calculate sum(1..100).
__calc:
    add rax, rcx
    sub rcx, rcx
    cmp rcx, 0
    jge __calc

__loop:
    // Simply does nothing. A dead loop.
    jmp __loop
