.text

.global __syscall
.global __sysreturn
.global __syscall_trap

// Registers on __syscall:
//  * rax  system call number
//  * rcx  return address
//  * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
//  * rdi  arg0
//  * rsi  arg1
//  * rdx  arg2
//  * r10  arg3 (needs to be moved to rcx to conform to C ABI)
//  * r8   arg4
//  * r9   arg5
__syscall:
  // We first check if the syscall is valid.
  cmp rax, 0x150
  jge syscall_end

syscall_normal:
  // Swap in kernel gs.
  // SWAPGS exchanges the current GS base register value with the value contained in MSR
  // address C0000102H (IA32_KERNEL_GS_BASE). The SWAPGS instruction is a privileged
  // instruction intended for use by system software.
  //
  // When using SYSCALL to implement system calls, there is no kernel stack at the OS entry
  // point. Neither is there a straightforward method to obtain a pointer to kernel structures
  // from which the kernel stack pointer could be read. Thus, the kernel cannot save general
  // purpose registers or reference memory.
  //
  // SWAPGS exchanges the CPL 0 data pointer from the IA32_KERNEL_GS_BASE MSR with the GS base
  // register. The kernel can then use the GS prefix on normal memory references to access
  // kernel data structures.
  swapgs

  // Equivalent to 
  // movq	%rsp, PER_CPU_VAR(rsp_scratch) -> TSS.rsp1
	// movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp <- TSS.rsp0
  // Previous rsp is no longer valid because we need to switch into kernel stack.
  mov gs:12, rsp
  mov rsp, gs:4

  pop rsp
  add rsp, 22 * 8

  // Errno and trap_num.
  push 0
  push 0x100
  // Skip fs and gs.
  sub rsp, 0x10
  // push general registers
  push r11                // rflags
  push rcx                // rip

__syscall_trap:
  // Construct struct `pt_regs` (GPRs) on the stack.
  push r15
  push r14
  push r13
  push r12
  push r11
  push r10
  push r9
  push r8
  push gs:12              // push rsp
  push rbp
  push rdi
  push rsi
  push rdx
  push rcx
  push rbx
  push rax

  // FSBase is MSR 0xC0000100, GSBase is 0xC0000101
  // push fsbase gsbase
  mov ecx, 0xC0000100
  rdmsr
  mov [rsp+18*8+4], edx
  mov [rsp+18*8], eax
  mov ecx, 0xC0000102
  rdmsr
  mov [rsp+19*8+4], edx
  mov [rsp+19*8], eax

  mov rsp, gs:4           // load kernel rsp <- TSS.sp0

  pop rbx
  pop rbx
  // pop rbx -> alignment?
  pop rbp
  pop r12
  pop r13
  pop r14
  pop r15

  pop rax
  mov ecx, 0xC0000100
  mov rdx, rax
  shr rdx, 0x20
  wrmsr

// Do something in the kernel.
syscall_end:
  ret

__sysreturn:
  // Resume the context.
  cli
  mov ecx, 0xC0000100
  rdmsr

  shl rdx, 0x20
  or rax, rdx

  push rax                // push fsbase
  push r15
  push r14
  push r13
  push r12
  push rbp
  push rbx
  push rdi

  mov rcx, rsp
  and rcx, 0xf
  jz __no_pad

__pad:
  push rdi                // keep rsp 16 bytes align

__no_pad:
  mov gs:4, rsp           // store kernel rsp -> TSS.sp0
  mov rsp, rdi            // set rsp = bottom of trap frame
  // Now rsp becomes the address of &mut Box<context>.

  swapgs                  // store kernel gsbase
  mov ecx, 0xC0000100
  mov edx, [rsp + 18*8+4]
  mov eax, [rsp + 18*8]
  wrmsr                   // pop fsbase
  mov ecx, 0xC0000101
  mov edx, [rsp + 19*8+4]
  mov eax, [rsp + 19*8]
  wrmsr                   // pop gsbase

  // Restore the &mut Box<Context>::GeneralRegisters
  pop rax
  pop rbx
  pop rcx
  pop rdx
  pop rsi
  pop rdi
  pop rbp
  pop r8                  // skip rsp
  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15
  // 16 * 8 bytes
  // rip & rflags.

  cmp dword ptr [rsp + 4*8], 0x100
  je __sysret

__iret:
  mov ecx, 0xC0000081
  rdmsr
  shr edx, 0x10             // dx = user_cs32
  lea ax, [edx + 8]         // ax = user_ss
  add dx, 0x10

  push rax                // push ss
  push [rsp - 8*8]        // push rsp
  push [rsp + 3*8]        // push rflags
  push rdx                // push cs
  push [rsp + 4*8]        // push rip

  mov rax, [rsp - 11*8]
  mov rcx, [rsp - 9*8]
  mov rdx, [rsp - 8*8]

  iretq

// Handles syscall return.
__sysret:
  pop rcx                 // rcx = rip
  pop r11                 // r11 = rflags
  mov rsp, [rsp - 11*8]   // load rsp

  sysretq
