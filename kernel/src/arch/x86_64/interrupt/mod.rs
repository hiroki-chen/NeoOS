//! This module implements the interrupt handling code on x86_64 platforms.
//!
//! # Interrupts
//! Interrupts are signals from a device, such as a keyboard or a hard drive, to the CPU,
//! telling it to immediately stop whatever it is currently doing and do something else.
//! For example, a keyboard controller can send an interrupt when a character key was pressed.
//! Then the OS can display the character on screen immediately, even if the CPU was doing
//! something completely unrelated before, and return to what it was doing afterwards.
//!
//! In x86 protected mode the table is called the Interrupt Descriptor Table (IDT) and can
//! have up to 256 entries
//!
//! # Traps
//! This module *also* implements the trap mechanism, technically, the software generated
//! interrupts. Trap is generated by the kernel when it encounters some exceptions. These
//! exceptions are handled by the so-called trap handlers.
//!
//! # Syscalls
//! In other words, a system call is a request made by a process to the operating system
//! to perform a specific service. A trap, on the other hand, is a type of interrupt that
//! is generated by the operating system in response to exceptional conditions.
//!
//! While system calls, traps, and interrupts both involve the operating system, they serve
//! different purposes and are not interchangeable.
//!
//! # How we deal with them
//! We handle interrupt by IDT vectors defined in `arch/x86_64/interrupt/idt_vectors.S`.
//! After CPU pushes `RFLAGS, CS, RIP`, each entry only does one thing:
//!   * Push errno = 0
//!   * Push trap_num = gate_num
//!   * Jump to __handle_trap.
//! E.g.:
//! ```asm
//! gate_233:
//!   push 0
//!   push 233
//!   jmp __handle_trap
//! ```
//!
//! Then, `__handle_trap` checks the privilege level when the interrupt occurs.
//!   * If interrupt occurs at kernel level (i.e., DPL = 0), we directly construct `TrapFrame`
//!     on the stack by pushing the remaining GPRs; finally, we move `RSP` into `RDI` as the
//!     function argument for `__trap_handler` (see the prototype below).
//!     ```asm
//!     check:
//!       push rax                      ; Backup.
//!       mov  ax, [rsp + 4 * 8]        ; load CS (current layout: 233, 0, rip, cs, rflags).
//!       and ax, 0x3                   ; Check DPL.
//!       jz __kernel
//!     __kernel:
//!       pop rax                       ; Restore  
//!       push 0                        ; Pad.
//!       push r15
//!       ...
//!       push rax
//!     
//!       mov rdi, rsp
//!       call __trap_handler ; Into Rust.
//!     ```
//!   * If interrupt occurs as user level (i.e., DPL = 3), we need to switch into kernel first.
//!     Because this it shares common behavior with syscall (user -> kernel), we first switch
//!     (by `swapgs`) the code, data base, and stack frame. Note we need to reset RSP to the
//!     kernel stack of that thread.
//!
//!     Then we handle it by `__syscall_trap` defined in `syscall.S` since syscalls are
//!     required to push registers.
//!
//! For syscalls, we need to first switch the code, data, and stack frame from Ring 3 to Ring
//! 0. This is also done by `swapgs`.
//! E.g.:
//! ```asm
//! __swtich:
//!   ; SWAPGS exchanges the CPL 0 data pointer from the `IA32_KERNEL_GS_BASE` MSR
//!   ; with the GS base register.
//!   swapgs
//!
//!   ; Save and get RSP.
//!   mov gs:12, rsp
//!   mov rsp, gs:4
//! ```

pub mod dispatcher;
pub mod idt;
pub mod syscall;

use core::arch::{asm, global_asm};

use log::info;
use x86::apic::{x2apic::X2APIC, ApicControl};

use crate::{
    arch::{
        gdt::init_gdt,
        interrupt::{idt::init_idt, syscall::init_syscall},
    },
    error::KResult,
};

// Defines a enumeration over CPU auto-generated interrupts.
pub const DIVIDE_BY_ZERO_INTERRUPT: usize = 0x00;
pub const DEBUG_INTERRUPT: usize = 0x01;
pub const NON_MASKABLE_INTERRUPT: usize = 0x02;
pub const BREAKPOINT_INTERRUPT: usize = 0x03;
pub const OVERFLOW_INTERRUPT: usize = 0x04;
pub const BOUND_RANGE_EXCEEDED_INTERRUPT: usize = 0x05;
pub const INVALID_OPCODE_INTERRUPT: usize = 0x06;
pub const DEVICE_NOT_AVAILABLE_INTERRUPT: usize = 0x07;
pub const DOUBLE_FAULT_INTERRUPT: usize = 0x08;
pub const PAGE_FAULT_INTERRUPT: usize = 0x0e;

pub const IRQ_MIN: usize = 0x20;
pub const IRQ_MAX: usize = 0x3f;
pub const SYSCALL: usize = 0x100;

pub const SYSCALL_REGS: usize = 0x6;

global_asm!(include_str!("trap.S"));
global_asm!(include_str!("idt_vectors.S"));

/// Trap frame of kernel interrupt
///
/// # Trap handler
///
/// You need to define a handler function like this:
///
/// ```
/// use arch::interrupt::TrapFrame;
///
/// #[no_mangle]
/// extern "C" fn __trap_dispatcher(tf: &mut TrapFrame) {
///     match tf.trap_num {
///         3 => {
///             println!("TRAP: BreakPoint");
///             tf.rip += 1;
///         }
///         _ => panic!("TRAP: {:#x?}", tf),
///     }
/// }
/// ```
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    // Pushed by 'trap.S'
    pub rax: usize,
    pub rbx: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rbp: usize,
    pub rsp: usize,
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    pub r11: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
    pub _pad: usize,

    // Pushed by 'idt_vectors.S'.
    // Also pushed by `syscall.S` when it is a syscall.
    // error_code = 0x100 => syscall; others => interrupt.
    pub trap_num: usize,
    pub error_code: usize,

    // Pushed by CPU
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

/// A struct that wrapps all the general registers for context switch.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct GeneralRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub gs: u64,
    pub fs: u64,
}

/// The context for the *user* processes. It is then stored into TSS.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Context {
    pub regs: GeneralRegisters,
    pub trapno: u64,
    pub errno: u64,
}

impl Context {
    /// Returns the type of the system call. This value is stored in RAX.
    pub fn get_syscall_number(&self) -> u64 {
        self.regs.rax
    }

    /// Returns the syscall registers.
    pub fn get_syscall_params(&self) -> [u64; SYSCALL_REGS] {
        [
            self.regs.rdi,
            self.regs.rsi,
            self.regs.rdx,
            self.regs.r10,
            self.regs.r8,
            self.regs.r9,
        ]
    }

    /// Gets the stack pointer.
    pub fn get_rsp(&self) -> u64 {
        self.regs.rsp
    }

    /// Gets the instruction pointer.
    pub fn get_rip(&self) -> u64 {
        self.regs.rip
    }

    /// Sets the next instruction upon saving.
    pub fn set_rip(&mut self, rip: u64) {
        self.regs.rip = rip;
    }

    /// Sets the stack pointer upon saving.
    pub fn set_rsp(&mut self, rsp: u64) {
        self.regs.rsp = rsp;
    }

    /// For sync: each thread has its own areas known as the thread local storage.
    /// This structure is stored in `FSBASE`.
    pub fn tls(&self) -> u64 {
        self.regs.fs
    }
}

/// Initialize the trap handler and the interrupt descriptor table.
pub unsafe fn init_interrupt_all() -> KResult<()> {
    // Step 1: This operation should be atomic, so no other interrupts could happten.
    disable();
    info!("init_interrupt_all(): disabled interrupts.");
    // Step 2: Set up the global descriptor table.
    init_gdt()?;
    info!("init_interrupt_all(): initialized gdt.");
    // Step 3: Set up the interrupt descriptor table.
    init_idt()?;
    info!("init_interrupt_all(): initialized idt.");
    info!("init_interrupt_all(): try `int 0x3`. You will see the trap frame.");
    asm!("int 0x3");
    // Step 4: Set up the syscall handlers.
    init_syscall()?;
    info!("init_interrupt_all(): initialized syscall handlers.");

    Ok(())
}

/// All FLAGS registers contain the condition codes, flag bits that let the results of one machine-language
/// instruction affect another instruction. Since we need to disable the interrupt, the FLAGS registers should
/// be stored onto the stack.
#[inline(always)]
pub unsafe fn disable_and_store() -> usize {
    let mut flags: usize;
    asm!("pushf; pop {flags}; cli", flags = out(reg) flags);
    flags
}

/// Restores the previously disabled interrupt.
#[inline(always)]
pub unsafe fn restore(flags: usize) {
    asm!("push {flags}; popf", flags = in(reg) flags)
}

/// Disables interrupts without getting the RFLAGS.
#[inline(always)]
pub unsafe fn disable() {
    asm!("cli", options(nomem, nostack));
}

/// Notify the CPU that we have received this IRQ.
#[inline(always)]
pub fn eoi() {
    let mut lapic = X2APIC::new();
    lapic.attach();
    lapic.eoi();
}
