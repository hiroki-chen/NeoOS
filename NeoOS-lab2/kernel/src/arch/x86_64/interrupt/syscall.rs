//! To initialize syscalls, you will typically need to write some low-level code in a
//! programming language like C or Assembly. This module implements syscalls in our
//! kernel.
//!
//! To implement syscalls, we will need a syscall table that defines the routines for
//! each syscall type, and then we register them into the STAR. The STAR register is a
//! 64-bit register that is used on X86_64 platforms to store the address of the
//! syscall handler.

use core::arch::global_asm;

use log::error;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

global_asm!(include_str!("syscall.S"));

use crate::{
    arch::cpu::cpu_feature_info,
    error::{Errno, KResult},
};

use super::Context;

extern "sysv64" {
    /// Note the calling convention : rdi, rsi, rdx, r10-8.
    /// The entry point to syscall functions. Note that this function call is only valid for
    /// non-Windows platforms.
    pub fn __syscall();

    /// Syscall return.
    pub fn __sysreturn(ctx: &mut Context);
}

/// Enables the CPU support for `syscall` instruction. This involves writing to the
/// MSR registers. Once you have confirmed that your CPU supports the `syscall`
/// instruction, you will need to make sure that the operating system or hypervisor
/// is configured to use the `syscall` instruction for making syscalls.
pub fn init_syscall() -> KResult<()> {
    // Check if the CPU supports this.
    let feature_info = cpu_feature_info()?;
    if !feature_info.has_sysenter_sysexit() {
        error!("enable_syscall(): CPU does not support instructions!.");
        return Err(Errno::EEXIST);
    }

    // Enable it by writing to the Efer MSR.
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }

    // These flags will be cleared during syscall initialization. When a syscall is
    // made, the operating system may clear some of the flags in the RFLAGS register
    // for several reasons. For example, we need to disable interrupt when syscall is
    // initializing.
    //
    // Some common flags that may be cleared include the IF flag, the TF flag, the AC
    // flag, and the DF flag. Linux: IOPL | NT.
    // See: https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-2.html
    //
    // X86_EFLAGS_TF   | X86_EFLAGS_DF | X86_EFLAGS_IF |
    // X86_EFLAGS_IOPL | X86_EFLAGS_AC | X86_EFLAGS_NT
    let rflags_mask_syscall: RFlags = RFlags::TRAP_FLAG
        | RFlags::DIRECTION_FLAG
        | RFlags::INTERRUPT_FLAG
        | RFlags::IOPL_LOW
        | RFlags::IOPL_HIGH
        | RFlags::ALIGNMENT_CHECK
        | RFlags::NESTED_TASK;

    SFMask::write(rflags_mask_syscall);
    LStar::write(VirtAddr::new(__syscall as u64));

    Ok(())
}
