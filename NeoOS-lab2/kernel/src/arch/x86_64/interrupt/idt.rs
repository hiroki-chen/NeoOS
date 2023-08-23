//! The Interrupt Descriptor Table (IDT) is a binary data structure specific to the
//! IA-32 and x86-64 architectures. It is the Protected Mode and Long Mode
//! counterpart to the Real Mode Interrupt Vector Table (IVT) telling the CPU where
//! the Interrupt Service Routines (ISR) are located (one per interrupt vector). It
//! is similar to the Global Descriptor Table in structure.
//!
//! The IDT entries are called gates. It can contain Interrupt Gates, Task Gates and
//! Trap Gates.

use alloc::boxed::Box;
use x86_64::{
    structures::{
        idt::{Entry, HandlerFunc, InterruptDescriptorTable},
        DescriptorTablePointer,
    },
    PrivilegeLevel, VirtAddr,
};

use crate::error::KResult;

pub const IDT_ENTRY_SIZE: usize = 0x100;
pub const INT3: usize = 0x3;
pub const INT4: usize = 0x4;

extern "C" {
    /// There are 256 interrupt vectors (0..255), so the IDT should have 256 entries
    /// each entry (`extern "C" fn()` pointers) corresponding to a specific interrupt
    /// vector.
    ///
    /// To invoke each handler, we cannot rely on Rust compiler. We must manually
    /// write assembly code to get them work.
    ///
    /// ```asm
    ///   movq %rax, 0(VECTORS)
    ///   call %rax
    /// ```
    #[link_name = "__idt_vectors"]
    static VECTORS: [extern "C" fn(); IDT_ENTRY_SIZE];
}

/// Initialize all the interrupt vectors for later usage.
pub fn init_idt() -> KResult<()> {
    // The crate x86_64 automatically wraps IDT table for us.
    // Do not drop this since the ownership is transferred to the CPU.
    let kernel_idt_table = Box::leak(Box::new(InterruptDescriptorTable::new()));

    // Construct the entry from `kernel_idt_table`.
    let entries: &mut [Entry<HandlerFunc>; IDT_ENTRY_SIZE] =
        unsafe { core::mem::transmute_copy(&kernel_idt_table) };
    // Copy `VECTORS` into `entries`.
    for i in 0..IDT_ENTRY_SIZE {
        let entry = unsafe {
            log::debug!(
                "init_idt(): IDT vector #[{}]: {:#x}",
                i,
                VECTORS[i] as usize
            );
            entries[i].set_handler_addr(VirtAddr::new(VECTORS[i] as u64))
        };
        // Set privilege level for enabling user-space interrupts.
        entry.set_privilege_level(if i == INT3 || i == INT4 {
            PrivilegeLevel::Ring3
        } else {
            PrivilegeLevel::Ring0
        });
    }

    // Load LDT.
    kernel_idt_table.load();
    log::debug!("init_idt(): IDT loaded at {:#x?}", sidt());

    Ok(())
}

/// Dumps current IDT register
#[allow(dead_code)]
#[inline(always)]
pub fn sidt() -> DescriptorTablePointer {
    let mut dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::zero(),
    };
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &mut dtp);
    }
    dtp
}
