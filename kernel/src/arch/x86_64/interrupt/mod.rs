use core::arch::asm;

/// All FLAGS registers contain the condition codes, flag bits that let the results of one machine-language
/// instruction affect another instruction. Since we need to disable the interrupt, the FLAGS registers should
/// be stored onto the stack.
#[inline(always)]
pub unsafe fn disable_and_store() -> usize {
    let mut flags: usize;
    asm!("pushf; pop {flags}; cli", flags = out(reg) flags);
    flags
}

#[inline(always)]
pub unsafe fn restore(flags: usize) {
    asm!("push {flags}; popf", flags = in(reg) flags)
}
