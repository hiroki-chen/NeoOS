//! x86_64 support for signal handling.

use super::interrupt::Context;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SigContext {
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    pub r11: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub rdx: usize,
    pub rax: usize,
    pub rcx: usize,
    pub rsp: usize,
    pub rip: usize,
    pub eflags: usize,

    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub _pad: u16,

    pub err: usize,
    pub trapno: usize,
    pub oldmask: usize,
    pub cr2: usize,
    pub fpstate: usize,
    // reserved
    pub _reserved1: [usize; 8],
}

impl SigContext {
    pub fn from_uctx(ctx: &Context) -> Self {
        // Do some copies.
        Self {
            r8: ctx.regs.r8 as _,
            r9: ctx.regs.r9 as _,
            r10: ctx.regs.r10 as _,
            r11: ctx.regs.r11 as _,
            r12: ctx.regs.r12 as _,
            r13: ctx.regs.r13 as _,
            r14: ctx.regs.r14 as _,
            r15: ctx.regs.r15 as _,
            rdi: ctx.regs.rdi as _,
            rsi: ctx.regs.rsi as _,
            rax: ctx.regs.rax as _,
            rbx: ctx.regs.rbx as _,
            rcx: ctx.regs.rcx as _,
            rdx: ctx.regs.rdx as _,
            rbp: ctx.regs.rbp as _,
            rsp: ctx.regs.rsp as _,
            rip: ctx.regs.rip as _,
            eflags: ctx.regs.rflags as _,
            cs: 0,
            gs: 0,
            fs: 0,
            _pad: 0,
            err: ctx.errno as _,
            trapno: ctx.trapno as _,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            _reserved1: [0; 8],
        }
    }
}
