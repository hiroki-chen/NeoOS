//! To initialize syscalls, you will typically need to write some low-level code in a
//! programming language like C or Assembly. This module implements syscalls in our
//! kernel.
//! 
//! To implement syscalls, we will need a syscall table that defines the routines for
//! each syscall type, and then we register them into the STAR. The STAR register is a
//! 64-bit register that is used on X86_64 platforms to store the address of the
//! syscall handler. 

use crate::error::KResult;

pub fn init_syscalls() -> KResult<()> {


  Ok(())
}