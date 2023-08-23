//! This module implementes the paging mechanism targeted at x86_64 platform.
//! Note that this is *platform-specific* implementation, and if you want to
//! check the backend-agnostic implementation of the kernel paging mechanism,
//! please refer to `kernel/src/mm/mod.rs`.
//!
//! The x86_64 architecture uses a 4-level page table and a page size of 4 KiB.
//! Each page table, independent of the level, has a fixed size of 512 entries.
//! Each entry has a size of 8 bytes, so each table is 512 * 8 B = 4 KiB large
//! and thus fits exactly into one page.
//!
//! It’s worth noting that the recent “Ice Lake” Intel CPUs optionally support
//! 5-level page tables to extend virtual addresses from 48-bit to 57-bit, but
//! we do not use 5-level page table.

pub mod paging;

use log::debug;

/// Pretty-prints the current page error information.
pub fn pretty_interpret(pf_errno: usize) {
    let present = pf_errno & 1;
    let write = (pf_errno & (1 << 1)) >> 1;
    let user = (pf_errno & (1 << 2)) >> 2;
    let reserved_write = (pf_errno & (1 << 3)) >> 3;
    let instruction_fetch = (pf_errno & (1 << 4)) >> 4;
    let protection_key = (pf_errno & (1 << 5)) >> 5;
    let shadow_stack = (pf_errno & (1 << 6)) >> 6;
    let sgx = (pf_errno & (1 << 7)) >> 7;

    debug!("+-------+------+------+------+------+-----+-----+-----+");
    debug!("|  SGX  |  SS  |  PK  |  IF  |  RW  |  U  |  W  |  P  |");
    debug!("+-------+------+------+------+------+-----+-----+-----+");
    debug!(
        "|   {}   |  {}   |  {}   |  {}   |  {}   |  {}  |  {}  |  {}  |",
        sgx, shadow_stack, protection_key, instruction_fetch, reserved_write, user, write, present
    );
    debug!("+-------+------+------+------+------+-----+-----+-----+");
}
