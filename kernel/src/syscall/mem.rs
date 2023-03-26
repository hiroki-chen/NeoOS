//! Memory and paging related syscall interfaces.

use alloc::sync::Arc;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, PAGE_SIZE},
    error::{Errno, KResult},
    memory::is_page_aligned,
    process::thread::{Thread, ThreadContext},
    sys::{Prot, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE},
};

/// mmap() creates a new mapping in the virtual address space of the calling process. The starting address for the new
/// mapping is specified in `addr`. The length argument specifies the length of the mapping (which must be greater than 0).
///
/// If `addr` is `NULL`, then the kernel chooses the (page-aligned) address at which to create the mapping; this is the most
/// portable method of creating a new mapping.
pub fn sys_mmap(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let mut addr = syscall_registers[0];
    let length = syscall_registers[1];
    let prot = syscall_registers[2];
    let flags = syscall_registers[3];
    let fd = syscall_registers[4];
    let offset = syscall_registers[5];

    // The argument `addr` is just a hint to the kernel that the thread recommends, but eventually it is up to the
    // kernel to decide which address is the best one.
    if addr == 0 {
        // Although NULL is valid when using `mmap` to create mapping at arbitrary address, we still use a canonical
        // address to do the mapping since it is portable to do so.
        addr = PAGE_SIZE as _;
    }

    if (flags & MAP_SHARED == 0)
        && (flags & MAP_PRIVATE == 0)
        && (flags & MAP_FIXED == 0)
        && (flags & MAP_SHARED_VALIDATE == 0)
    {
        // Flags must contain at least one of the above property.
        return Err(Errno::EINVAL);
    }

    let prot = Prot::from_bits_truncate(prot);
    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    if flags & MAP_FIXED != 0 {
        // Don't interpret addr as a hint: place the mapping at
        // exactly that address.  addr must be suitably aligned: for
        // most architectures a multiple of the page size is
        // sufficient; however, some architectures may impose
        // additional restrictions.  If the memory region specified
        // by addr and length overlaps pages of any existing
        // mapping(s), then the overlapped part of the existing
        // mapping(s) will be discarded.  If the specified address
        // cannot be used, mmap() will fail.
        // thread.vm.lock().
    } else {
        // We follow the hint, but if there is no free memory, we force
        // use another address to map.
        addr = thread
            .vm
            .lock()
            .find_free_arena(addr, length as _)?
            .as_u64();
    }

    // Then, we push the region back again into the process memory area.

    Ok(0)
}

/// The reverse of `mmap` syscall.
pub fn sys_munmap(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}

/// mprotect() changes the access protections for the calling process's memory pages containing any part of the address range
/// in the interval [`addr`, `addr+len-1`]. `addr` must be aligned to a page boundary.
pub fn sys_mprotect(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let addr = syscall_registers[0];
    let len = syscall_registers[1];
    let prot = syscall_registers[2];

    if !is_page_aligned(addr) {
        // The pointer must be aligned.
        return Err(Errno::EINVAL);
    }

    let prot = Prot::from_bits_truncate(prot);
    if prot.intersects(Prot::PROT_GROWSDOWN | Prot::PROT_GROWSUP) {
        return Err(Errno::EINVAL);
    }

    let vm = thread.vm.lock();
    let arena = vm
        .iter()
        .find(|arena| arena.overlap_with(&(addr..addr + len)))
        .ok_or(Errno::ENOMEM)?;

    if !arena.flags.user_accessible || (!arena.flags.writable && prot.contains(Prot::PROT_WRITE)) {
        return Err(Errno::EACCES);
    }

    Ok(0)
}
