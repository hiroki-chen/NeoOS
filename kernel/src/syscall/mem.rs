//! Memory and paging related syscall interfaces.

use alloc::{boxed::Box, sync::Arc};
use rcore_fs::vfs::MMapArea;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, PAGE_SIZE},
    error::{Errno, KResult},
    fs::file::FileObject,
    memory::{brk_hook, is_page_aligned, mmap_hook, page_frame_number, KernelFrameAllocator},
    mm::{
        callback::{ArenaCallback, UserArenaCallback},
        Arena, ArenaFlags, ArenaType,
    },
    process::thread::{Thread, ThreadContext},
    sys::{Prot, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE},
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
    mmap_hook();

    let mut addr = syscall_registers[0];
    let length = syscall_registers[1];
    let prot = syscall_registers[2];
    let flags = syscall_registers[3];

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
        thread.vm.lock().remove_addr(addr, length as _)?;
    } else {
        // We follow the hint, but if there is no free memory, we force
        // use another address to map.
        addr = page_frame_number(thread.vm.lock().cur_heap_end() + PAGE_SIZE as u64 - 1);
    }

    // Then, we push the region back again into the process memory area.
    if flags & MAP_ANONYMOUS != 0 {
        let callback: Box<dyn ArenaCallback> = match flags & MAP_SHARED != 0 {
            true => todo!(),
            false => Box::new(UserArenaCallback::new(KernelFrameAllocator)),
        };

        thread.vm.lock().add(Arena {
            range: addr..addr + length,
            flags: prot.into(),
            callback,
            ty: ArenaType::Heap,
            name: "[heap]".into(),
        });

        Ok(addr as _)
    } else {
        // Do a memory map for the opened file.
        // Get the file descriptor.
        let fd = syscall_registers[4];
        let offset = syscall_registers[5];

        let file = proc.get_fd(fd)?;
        if let FileObject::File(file) = file {
            let area = MMapArea {
                start_vaddr: addr as _,
                end_vaddr: (addr + length) as _,
                prot: prot.bits() as _,
                flags: flags as _,
                offset: offset as _,
            };

            kinfo!("{addr:#x}");
            file.mmap(&area).map(|_| addr as usize)
        } else {
            Err(Errno::EINVAL)
        }
    }
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

    let mut vm = thread.vm.lock();
    let arena = vm
        .iter_mut()
        // Now we assume that some arena must "contain" the mprotected area.
        .find(|arena| arena.subset_of(addr..addr + len))
        .ok_or(Errno::ENOMEM)?;

    arena.flags = ArenaFlags::from(prot);

    Ok(0)
}

/// brk() sets the end of the data segment to the value specified by `addr`, when that value is reasonable, the system has
/// enough memory, and the process does not exceed its maximum data size. On success, brk() returns zero.
pub fn sys_brk(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    brk_hook();
    let addr = syscall_registers[0];

    // Check if `addr` is within the valid range.
    let vm = thread.vm.lock();
    let cur_end = vm.cur_heap_end();

    // Only handle `brk(NULL)` request.
    if addr == 0 {
        return Ok(cur_end as _);
    } else {
        Err(Errno::ENOMEM)
    }
}

/// The madvise() system call is used to give advice or directions to the kernel about the address range beginning at
/// address addr and with size length bytes In most cases, the goal of such advice is to improve system or application
/// performance.
pub fn sys_madvice(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}
