//! Linux ELF format parsing module.

use alloc::{boxed::Box, string::ToString, sync::Arc};
use goblin::{
    container::Ctx,
    elf::{Elf, ProgramHeader},
};
use rcore_fs::vfs::INode;

use crate::{
    arch::{mm::paging::KernelPageTable, PAGE_SIZE},
    error::{fserror_to_kerror, Errno, KResult},
    function, kerror, kinfo,
    memory::KernelFrameAllocator,
    mm::{
        callback::{FileArenaCallback, INodeWrapper},
        Arena, ArenaFlags, MemoryManager,
    },
    page, virt,
};

/// Loads a memory from a disk INode and then maps it into the virtual memory. Returns the largest memory we can use.
pub fn load_elf_and_map(
    vm: &mut MemoryManager<KernelPageTable>,
    inode: &Arc<dyn INode>,
) -> KResult<u64> {
    kinfo!("loading the ELF file and mapping it into memory.");
    let mut max_mem = 0u64;
    let mut buf = [0u8; 0x3c0];
    let size = inode.read_at(0, &mut buf).map_err(fserror_to_kerror)?;
    if size != buf.len() {
        kerror!("reading is wrong.");
        return Err(Errno::ENFILE);
    }

    let elf_header = Elf::parse_header(&buf).map_err(|err| {
        kerror!("elf parsing failed. Error: {}", err.to_string());
        Errno::EINVAL
    })?;
    let ctx = Ctx::new(
        elf_header.container().unwrap(),
        elf_header.endianness().unwrap(),
    );

    // Check if the type is correct.
    let elf_type = elf_header.e_type;
    if (elf_type & 0x2 == 0) || (elf_type & 0x3 == 0) {
        kerror!("unsupported ELF type. Should be shared object or executable. Got {elf_type}.");
        return Err(Errno::EINVAL);
    }

    // Check if the target architecture is correct.
    let arch = elf_header.e_machine;
    if arch & 0x3E == 0 {
        kerror!("unsupported target architecture. Should be x86_64. Got {arch}.");
        return Err(Errno::EINVAL);
    }

    // Iterate all the program headers from the header.
    let program_header =
        ProgramHeader::parse(&buf, elf_header.e_phoff as _, elf_header.e_phnum as _, ctx).map_err(
            |err| {
                kerror!("cannot parse program headers. Err: {}", err.to_string());
                Errno::EINVAL
            },
        )?;
    for ph in program_header.iter() {
        kinfo!("visiting program header of type {:x}", ph.p_type);

        if ph.p_type & 0x1 != 0 {
            // This header can be loaded.
            vm.add(Arena {
                range: ph.p_vaddr..ph.p_vaddr + ph.p_memsz,
                flags: ArenaFlags {
                    writable: 0x2 & ph.p_flags != 0,
                    user_accessible: true,
                    non_executable: 0x1 & ph.p_flags == 0,
                    mmio: 0,
                },
                callback: Box::new(FileArenaCallback {
                    file: INodeWrapper(inode.clone()),
                    mem_start: ph.p_vaddr,
                    file_start: ph.p_offset,
                    file_end: ph.p_offset + ph.p_filesz,
                    frame_allocator: KernelFrameAllocator,
                }),
            })
        }

        max_mem = max_mem.max(ph.p_vaddr + ph.p_memsz);
    }

    // Get the entry point.
    Ok(page!(max_mem + PAGE_SIZE as u64).start_address().as_u64())
}
