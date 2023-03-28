//! Linux ELF format parsing module.

use core::ffi::CStr;

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use goblin::{
    container::Ctx,
    elf::{Elf, Header, ProgramHeader},
};
use rcore_fs::vfs::INode;

use crate::{
    arch::{mm::paging::KernelPageTable, PAGE_SIZE},
    error::{fserror_to_kerror, Errno, KResult},
    function, kdebug, kerror, kinfo,
    memory::KernelFrameAllocator,
    mm::{
        callback::{FileArenaCallback, INodeWrapper},
        Arena, ArenaFlags, MemoryManager,
    },
    page,
    process::ld::{AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM},
    virt,
};

pub struct ElfFile {
    header: Header,
    program_headers: Vec<ProgramHeader>,
    ctx: Ctx,
    inode: Arc<dyn INode>,
    raw: [u8; 0x3c0],
}

impl ElfFile {
    /// Loads the elf file from the memory. This only parses the header!
    pub fn load(inode: &Arc<dyn INode>) -> KResult<Self> {
        kinfo!("loading ELF header");

        let mut buf = [0u8; 0x3c0];
        let size = inode.read_at(0, &mut buf).map_err(fserror_to_kerror)?;
        if size != buf.len() {
            kerror!("reading is wrong.");
            return Err(Errno::ENFILE);
        }

        let header = Elf::parse_header(&buf).map_err(|err| {
            kerror!("elf parsing failed. Error: {}", err.to_string());
            Errno::EINVAL
        })?;
        let ctx = Ctx::new(header.container().unwrap(), header.endianness().unwrap());

        // Check if the type is correct.
        let elf_type = header.e_type;
        if (elf_type & 0x2 == 0) || (elf_type & 0x3 == 0) {
            kerror!("unsupported ELF type. Should be shared object or executable. Got {elf_type}.");
            return Err(Errno::EINVAL);
        }

        // Check if the target architecture is correct.
        let arch = header.e_machine;
        if arch & 0x3E == 0 {
            kerror!("unsupported target architecture. Should be x86_64. Got {arch}.");
            return Err(Errno::EINVAL);
        }

        // Iterate all the program headers from the header.
        let program_headers =
            ProgramHeader::parse(&buf, header.e_phoff as _, header.e_phnum as _, ctx).map_err(
                |err| {
                    kerror!("cannot parse program headers. Err: {}", err.to_string());
                    Errno::EINVAL
                },
            )?;

        Ok(Self {
            header,
            ctx,
            program_headers,
            inode: inode.clone(),
            raw: buf,
        })
    }

    /// Loads a memory from a disk INode and then maps it into the virtual memory. Returns the largest memory we can use.
    pub fn load_elf_and_map(&self, vm: &mut MemoryManager<KernelPageTable>) -> KResult<u64> {
        kinfo!(" mapping the ELF file into memory.");

        let mut max_mem = 0;
        for ph in self.program_headers.iter() {
            kdebug!("visiting program header of type {:x}", ph.p_type);

            if ph.p_type == 0x1 {
                kdebug!("loading program header {:x?}", ph);
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
                        file: INodeWrapper(self.inode.clone()),
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

    pub fn get_interpreter(&self) -> KResult<&str> {
        // No interpret => executable.
        let interpret_header = self
            .program_headers
            .iter()
            .find(|header| header.p_type == 0x3)
            .ok_or({
                kerror!("This ELF file does not contain interpreter. This file does no depend on shared objects.");
                Errno::EINVAL
            })?;

        // Read the name: ld.so / ld-musl.so
        let offset = interpret_header.p_offset;
        let slice = &self.raw[offset as usize..(offset + interpret_header.p_filesz) as usize];

        Ok(CStr::from_bytes_until_nul(slice)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default())
    }

    /// Constructs the auxiliary vector map.
    ///
    /// The auxiliary vector (aka auxv) is some memory near the start of a running ELF program's stack. Specifically,
    /// it's a sequence of pairs of either 64 bit or 32 bit unsigned ints. The two components of the pair form a key and
    /// a value.
    pub fn get_auxv(&self) -> KResult<BTreeMap<u8, usize>> {
        let mut auxv = BTreeMap::new();
        let program_headers = &self.program_headers;

        match program_headers
            .iter()
            .find(|&program_header| program_header.p_type == 0x6)
        {
            Some(at_phdr) => {
                auxv.insert(AT_PHDR, at_phdr.p_vaddr as usize);
            }
            None => {
                if let Some(at_phdr) = program_headers.iter().find(|&program_header| {
                    program_header.p_type == 0x1 && program_header.p_offset == 0
                }) {
                    auxv.insert(AT_PHDR, (at_phdr.p_vaddr + self.header.e_phoff) as usize);
                }
            }
        }

        auxv.insert(AT_PHENT, self.header.e_phentsize as usize);
        auxv.insert(AT_PHNUM, self.header.e_phnum as usize);
        auxv.insert(AT_PAGESZ, PAGE_SIZE);

        Ok(auxv)
    }

    /// Gets the entry point.
    #[inline]
    pub fn entry_point(&self) -> u64 {
        self.header.e_entry
    }
}
