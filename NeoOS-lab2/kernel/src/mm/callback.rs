//! Implements the underlying operations by `Arena`.

use core::{fmt::Debug, marker::PhantomData};

use alloc::{boxed::Box, format, sync::Arc};
use rcore_fs::vfs::INode;
use x86_64::VirtAddr;

use crate::{
    arch::{mm::paging::PageTableBehaviors, PAGE_SIZE},
    error::{fserror_to_kerror, KResult},
    fs::file::ReadAsFile,
    memory::{page_frame_number, FrameAlloc},
};

use super::{check_permission, AccessType, ArenaFlags};

pub trait ArenaCallback: Debug + Send + Sync + 'static {
    fn clone_as_box(&self) -> Box<dyn ArenaCallback>;

    fn clone_and_map(
        &self,
        dst: &mut dyn PageTableBehaviors,
        src: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
        flags: &ArenaFlags,
    );

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags);

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr);

    /// Kernel interrupt handler -> kernel::handle_page_fault -> thread.vm::handle_page_fault ->
    /// arena::callback::handle_page_fault (this interface).
    fn handle_page_fault(&self, page_table: &mut dyn PageTableBehaviors, addr: u64) -> bool {
        self.do_handle_page_fault(page_table, addr, AccessType::all())
    }

    fn do_handle_page_fault(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: u64,
        access_type: AccessType,
    ) -> bool;

    fn inode(&self) -> u64 {
        0
    }

    fn shared(&self) -> bool {
        false
    }
}

impl Clone for Box<dyn ArenaCallback> {
    fn clone(&self) -> Self {
        self.clone_as_box()
    }
}

/// The callback for a file that allocates memory and maps it into the memory.
#[derive(Clone)]
pub struct FileArenaCallback<F, A> {
    pub file: F,
    pub mem_start: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub frame_allocator: A,
}

/// The callback for virtual memory mappings like `mmap` would do.
#[derive(Clone, Debug)]
pub struct UserArenaCallback<A> {
    frame_allocator: A,
}

/// The callback for normal memory allocators.
#[derive(Clone, Debug)]
pub struct SystemArenaCallback<A>
where
    A: FrameAlloc,
{
    frame_allocator: A,
}

/// A dummy callback that does nothing.
#[derive(Clone, Debug)]
pub struct DummyArenaCallback<A>
where
    A: FrameAlloc,
{
    _marker: PhantomData<A>,
}

impl<A> SystemArenaCallback<A>
where
    A: FrameAlloc,
{
    pub fn new(frame_allocator: A) -> Self {
        Self { frame_allocator }
    }
}

impl<A> DummyArenaCallback<A>
where
    A: FrameAlloc,
{
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<A> UserArenaCallback<A>
where
    A: FrameAlloc,
{
    pub fn new(frame_allocator: A) -> Self {
        Self { frame_allocator }
    }
}

impl<F, A> FileArenaCallback<F, A>
where
    F: ReadAsFile,
    A: FrameAlloc,
{
    /// After a new entry is created, we need to copy the file to that entry.
    pub fn fill_data(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
    ) -> KResult<usize> {
        // Destination virtual memory region.
        let dst = page_table.get_page_slice_mut(addr)?;
        // Prepare source buffer. Memory offset + file base.
        // We always copy a page, so there is a need to round up the address.
        let file_offset = page_frame_number(addr.as_u64()) + self.file_start - self.mem_start;

        // This function still contain some minor bug. Fix it.
        let read_size = (self.file_end as isize - file_offset as isize)
            // If the read_size becomes zero, it usually happens when the file size is smaller than the memory
            // size for some sectiosn like .bss or .data.
            // .max((self.file_end - self.file_start) as _)
            .min(PAGE_SIZE as isize)
            .max(0) as usize;

        let read_size = self
            .file
            .read_at(file_offset as usize, &mut dst[..read_size])?;
        if read_size != PAGE_SIZE {
            dst[read_size..].fill(0);
        }

        Ok(read_size)
    }
}

#[derive(Clone)]
pub struct INodeWrapper(pub Arc<dyn INode>);

impl ReadAsFile for INodeWrapper {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        self.0.read_at(offset, buf).map_err(fserror_to_kerror)
    }

    fn inode(&self) -> u64 {
        self.0.metadata().unwrap().inode as _
    }
}

impl<F, A> ArenaCallback for FileArenaCallback<F, A>
where
    F: ReadAsFile,
    A: FrameAlloc,
{
    fn inode(&self) -> u64 {
        self.file.inode()
    }

    fn clone_as_box(&self) -> Box<dyn ArenaCallback> {
        Box::new(self.clone())
    }

    fn clone_and_map(
        &self,
        dst: &mut dyn PageTableBehaviors,
        src: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
        flags: &ArenaFlags,
    ) {
        let src_entry = src.get_entry(addr).expect(&format!(
            "failed to get entry from the source page table @ {addr:#x}"
        ));
        // Check if the source entry is ok.
        if src_entry.present() && flags.writable {
            // If ok, we can directly copy the page table entry from the source page table.
            let src_buf = src.get_page_slice_mut(addr).expect(&format!(
                "failed to get entry from the source page table @ {addr:#x}"
            ));
            let frame = self
                .frame_allocator
                .alloc()
                .expect("failed to allocate new frame");
            // Maps `addr` to `frame`
            let dst_entry = dst.map(addr, frame);
            // Apply the memory attribute from the source manager.
            dst_entry.set_writable(flags.writable);
            dst_entry.set_execute(!flags.non_executable);
            dst_entry.set_user(flags.user_accessible);
            dst_entry.update();

            // Then copy the data into frame.
            dst.get_page_slice_mut(addr)
                .expect(&format!(
                    "failed to get entry from the source page table @ {addr:#x}",
                ))
                .copy_from_slice(src_buf);
            // FIXME: Notify other cores (?): slow and some bug
            // tlb_broadcast(None, Some(addr));
        } else {
            // Map to 0x0 and copy from the file instead because the source page table entry is now allowed
            // for us to touch. This is delayed mapping.
            self.map(dst, addr, flags);
        }
    }

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags) {
        let entry = page_table.map(addr, phys!(0));
        // Delayed mapping.
        entry.set_present(false);
        entry.set_execute(!flags.non_executable);
        entry.set_writable(flags.writable);
        entry.set_user(flags.user_accessible);
        entry.set_mmio(flags.mmio);
        entry.update();
    }

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr) {
        match page_table.get_entry(addr) {
            Ok(entry) => {
                if entry.present() {
                    self.frame_allocator
                        .dealloc(entry.target().as_u64())
                        .unwrap();
                }
                entry.set_present(true);
                page_table.unmap(addr);
            }
            Err(errno) => {
                kerror!(
                    "FileArenaCallback::unmap(): unable to find page table entry @ {:#x}",
                    addr.as_u64()
                );
                return;
            }
        };
    }

    fn do_handle_page_fault(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: u64,
        access_type: AccessType,
    ) -> bool {
        let entry = match page_table.get_entry(VirtAddr::new(addr)) {
            Ok(e) => e,
            Err(errno) => return false,
        };

        if entry.present() {
            match check_permission(&access_type, entry) {
                true => return true,
                false => {
                    kerror!(
                        "entry exists but access type violation was found. Access type: {:#x?}; entry: {:#x?}; fault address is {:#x}",
                        access_type,
                        entry,
                        addr,
                    );
                    return false;
                }
            }
        }

        // Allocate a new physical frame for this page table entry.
        let frame = match self.frame_allocator.alloc() {
            Ok(f) => f,
            Err(errno) => {
                kerror!(
                    "failed to allocate frame for page table entry. Error: {:?}",
                    errno
                );
                return false;
            }
        };

        // Map to this entry.
        entry.set_target(frame);
        entry.set_present(true);
        entry.update();

        match self.fill_data(page_table, VirtAddr::new(addr)) {
            Ok(_) => true,
            Err(errno) => {
                kerror!("failed to fill data.");
                false
            }
        }
    }
}

impl<F, A> Debug for FileArenaCallback<F, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Memory start: {:#x}; File start: {:#x}; File end: {:#x}",
            self.mem_start, self.file_start, self.file_end
        )
    }
}

impl<A> ArenaCallback for SystemArenaCallback<A>
where
    A: FrameAlloc,
{
    fn clone_as_box(&self) -> Box<dyn ArenaCallback> {
        Box::new(self.clone())
    }

    fn clone_and_map(
        &self,
        dst: &mut dyn PageTableBehaviors,
        src: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
        flags: &ArenaFlags,
    ) {
        let entry = src
            .get_entry(addr)
            .expect("clone_and_map(): failed to get entry");
        if entry.present() {
            // eager map and copy data
            let data = src.get_page_slice_mut(addr).unwrap();
            let target = self
                .frame_allocator
                .alloc()
                .expect("clone_and_map(): failed to alloc frame");
            let entry = dst.map(addr, target);

            entry.set_execute(!flags.non_executable);
            entry.set_writable(flags.writable);
            entry.set_user(flags.user_accessible);
            entry.set_mmio(flags.mmio);
            entry.update();

            dst.get_page_slice_mut(addr).unwrap().copy_from_slice(data);
        } else {
            // delay map
            self.map(dst, addr, flags);
        }
    }

    fn do_handle_page_fault(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: u64,
        access_type: AccessType,
    ) -> bool {
        let entry = match page_table.get_entry(VirtAddr::new(addr)) {
            Ok(e) => e,
            Err(errno) => return false,
        };

        if entry.present() {
            match check_permission(&access_type, entry) {
                true => return true,
                false => {
                    kerror!(
                        "entry exists but access type violation was found. Access type: {:#x?}, fault address is {:#x}",
                        access_type,
                        addr,
                    );
                    return false;
                }
            }
        }

        // Allocate a new physical frame for this page table entry.
        let frame = match self.frame_allocator.alloc() {
            Ok(f) => f,
            Err(errno) => {
                kerror!(
                    "failed to allocate frame for page table entry. Error: {:?}",
                    errno
                );
                return false;
            }
        };

        // Map to this entry.
        entry.set_target(frame);
        entry.set_present(true);
        entry.update();

        let data = page_table.get_page_slice_mut(VirtAddr::new(addr)).unwrap();
        for d in data {
            *d = 0;
        }

        true
    }

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags) {
        let frame = self
            .frame_allocator
            .alloc()
            .expect("map(): no physical memory available!");
        let entry = page_table.map(addr, frame);
        entry.set_present(true);
        entry.set_execute(!flags.non_executable);
        entry.set_writable(flags.writable);
        entry.set_user(flags.user_accessible);
        entry.set_mmio(flags.mmio);
        entry.update();
    }

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr) {
        let entry = page_table
            .get_entry(addr)
            .expect("unmap(): failed to get entry; maybe unmapped?");
        self.frame_allocator
            .dealloc(entry.target().as_u64())
            .unwrap();
        page_table.unmap(addr);
    }
}

impl<A> ArenaCallback for DummyArenaCallback<A>
where
    A: FrameAlloc,
{
    fn clone_as_box(&self) -> Box<dyn ArenaCallback> {
        Box::new(self.clone())
    }

    fn clone_and_map(
        &self,
        dst: &mut dyn PageTableBehaviors,
        src: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
        flags: &ArenaFlags,
    ) {
        // This function should not panic.
    }

    fn do_handle_page_fault(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: u64,
        access_type: AccessType,
    ) -> bool {
        kerror!("trying to use dummy callback @ {addr:#x}");
        false
    }

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags) {
        panic!("trying to use dummy callback @ {addr:#x}");
    }

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr) {
        // Ignored.
    }
}

impl<A> ArenaCallback for UserArenaCallback<A>
where
    A: FrameAlloc,
{
    fn clone_as_box(&self) -> Box<dyn ArenaCallback> {
        Box::new(self.clone())
    }

    fn clone_and_map(
        &self,
        dst: &mut dyn PageTableBehaviors,
        src: &mut dyn PageTableBehaviors,
        addr: VirtAddr,
        flags: &ArenaFlags,
    ) {
        let src_entry = src.get_entry(addr).expect(&format!(
            "failed to get entry from the source page table @ {addr:#x}"
        ));
        // Check if the source entry is ok.
        if src_entry.present() {
            // If ok, we can directly copy the page table entry from the source page table.
            let src_buf = src.get_page_slice_mut(addr).expect(&format!(
                "failed to get entry from the source page table @ {addr:#x}"
            ));
            let frame = self
                .frame_allocator
                .alloc()
                .expect("failed to allocate new frame");
            // Maps `addr` to `frame`
            let dst_entry = dst.map(addr, frame);
            // Apply the memory attribute from the source manager.
            dst_entry.set_writable(flags.writable);
            dst_entry.set_execute(!flags.non_executable);
            dst_entry.set_user(flags.user_accessible);
            dst_entry.update();

            // Then copy the data into frame.
            dst.get_page_slice_mut(addr)
                .expect(&format!(
                    "failed to get entry from the source page table @ {addr:#x}",
                ))
                .copy_from_slice(src_buf);
        } else {
            self.map(dst, addr, flags);
        }
    }

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags) {
        // Temporarily map `addr` into a dummy physical address and set `present` bit to be 0 to cause a deliberate
        // page fault that we deal with in `do_handle_page_fault`.
        let entry = page_table.map(addr, phys!(0));
        entry.set_present(false);
        entry.update();
    }

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr) {
        match page_table.get_entry(addr) {
            Ok(entry) => {
                if entry.present() {
                    let _ = self.frame_allocator.dealloc(entry.target().as_u64());
                } else {
                    entry.set_present(true);
                }

                page_table.unmap(addr);
            }
            Err(_) => kwarn!("Trying to unmap a non-existing page table entry"),
        }
    }

    fn do_handle_page_fault(
        &self,
        page_table: &mut dyn PageTableBehaviors,
        addr: u64,
        access_type: AccessType,
    ) -> bool {
        let entry = match page_table.get_entry(VirtAddr::new(addr)) {
            Ok(e) => e,
            Err(errno) => return false,
        };

        if entry.present() {
            match check_permission(&access_type, entry) {
                true => return true,
                false => {
                    kerror!(
                        "entry exists but access type violation was found. Access type: {:#x?}, fault address is {:#x}",
                        access_type,
                        addr,
                    );
                    return false;
                }
            }
        }

        // Allocate a new physical frame for this page table entry.
        let frame = match self.frame_allocator.alloc() {
            Ok(f) => f,
            Err(errno) => {
                kerror!(
                    "failed to allocate frame for page table entry. Error: {:?}",
                    errno
                );
                return false;
            }
        };

        // Map to this entry.
        entry.set_target(frame);
        entry.set_present(true);
        entry.update();

        let data = page_table.get_page_slice_mut(VirtAddr::new(addr)).unwrap();
        for d in data {
            *d = 0;
        }

        true
    }
}
