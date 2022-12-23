//! Implements the underlying operations by `Arena`.

use core::fmt::Debug;

use alloc::{boxed::Box, sync::Arc};
use log::error;
use x86_64::{PhysAddr, VirtAddr};

use crate::{
    arch::{mm::paging::PageTableBehaviors, PAGE_SIZE},
    error::KResult,
    fs::{file::ReadAsFile, vfs::INode},
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
        // Prepare source buffer.
        let file_offset = addr + self.file_start - self.mem_start;
        let read_size = (self.file_end as isize - file_offset.as_u64() as isize)
            .min(PAGE_SIZE as isize)
            .max(0) as usize;
        let read_size = self
            .file
            .read_buf_at(file_offset.as_u64() as usize, &mut dst[..read_size])?;
        if read_size != PAGE_SIZE {
            dst[read_size..].iter_mut().for_each(|d| *d = 0);
        }

        Ok(read_size)
    }
}

#[derive(Clone)]
pub struct INodeWrapper(pub Arc<dyn INode>);

impl ReadAsFile for INodeWrapper {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        self.0.read_buf_at(offset, buf)
    }
}

impl<F, A> ArenaCallback for FileArenaCallback<F, A>
where
    F: ReadAsFile,
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
        todo!()
    }

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: &ArenaFlags) {
        let entry = page_table.map(addr, PhysAddr::new(0));
        entry.set_present(false);
        entry.set_execute(!flags.non_executable);
        entry.set_writable(flags.writable);
        entry.set_user(flags.user_accessible);
        entry.set_mmio(flags.mmio);
        entry.update();
    }

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr) {
        let entry = match page_table.get_entry(addr) {
            Ok(entry) => entry,
            Err(errno) => {
                error!(
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
        let page_frame = page_frame_number(addr);
        let entry = match page_table.get_entry(VirtAddr::new(page_frame)) {
            Ok(e) => e,
            Err(errno) => return false,
        };

        if entry.present() {
            match check_permission(&access_type, entry) {
                true => return true,
                false => {
                    error!("do_handle_page_fault(): entry exists but access type violation was found. Access type: {:#x?}", access_type);
                    return false;
                }
            }
        }

        // Allocate a new physical frame for this page table entry.
        let frame = match self.frame_allocator.alloc() {
            Ok(f) => f,
            Err(errno) => {
                error!("do_handle_page_fault(): failed to allocate frame for page table entry. Error: {:?}", errno);
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
                error!("do_handle_page_fault(): failed to fill data.");
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
