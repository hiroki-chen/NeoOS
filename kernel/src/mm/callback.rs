//! Implements the underlying operations by `Arena`.

use core::fmt::Debug;

use alloc::{boxed::Box, sync::Arc};
use log::error;
use x86_64::{PhysAddr, VirtAddr};

use crate::{
    arch::mm::paging::PageTableBehaviors,
    fs::{file::ReadAsFile, vfs::INode},
    memory::FrameAlloc,
};

use super::ArenaFlags;

pub trait ArenaCallback: Debug + Send + Sync + 'static {
    fn clone_as_box(&self) -> Box<dyn ArenaCallback>;

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: ArenaFlags);

    fn unmap(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr);
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

#[derive(Clone)]
pub struct INodeWrapper(pub Arc<dyn INode>);

impl ReadAsFile for INodeWrapper {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> crate::error::KResult<usize> {
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

    fn map(&self, page_table: &mut dyn PageTableBehaviors, addr: VirtAddr, flags: ArenaFlags) {
        let entry = page_table.map(addr, PhysAddr::new(0));
        entry.set_present(false);
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
