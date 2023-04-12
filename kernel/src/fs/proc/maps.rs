//! Prints the memory mapping information of a given thread.

use core::any::Any;

use rcore_fs::vfs::{make_rdev, FileType, FsError, INode, Metadata, PollStatus, Result, Timespec};

use crate::process::search_by_id;

pub struct Maps {
    proc_id: u64,
    inode: u64,
}

impl Maps {
    pub fn new(thread_id: u64, inode: u64) -> Self {
        Self {
            proc_id: thread_id,
            inode,
        }
    }
}

impl INode for Maps {
    fn read_at(&self, _offset: usize, buf: &mut [u8]) -> Result<usize> {
        let proc = search_by_id(self.proc_id).map_err(|_| FsError::NoDevice)?;
        let proc = proc.lock();
        let vm = proc.vm.lock();

        // Needs to format the virtual memory.
        let content = vm.get_maps().map_err(|_| FsError::NoDevice)?;
        if buf.len() < content.len() {
            return Err(FsError::InvalidParam);
        }

        buf[..content.len()].copy_from_slice(content.as_bytes());
        Ok(content.len())
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        Err(FsError::NotFile)
    }

    fn poll(&self) -> Result<PollStatus> {
        Ok(PollStatus {
            read: false,
            write: false,
            error: false,
        })
    }

    fn set_metadata(&self, _metadata: &Metadata) -> Result<()> {
        Ok(())
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: self.inode as _,
            size: 0,
            blk_size: 1024,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::File,
            // r--r--r--
            mode: 0o444,
            nlinks: 0,
            uid: 0,
            gid: 0,
            rdev: make_rdev(0x5, 0x5),
        })
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}
