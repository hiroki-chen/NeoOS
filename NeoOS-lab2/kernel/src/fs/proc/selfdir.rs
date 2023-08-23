//! Refers to `/proc/self`, a special kind of directory that redirects to /proc/pid (the calling process). Because Rust
//! reserves the `self` keyword, we rename this module to `selfdir`.

use core::sync::atomic::Ordering;

use alloc::{
    format,
    sync::{Arc, Weak},
};
use rcore_fs::vfs::{FileType, FsError, INode, Metadata, PollStatus, Result, Timespec};

use crate::{fs::INODE_COUNT, process::thread::current};

use super::ProcInode;

pub struct SelfDir {
    inode: u64,
    parent_ptr: Weak<ProcInode>,
}

impl SelfDir {
    pub fn new(parent_ptr: Weak<ProcInode>) -> Arc<Self> {
        Arc::new(Self {
            inode: INODE_COUNT.fetch_add(0x1, Ordering::SeqCst),
            parent_ptr,
        })
    }
}

impl INode for SelfDir {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        Err(FsError::IsDir)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        Err(FsError::IsDir)
    }

    fn poll(&self) -> Result<PollStatus> {
        Err(FsError::IsDir)
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn set_metadata(&self, _metadata: &Metadata) -> Result<()> {
        // Ignored
        Ok(())
    }

    fn metadata(&self) -> Result<Metadata> {
        // todo: more meaningful.
        Ok(Metadata {
            dev: 0,
            inode: self.inode as _,
            size: 1,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::Dir,
            mode: 0o755,
            nlinks: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
        })
    }

    fn find(&self, name: &str) -> Result<Arc<dyn INode>> {
        // Redirect to the calling process id.
        let pid = current().unwrap().parent.lock().process_id;
        let parent = self.parent_ptr.upgrade().unwrap();
        let parent_children = parent.children.read();

        // Read from the real one.
        Ok(parent_children
            .get(&format!("{pid}"))
            .ok_or(FsError::EntryNotFound)?
            .find(name)?
            .clone())
    }
}
