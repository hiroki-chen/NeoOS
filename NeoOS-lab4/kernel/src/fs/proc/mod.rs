//! A special filesystem for yielding process information.

use core::sync::atomic::Ordering;

use alloc::{
    collections::BTreeMap,
    format,
    string::String,
    sync::{Arc, Weak},
};
use lazy_static::lazy_static;
use rcore_fs::vfs::{
    FileSystem, FileType, FsError, FsInfo, INode, Metadata, PollStatus, Result, Timespec,
};
use spin::RwLock;

use crate::{function, kdebug};

use self::{maps::Maps, selfdir::SelfDir};

use super::INODE_COUNT;

pub mod maps;
pub mod selfdir;

lazy_static! {
    pub static ref PROC_FS: Arc<ProcFileSystem> = ProcFileSystem::new();
}

pub struct ProcFileSystem {
    /// The mount point directory. Should be /proc.
    mount_point: Arc<ProcInode>,
}

impl ProcFileSystem {
    pub fn new() -> Arc<Self> {
        let fs = Arc::new(Self {
            mount_point: ProcInode::new(None),
        });
        // Add `self`.
        fs.mount_point
            .children
            .write()
            .insert("self".into(), SelfDir::new(Arc::downgrade(&fs.mount_point)));
        *fs.mount_point.fs.write() = Arc::downgrade(&fs);
        fs
    }

    /// Inserts a new device inode. Should be called when a new process is created.
    pub fn add_new(&self, pid: u64) {
        let inode_id = INODE_COUNT.fetch_add(0x1, Ordering::SeqCst);
        let pid_dir = ProcInode::new(Some(Arc::downgrade(&self.mount_point)));

        // Create some files.
        let mut children = pid_dir.children.write();
        children.insert(
            "maps".into(),
            Arc::new(Maps::new(pid, INODE_COUNT.fetch_add(0x1, Ordering::SeqCst))),
        );
        drop(children);

        // Add to the parent.
        self.mount_point
            .children
            .write()
            .insert(format!("{pid}"), pid_dir);
        kdebug!("added {pid} into the /proc filesystem");
    }
}

impl FileSystem for ProcFileSystem {
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn INode> {
        self.mount_point.clone()
    }

    fn info(&self) -> FsInfo {
        FsInfo {
            bsize: 0,
            frsize: 0,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            namemax: 0,
        }
    }
}

pub struct ProcInode {
    id: u64,
    parent_ptr: Weak<Self>,
    fs: RwLock<Weak<ProcFileSystem>>,
    /// String looks like "pid/filename".
    children: RwLock<BTreeMap<String, Arc<dyn INode>>>,
}

impl ProcInode {
    pub fn new(parent: Option<Weak<Self>>) -> Arc<Self> {
        let id = INODE_COUNT.fetch_add(1, Ordering::SeqCst);
        let parent_ptr = parent.unwrap_or_default();

        Arc::new(Self {
            id,
            parent_ptr,
            fs: RwLock::new(Weak::default()),
            children: RwLock::new(BTreeMap::new()),
        })
    }
}

impl INode for ProcInode {
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

    fn fs(&self) -> Arc<dyn FileSystem> {
        self.fs.read().upgrade().unwrap()
    }

    fn sync_all(&self) -> Result<()> {
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn find(&self, name: &str) -> Result<Arc<dyn INode>> {
        Ok(match name {
            ".." => self.parent_ptr.upgrade().unwrap(),
            "." => unsafe { Arc::from_raw(self) },
            name => self
                .children
                .read()
                .get(name)
                .cloned()
                .ok_or(FsError::NoDevice)?,
        })
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: self.id as _,
            size: self.children.read().len(),
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
}
