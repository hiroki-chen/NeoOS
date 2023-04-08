//! Devfs is an alternative to "real" character and block special devices on your root filesystem. Kernel device
//! drivers can register devices by name rather than major and minor numbers. These devices will appear in devfs
//! automatically, with whatever default ownership and protection the driver specified.

use core::{any::Any, sync::atomic::Ordering};

use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::lazy_static;
use rcore_fs::vfs::{FileSystem, FileType, FsError, FsInfo, INode, Metadata, PollStatus, Timespec};
use spin::RwLock;

use crate::{
    fs::devfs::{null::NullINode, random::Random, serial::SerialINode, tty::TTY, zero::ZeroINode},
    function, kinfo,
};

use super::INODE_COUNT;

pub mod null;
pub mod random;
pub mod serial;
pub mod tty;
pub mod zero;

lazy_static! {
    pub static ref DEV_FS: Arc<DeviceFilesystem> = {
        let fs = DeviceFilesystem::new();
        let mut devices = Vec::<(String, Arc<dyn INode>)>::new();
        devices.push(("null".into(), Arc::new(NullINode::new())));
        devices.push(("zero".into(), Arc::new(ZeroINode::new())));
        devices.push(("random".into(), Arc::new(Random::new())));
        devices.push(("tty".into(), TTY.clone()));
        devices.extend(SerialINode::get_all_device_inodes().into_iter());

        fs.add_all_devices(devices);
        fs
    };
}

/// /dev is the location of special or device files. It is a very interesting directory that highlights one important
/// aspect of the Linux filesystem - everything is a file or a directory.
pub struct DeviceFilesystem {
    /// The mount point directory. Should be at `/dev`.
    mount_point: Arc<DeviceINode>,
}

impl DeviceFilesystem {
    pub fn new() -> Arc<Self> {
        let fs = Arc::new(Self {
            mount_point: DeviceINode::new(None),
        });
        *fs.mount_point.fs.write() = Arc::downgrade(&fs);
        fs
    }

    /// Mounts the whole filesystem under `mount_point`.
    pub fn add_all_devices(&self, devices: Vec<(String, Arc<dyn INode>)>) {
        let mut lock = self.mount_point.children.write();

        for (name, device) in devices.into_iter() {
            kinfo!("adding device {} into device filesystem", name);

            lock.insert(name, device);
        }
    }
}

impl FileSystem for DeviceFilesystem {
    fn sync(&self) -> rcore_fs::vfs::Result<()> {
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

/// The INode which is the child of `mount_point`.
pub struct DeviceINode {
    id: u64,
    parent_ptr: Weak<DeviceINode>,
    fs: RwLock<Weak<DeviceFilesystem>>,
    children: RwLock<BTreeMap<String, Arc<dyn INode>>>,
}

impl DeviceINode {
    /// Creates a new device inode with an opiton of a parent pointer.
    pub fn new(parent: Option<Weak<DeviceINode>>) -> Arc<Self> {
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

impl INode for DeviceINode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        Err(FsError::IsDir)
    }

    fn list(&self) -> rcore_fs::vfs::Result<Vec<(usize, String)>> {
        unimplemented!()
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        Err(FsError::IsDir)
    }

    fn poll(&self) -> rcore_fs::vfs::Result<PollStatus> {
        Err(FsError::IsDir)
    }

    fn metadata(&self) -> rcore_fs::vfs::Result<Metadata> {
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

    fn find(&self, name: &str) -> rcore_fs::vfs::Result<Arc<dyn INode>> {
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

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        self.fs.read().upgrade().unwrap()
    }

    fn sync_all(&self) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }

    fn sync_data(&self) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }
}
