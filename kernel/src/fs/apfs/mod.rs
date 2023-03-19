//! Implements the Apple File System (APFS).
//!
//! An Apple File System partition has a single container, which provides space management and crash protection. A container
//! can contain multiple volumes (also known as file systems), each of which contains a directory structure for files and
//! folders. Although thereʼs only one container, there are several copies of the container superblock (an instance of
//! nx_superblock_t) stored on disk. These copies hold the state of the container at past points in time.
//!
//! Many types are prefixed with nx_ or j_, which indicates that theyʼre part of the container layer or the file-system
//! layer, respectively.
//!
//! Most implementations are directly taken from Apple's Developer Manual for APFS.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{ffi::CStr, fmt::Debug};
use spin::RwLock;

use crate::{
    arch::QWORD_LEN,
    error::{Errno, KResult},
    fs::apfs::meta::{ApfsVolumn, BTreeInfo, Xid, BLOCK_SIZE},
    function, kerror, kinfo, kwarn,
    utils::calc_fletcher64,
};

use self::meta::{
    get_timespec, ApfsSuperblock, BTreeNodeFlags, BTreeNodePhysical, CheckpointMapPhysical,
    DrecFlags, FsMap, JDrecHashedKey, JDrecVal, JFileExtentKey, JFileExtentVal, JInodeKey,
    JInodeVal, JKey, NxSuperBlock, ObjectMap, ObjectMapKey, ObjectMapPhysical, ObjectPhysical,
    ObjectTypes, Oid, Omap, APFS_TYPE_DIR_REC, APFS_TYPE_FILE_EXTENT, APFS_TYPE_INODE,
    OBJ_TYPE_SHIFT, ROOT_DIR_RECORD_ID, S_IFCHR, S_IFLNK, S_IFREG,
};

use rcore_fs::{
    dirty::Dirty as MaybeDirty,
    vfs::{FileSystem, FsError, FsInfo, INode, Metadata, PollStatus},
};

pub mod meta;

#[cfg(feature = "apfs_write")]
pub mod btree;

/// Denotes the disk driver backend the filesystem uses.
pub trait Device: Send + Sync {
    /// Reads a buffer at a given offset of the disk and returns the size successfully read.
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;

    /// Reads a buffer at a given offset of the disk and returns the size successfully written.
    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize>;

    /// Synchronizes the memory and the disk content.
    fn sync(&self) -> KResult<()>;
}

/// Allows us to access the disk in a block-like way.
pub trait BlockLike: Device {
    /// Use this function unless you know what you are accessing.
    fn load_struct<T>(&self, id: Oid) -> KResult<T>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + Clone + Sized + 'static,
    {
        unsafe {
            let mut buf = vec![0u8; BLOCK_SIZE];
            // Read the block.
            self.read_block(id, 0, &mut buf)?;
            let object = &*(buf.as_ptr() as *const T);

            // Do the checksum.
            let header = &*(buf.as_ptr() as *const ObjectPhysical);
            let checksum = calc_fletcher64(&buf[QWORD_LEN..])?;
            match checksum.to_le_bytes() == header.o_cksum {
                true => Ok(object.clone()),
                false => {
                    kerror!(
                        "checksum mismatch. Expecting: {:x?}, got: {:x}",
                        header.o_cksum,
                        checksum
                    );
                    Err(Errno::EINVAL)
                }
            }
        }
    }

    fn read_block(&self, id: Oid, offset: usize, buf: &mut [u8]) -> KResult<()> {
        if offset + buf.len() > BLOCK_SIZE {
            kerror!("offset + buf.len() exceeds the block size (4KB).");
            return Err(Errno::EINVAL);
        }

        match self.read_buf_at(offset + id as usize * BLOCK_SIZE, buf) {
            Ok(len) => {
                if len == buf.len() {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
            Err(errno) => {
                kerror!("failed to read buffer. Errno: {:?}", errno);
                Err(errno)
            }
        }
    }

    fn write_block(&self, id: Oid, offset: usize, buf: &[u8]) -> KResult<()> {
        if offset + buf.len() > BLOCK_SIZE {
            kerror!("offset + buf.len() exceeds the block size (4KB).");
            return Err(Errno::EINVAL);
        }

        match self.write_buf_at(offset + id as usize * BLOCK_SIZE, buf) {
            Ok(len) => {
                if len == buf.len() {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
            Err(errno) => {
                kerror!("failed to write buffer. Errno: {:?}", errno);
                Err(errno)
            }
        }
    }
}

impl BlockLike for dyn Device {}

/// Represents the instance of the APFS.
///
/// The inode is a unique identifier that identifies a file system object — a file or a folder.
///
/// # Current goals (~3 months)
///
/// * Implement basic reading / BTree manipulations
/// * Add more unit test suites.
/// * Add support for concurrency.
///
/// All members should be guarded with a wrapper like [`Arc`] or [`RwLock`] to prevent self mutablility issues.
pub struct AppleFileSystem {
    /// A pointer to self.
    self_ptr: Weak<AppleFileSystem>,
    /// The container's superblock.
    superblock: RwLock<MaybeDirty<NxSuperBlock>>,
    /// The block driver (e.g., AHCI controller).
    device: Arc<dyn Device>,
    /// Read-only volumn list. Should be a list of root node?
    volumn_lists: RwLock<Vec<Arc<ApfsVolumn>>>,
    /// The root node of the object map.
    nx_omap_root: RwLock<Option<(BTreeNodePhysical, BTreeInfo)>>,
    /// The object map (in-memory).
    nx_omap: RwLock<Option<ObjectMap>>,
    /// The inode map. Volumn name to inode.
    inodes: RwLock<BTreeMap<String, BTreeMap<u64, Weak<AppleFileSystemInode>>>>,
}

impl AppleFileSystem {
    /// Cast `self` into atomic reference counter.
    fn as_arc(self) -> KResult<Arc<Self>> {
        let fs = Arc::new(self);
        let weak = Arc::downgrade(&fs);
        let ptr = Arc::into_raw(fs) as *mut Self;
        unsafe {
            (*ptr).self_ptr = weak;
            Ok(Arc::from_raw(ptr))
        }
    }

    /// Mounts the APFS container via a device driver (AHCI SATA) and returns a arc-ed instance. One may need to call
    /// `self.mount_volumns` to make other volumns present.
    pub fn mount_container(device: Arc<dyn Device>) -> KResult<Arc<Self>> {
        // Step 1: Read block zero of the partition. This block contains a copy of the container superblock
        // (an instance of `nx_superblock_t`). It might be a copy of the latest version or an old version,
        // depending on whether the drive was unmounted cleanly.
        let mut nx_superblock = device.load_struct::<NxSuperBlock>(0)?;

        // Verify the block.
        if !nx_superblock.verify() {
            kerror!("the superblock is corrupted.");
            return Err(Errno::EINVAL);
        }

        // Step 2: Use the block-zero copy of the container superblock to locate the checkpoint descriptor area
        // by reading the `nx_xp_desc_base` field.
        let nx_xp_desc_base = nx_superblock.nx_xp_desc_base;
        let highest_bit = nx_xp_desc_base & (1 << 63);
        if highest_bit != 0 {
            kerror!("currently we do not support non-contiguous checkpoint descriptor area");
            return Err(Errno::EACCES);
        }

        // Step 3: Read the entries in the checkpoint descriptor area, which are instances of `checkpoint_map_phys_t`.
        // or `nx_superblock_t`.
        let mut best_xid = 0;
        for idx in 0..nx_superblock.nx_xp_desc_blocks {
            // Should check whether this object is a checkpoint mapping or another superblock.
            // This can be done by reading the header of the target block.
            let addr = nx_xp_desc_base + idx as u64;
            let object = match read_object(&device, addr) {
                Ok(object) => object,
                // Not a valid block (maybe continuguous to the previous one).
                Err(_) => continue,
            };

            // Check the type.
            let hdr = unsafe { &*(object.as_ptr() as *const ObjectPhysical) };
            let object_type = ObjectTypes::from_bits_truncate((hdr.o_type & 0xff) as _);
            match object_type {
                // Find the container superblock that has the largest transaction identifier and isnʼt malformed.
                ObjectTypes::OBJECT_TYPE_NX_SUPERBLOCK => {
                    let cur_superblock = unsafe { &*(object.as_ptr() as *const NxSuperBlock) };
                    // The checkpoint description area is a ring buffer stored as an array. So performing a modulo is
                    // necessary at this timepoint.
                    let map_addr = cur_superblock.nx_xp_desc_base
                        + ((idx + cur_superblock.nx_xp_desc_blocks - 1)
                            % cur_superblock.nx_xp_desc_blocks) as u64;
                    let map_object = unsafe {
                        let map_object = read_object(&device, map_addr)?;
                        &*(map_object.as_ptr() as *const CheckpointMapPhysical)
                    };

                    // Find the latest superblock.
                    if map_object.cpm_o.o_xid > best_xid {
                        best_xid = map_object.cpm_o.o_xid;
                        nx_superblock = cur_superblock.clone();
                    }
                }
                _ => continue,
            }
        }

        kinfo!("mounted the superblock: {:x?}", nx_superblock);
        Self {
            self_ptr: Weak::default(),
            superblock: RwLock::new(MaybeDirty::new(nx_superblock)),
            device: device.clone(),
            volumn_lists: RwLock::new(Vec::new()),
            nx_omap_root: RwLock::new(None),
            nx_omap: RwLock::new(None),
            inodes: RwLock::new(BTreeMap::new()),
        }
        .as_arc()
    }

    /// Mounts all volumns
    pub fn mount_volumns_all(&self) -> KResult<()> {
        // Read from the nx_fs_oid.
        let nx_fs_oid = self.superblock.read().nx_fs_oid;

        // For each volume, look up the specified virtual object identifier in the container object map to locate the
        // volume superblock. Since oid must not be zero, we can skip zeros.
        let valid_fs_oids = nx_fs_oid
            .into_iter()
            .filter(|&oid| oid != 0)
            .collect::<Vec<_>>();

        for oid in valid_fs_oids {
            let key = ObjectMapKey {
                ok_oid: oid,
                // TODO: There is no transaction id currently.
                ok_xid: Xid::MIN,
            };

            kinfo!("mounting {:x?}", key);
            self.mount_volumn(&key)?;
        }

        Ok(())
    }

    /// Mounts other volumn.
    pub fn mount_volumn(&self, omap_key: &ObjectMapKey) -> KResult<()> {
        let omap = self.nx_omap.read();
        let omap_root = self.nx_omap_root.read();

        if omap.is_none() || omap_root.is_none() {
            kerror!("cannot mount other volumns if we have not mounted the container!");
            return Err(Errno::ENODEV);
        }

        let entry = match omap.as_ref().unwrap().get(omap_key) {
            Some(entry) => entry,
            None => {
                kerror!("the requested volumn does not exist.");
                return Err(Errno::ENOENT);
            }
        };
        if entry.ov_size as usize % BLOCK_SIZE != 0 {
            kerror!("not aligned to block size.");
            return Err(Errno::EINVAL);
        }

        let object = read_object(&self.device, entry.ov_paddr)?;
        // Parse it as apfs_superblock_t.
        let apfs_superblock = unsafe { &*(object.as_ptr() as *const ApfsSuperblock) }.clone();

        if !ObjectTypes::from_bits_truncate((apfs_superblock.apfs_o.o_type & 0xff) as _)
            .contains(ObjectTypes::OBJECT_TYPE_FS)
        {
            kerror!("this apfs header is corrupted.");
            return Err(Errno::EINVAL);
        }

        let volumn_name =
            String::from_utf8(apfs_superblock.apfs_volname.to_vec()).map_err(|_| Errno::EINVAL)?;
        kinfo!("successfully mounted volumn: {volumn_name}.");

        self.volumn_lists
            .write()
            .push(ApfsVolumn::from_raw(&self.device, apfs_superblock)?);

        Ok(())
    }

    /// Loads the object map of the nx_superblock into the filesystem.
    pub fn load_nx_object_map(&self) -> KResult<()> {
        let omap_phys_oid = self.superblock.read().nx_omap_oid;
        let omap = read_omap(&self.device, omap_phys_oid)?;

        self.nx_omap_root
            .write()
            .replace((omap.root_node.clone(), omap.btree_info.clone()));
        self.nx_omap.write().replace(omap.omap);

        Ok(())
    }

    /// Get the directory record from a directory record id. The APFS manages all the objects at the same level
    /// with a same id.
    pub fn get_drec(&self, drec_id: u64, dir_name: &str, volumn_name: &str) -> KResult<JDrecVal> {
        let obj_id_and_type = ((APFS_TYPE_DIR_REC as u64) << OBJ_TYPE_SHIFT) | drec_id;
        let mut name = [0u8; 255];
        // Null terminated.
        name[..dir_name.len()].copy_from_slice(dir_name.as_bytes());

        let drec_key = JDrecHashedKey {
            hdr: JKey { obj_id_and_type },
            name_len_and_hash: u32::default(),
            name,
        };

        // Search the map.
        match self.volumn_lists.read().iter().find(|&volumn| {
            let name = CStr::from_bytes_until_nul(&volumn.superblock.apfs_volname)
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            name == volumn_name
        }) {
            Some(volumn) => match volumn.fs_map.dir_record_map.get(&drec_key) {
                Some(e) => Ok(e.clone()),
                None => return Err(Errno::ENOENT),
            },
            None => return Err(Errno::ENOENT),
        }
    }

    /// Reads an Inode from the disk and converts to `Arc<AppleFileSystemInode>`.
    ///
    /// If there does not exist such Inodes indicated by `inode_id`, an error `ENOENT` will be reported.
    pub fn get_inode(
        &self,
        drec: JDrecVal,
        volumn_name: &str,
    ) -> KResult<Arc<AppleFileSystemInode>> {
        if let Some(inode) = self.inodes.read().get(&volumn_name.to_string()) {
            let id = drec.file_id;
            if let Some(inode) = inode.get(&id) {
                if let Some(inode) = inode.upgrade() {
                    return Ok(inode);
                }
            }
        }

        // Otherwise, we create a new one from the volumn list's map.
        match self.volumn_lists.read().iter().find(|&volumn| {
            let name = CStr::from_bytes_until_nul(&volumn.superblock.apfs_volname)
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            name == volumn_name
        }) {
            Some(volumn) => {
                let key = JInodeKey {
                    hdr: JKey {
                        obj_id_and_type: ((APFS_TYPE_INODE as u64) << OBJ_TYPE_SHIFT)
                            | drec.file_id,
                    },
                };

                let inode_val = match volumn.fs_map.inode_map.get(&key) {
                    Some(inode_val) => inode_val,
                    None => return Err(Errno::ENOENT),
                };

                let file_extent = volumn
                    .fs_map
                    .file_extent_map
                    .get(&JFileExtentKey {
                        hdr: JKey {
                            obj_id_and_type: ((APFS_TYPE_FILE_EXTENT as u64) << OBJ_TYPE_SHIFT)
                                | inode_val.private_id,
                        },
                        logical_addr: inode_val.private_id,
                    })
                    .map(|val| RwLock::new(MaybeDirty::new(val.clone())));

                Ok(Arc::new(AppleFileSystemInode {
                    id: drec.file_id,
                    volumn: volumn.clone(),
                    apfs: self.self_ptr.upgrade().unwrap(),
                    inode_inner: RwLock::new(MaybeDirty::new(inode_val.clone())),
                    file_extent,
                    dir_record: RwLock::new(MaybeDirty::new(drec)),
                }))
            }
            None => Err(Errno::ENODEV),
        }
    }

    pub fn get_root_inode(&self, volumn_name: &str) -> Arc<dyn INode> {
        // Before we locate the real root, we need to walk the JDirRecordMap to find 'root' inode because
        // APFS always creates two 'virtual' directories, namely, 'private-dir\0' and 'root\0'.
        let drec = self
            .get_drec(ROOT_DIR_RECORD_ID, "root", volumn_name)
            .expect("No root directory record. APFS is mounted incorrectly");
        self.get_inode(drec, volumn_name)
            .expect("No root inode found")
    }
}

impl FileSystem for AppleFileSystem {
    fn sync(&self) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn INode> {
        // FIXME: Better choice?
        self.get_root_inode("untitled")
    }

    fn info(&self) -> FsInfo {
        todo!()
    }
}

impl Drop for AppleFileSystem {
    fn drop(&mut self) {
        self.sync()
            .expect("Cannot synchronize the filesystem. Check if driver is dropped accidentally.");
    }
}

pub struct AppleFileSystemInode {
    /// The Inode Id.
    id: u64,
    /// The volumn to which this inode belongs.
    volumn: Arc<ApfsVolumn>,
    /// Reference to the filesystem wrapper by an atomic reference counter.
    ///
    /// This is needed because Inode depends on the existence of the filesystem so we must prevent the
    /// filesystem from dropping accidentally..
    apfs: Arc<AppleFileSystem>,
    /// The raw INode.
    inode_inner: RwLock<MaybeDirty<JInodeVal>>,
    /// The directory record of this inode.
    dir_record: RwLock<MaybeDirty<JDrecVal>>,
    /// The file extent value (if any).
    file_extent: Option<RwLock<MaybeDirty<JFileExtentVal>>>,
}

impl AppleFileSystemInode {
    /// Gets all the directory records under this directory.
    fn get_all(&self) -> KResult<Vec<(JDrecHashedKey, JDrecVal)>> {
        if !DrecFlags::from_bits_truncate(self.dir_record.read().flags).contains(DrecFlags::DT_DIR)
        {
            kerror!("trying to read entry from a non-directory file");
            return Err(Errno::EISDIR);
        }

        // Get the file id which points to all the directory records keys.
        // This is done by constructing a range of `JDrecHashedKey`s.
        let file_id = self.dir_record.read().file_id;
        let obj_id_and_type = ((APFS_TYPE_DIR_REC as u64) << OBJ_TYPE_SHIFT) | file_id;

        let all_keys_begin = JDrecHashedKey {
            hdr: JKey { obj_id_and_type },
            // Can be ignored because we invoke `*_until_nul`.
            name_len_and_hash: 0,
            name: [0u8; 255],
        };

        let all_keys_end = JDrecHashedKey {
            hdr: JKey { obj_id_and_type },
            // Can be ignored because we invoke `*_until_nul`.
            name_len_and_hash: 0,
            name: {
                let mut buf = [u8::MAX; 255];
                *buf.last_mut().unwrap() = 0;
                buf
            },
        };

        Ok(self
            .volumn
            .fs_map
            .dir_record_map
            .range(all_keys_begin..all_keys_end)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

impl Debug for AppleFileSystemInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppleFileSystemInode")
            .field("id", &self.id)
            .field("inode_inner", &self.inode_inner.read())
            .finish()
    }
}

impl INode for AppleFileSystemInode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        let inode_inner = self.inode_inner.read();
        match inode_inner.mode {
            S_IFREG | S_IFLNK => {
                // Read the file extent map first to locate the data stream of this file.
                let file_extent = self
                    .file_extent
                    .as_ref()
                    .ok_or(FsError::InvalidParam)?
                    .read();

                // Check if `offset` is valid.
                if offset >= file_extent.len() {
                    kerror!("`offset ` is larger than the file length!");
                    return Err(FsError::InvalidParam);
                }

                // Calculate the block number to be read.
                let buf_len = buf.len().min(file_extent.len());
                let block_len = buf_len / BLOCK_SIZE;
                let file_start = file_extent.phys_block_num + (offset / BLOCK_SIZE) as u64;

                for i in 0..block_len {
                    let blk = file_start as usize + i;
                    let start = i * BLOCK_SIZE;
                    let end = (start + BLOCK_SIZE).min(buf_len);
                    self.apfs
                        .device
                        .read_block(blk as _, 0, &mut buf[start..end])
                        .map_err(|_| FsError::InvalidParam)?;
                }

                Ok(buf.len())
            }

            S_IFCHR => {
                todo!()
            }

            _ => Err(FsError::NotFile),
        }
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        #[cfg(not(feature = "apfs_write"))]
        {
            kwarn!("Trying to write to a read-only filesystem. Your modification is lost.");
            // Wo do not panic here.
            Ok(0)
        }
        #[cfg(feature = "apfs_write")]
        compile_error!("write is currently unsupported.");
    }

    fn poll(&self) -> rcore_fs::vfs::Result<PollStatus> {
        todo!()
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn get_entry(&self, id: usize) -> rcore_fs::vfs::Result<String> {
        let values = self.get_all().map_err(|_| FsError::IsDir)?;
        let name = values
            .into_iter()
            .find(|(k, v)| v.file_id == id as u64)
            .ok_or(FsError::InvalidParam)?
            .0
            .name;

        let name = CStr::from_bytes_until_nul(&name)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string();

        Ok(name)
    }

    fn list(&self) -> rcore_fs::vfs::Result<Vec<String>> {
        Ok(self
            .get_all()
            .map_err(|_| FsError::IsDir)?
            .iter()
            .map(|(k, v)| {
                CStr::from_bytes_until_nul(&k.name)
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect())
    }

    fn metadata(&self) -> rcore_fs::vfs::Result<Metadata> {
        let inode_inner = self.inode_inner.read();
        let drec = self.dir_record.read();

        let ty = DrecFlags::from_bits_truncate(drec.flags);
        let (size, blocks) = match ty {
            DrecFlags::DT_REG | DrecFlags::DT_LNK => {
                let file_extent = self.file_extent.as_ref().unwrap().read();
                let size = file_extent.len() * BLOCK_SIZE;
                (size, file_extent.len())
            }
            // The size of a directory is the number of its directory entries.
            DrecFlags::DT_DIR => (inode_inner.nchildren as _, 1),
            // todo: add other types.
            _ => panic!("unknown file type"),
        };

        Ok(Metadata {
            dev: 0,
            inode: self.id as _,
            size,
            blk_size: BLOCK_SIZE,
            blocks,
            atime: get_timespec(inode_inner.access_time),
            mtime: get_timespec(inode_inner.mod_time),
            ctime: get_timespec(inode_inner.change_time),
            type_: ty.get_type(),
            // R/W/X
            mode: inode_inner.mode,
            // Meaningless for non-file objects (e.g., directories).
            nlinks: inode_inner.nlink as _,
            uid: inode_inner.owner as _,
            gid: inode_inner.group as _,
            // to be set.
            rdev: 0,
        })
    }
}

fn do_read_btree(device: &Arc<dyn Device>, oid: Oid) -> KResult<(BTreeInfo, BTreeNodePhysical)> {
    let buf = read_object(device, oid)?;
    let omap_phys = unsafe { &*(buf.as_ptr() as *const ObjectMapPhysical) };

    // Read the root node.
    let root_node_oid = omap_phys.om_tree_oid;
    let buf = read_object(device, root_node_oid)?;
    let root_node = unsafe { &*(buf.as_ptr() as *const BTreeNodePhysical) }.clone();

    // Check if root node is correct.
    let btree_node_flags = BTreeNodeFlags::from_bits_truncate(root_node.btn_flags);
    if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_ROOT) {
        kerror!("trying to parse a non-root node; abort.");
        return Err(Errno::EINVAL);
    } else if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_FIXED_KV_SIZE) {
        kerror!("non-fixed k-v pairs are not supported; abort.");
        return Err(Errno::EINVAL);
    }

    // If this is the root node, then the end of the block contains the B-Tree node information, and we
    // should parse this information so that we know how the tree is organized.
    let btree_info = root_node
        .btn_data
        .iter()
        .copied()
        .rev()
        .take(core::mem::size_of::<BTreeInfo>())
        .rev() // Note the endianess.
        .collect::<Vec<_>>();

    // Parse the information.
    let btree_info = unsafe { &*(btree_info.as_ptr() as *const BTreeInfo) }.clone();

    Ok((btree_info, root_node))
}

/// Reads the object map for a given container/volumn into the memory.
pub fn read_omap(device: &Arc<dyn Device>, oid: Oid) -> KResult<Omap> {
    let (btree_info, root_node) = do_read_btree(device, oid)?;
    kinfo!("loaded BTree information: {:x?}", btree_info);

    let omap = root_node.parse_as_object_map(device)?;

    Ok(Omap {
        omap,
        root_node,
        btree_info,
    })
}

/// Reads the filesystem map for a given container/volumn into the memory.
pub fn read_fs_tree(device: &Arc<dyn Device>, oid: Oid) -> KResult<FsMap> {
    let buf = read_object(device, oid)?;
    let fs_tree = unsafe { &*(buf.as_ptr() as *const BTreeNodePhysical) }.clone();
    fs_tree.parse_as_fs_tree(device)
}

/// Reads a file object from the disk at a given address.
pub fn read_object(device: &Arc<dyn Device>, addr: u64) -> KResult<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    device.read_block(addr, 0, &mut buf)?;

    let hdr = unsafe { &*(buf.as_ptr() as *const ObjectPhysical) };
    let cs = calc_fletcher64(&buf[QWORD_LEN..])?.to_le_bytes();

    if cs != hdr.o_cksum {
        Err(Errno::EINVAL)
    } else {
        Ok(buf)
    }
}
