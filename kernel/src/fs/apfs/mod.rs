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

use alloc::{sync::Arc, vec, vec::Vec};
use spin::RwLock;

use crate::{
    arch::QWORD_LEN,
    error::{Errno, KResult},
    fs::apfs::meta::BLOCK_SIZE,
    function, kerror, kinfo,
    utils::calc_fletcher64,
};

use self::meta::{CheckpointMapPhysical, NxSuperBlock, ObjectPhysical, ObjectTypes, Oid};

use super::vfs::{FileSytem, INode, MaybeDirty};

pub mod meta;

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
                false => Err(Errno::EINVAL),
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
/// The inode is a unique identifier that identifies a file system object — a file or a folder
pub struct AppleFileSystem {
    // TODO: What should be included here?
    superblock: MaybeDirty<RwLock<NxSuperBlock>>,
    device: Arc<dyn Device>,
}

impl AppleFileSystem {
    /// Mounts the filesystem via a device driver (AHCI SATA) and returns a arc-ed instance. We only need the superblock.
    pub fn mount(device: Arc<dyn Device>) -> KResult<Arc<Self>> {
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
            let object = read_object(&device, addr)?;

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

        kinfo!("mounted the superblock: {:#x?}", nx_superblock);
        Ok(Arc::new(Self {
            superblock: MaybeDirty::new(RwLock::new(nx_superblock)),
            device: device.clone(),
        }))
    }
}

pub struct AppleFileSystemInode {
    // TODO: What should be included here?
    fs: Arc<AppleFileSystem>,
}

impl FileSytem for AppleFileSystem {
    fn sync(&self) -> crate::error::KResult<()> {
        todo!()
    }

    fn root(&self) -> crate::error::KResult<alloc::sync::Arc<dyn super::vfs::INode>> {
        todo!()
    }

    fn metadata(&self) -> crate::error::KResult<super::vfs::FsMetadata> {
        todo!()
    }
}

impl INode for AppleFileSystemInode {
    fn poll(&self) -> crate::error::KResult<super::vfs::PollFlags> {
        todo!()
    }

    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> crate::error::KResult<usize> {
        todo!()
    }

    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> crate::error::KResult<usize> {
        todo!()
    }

    fn cast_to_any(&self) -> &dyn core::any::Any {
        todo!()
    }
}

/// Reads a file object from the disk at a given address.
fn read_object(device: &Arc<dyn Device>, addr: u64) -> KResult<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    device.read_block(addr, 0, &mut buf)?;

    let hdr = unsafe { &*(buf.as_ptr() as *const ObjectPhysical) };
    let cs = calc_fletcher64(&buf[QWORD_LEN..])?.to_le_bytes();

    if cs != hdr.o_cksum {
        kerror!("corrupted block.");
        Err(Errno::EINVAL)
    } else {
        Ok(buf)
    }
}
