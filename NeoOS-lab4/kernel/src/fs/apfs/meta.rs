//! Defines some important metadata.

use core::{any::Any, cmp::Ordering, ffi::CStr, fmt::Debug, panic, time::Duration};

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use bitflags::bitflags;
use crc::{Crc, CRC_32_ISCSI};
use rcore_fs::{
    dirty::Dirty as MaybeDirty,
    vfs::{FileType, Timespec},
};
use serde::{Deserialize, Serialize};
use spin::RwLock;
use unicode_normalization::char::decompose_canonical;

use crate::{
    arch::{DWORD_LEN, QWORD_LEN},
    error::{Errno, KResult},
    function, kdebug, kerror, kinfo,
};

use super::{read_fs_tree, read_object, read_omap, AppleFileSystem, Device};

// Some type alias.

/// In fact, 16-byte long u8 array.
pub type Uuid = [u8; 16];
/// An object identifier.
///
/// Objects are identified by this number as follows:
/// * For a physical object, its identifier is the logical block address on disk where the object is stored.
/// * For an ephemeral object, its identifier is a number.
/// * For a virtual object, its identifier is a number.
pub type Oid = u64;
/// A transaction identifier.
///
/// Transactions are uniquely identified by a monotonically increasing number.
///
/// This data type is sufficiently large that you arenʼt expected to ever run out of transaction identifiers. For example,
/// if you created 1,000,000 transactions per second, it would take more than 5,000 centuries to exhaust the available
/// transaction identifiers.
pub type Xid = u64;
/// The object map type; we store it as a BTreeMap.
///
/// We may need to serialize this thing. virtual -> physical;
pub type ObjectMap = BTreeMap<ObjectMapKey, ObjectMapValue>;
/// The filesystem trees.
pub type InodeMap = BTreeMap<JInodeKey, JInodeVal>;
pub type DirRecordMap = BTreeMap<JDrecHashedKey, JDrecVal>;
pub type PhysExtMap = BTreeMap<JPhysExtKey, JPhysExtVal>;
pub type FileExtentMap = BTreeMap<JFileExtentKey, JFileExtentVal>;
pub type DirStatMap = BTreeMap<JDirStatKey, JDirStatVal>;

// Some important constants.

pub const BLOCK_SIZE: usize = 0x1000;
pub const NX_MAGIC: &[u8; 4] = b"NXSB";
pub const APFS_MAGIC: &[u8; 4] = b"APSB";
pub const OBJECT_HDR_SIZE: usize = core::mem::size_of::<ObjectPhysical>();
pub const MAX_ALLOWED_CHECKPOINT_MAP_SIZE: usize = 100;
pub const ROOT_DIR_RECORD_ID: u64 = 0x1;

// B-Tree constants.
pub const BTREE_STORAGE_SIZE: usize =
    BLOCK_SIZE - OBJECT_HDR_SIZE - 4 * core::mem::size_of::<Nloc>() - QWORD_LEN;

pub const OBJ_ID_MASK: u64 = 0x0fffffffffffffff;
pub const OBJ_TYPE_MASK: u64 = 0xf000000000000000;
pub const OBJ_TYPE_SHIFT: u64 = 60;
pub const SYSTEM_OBJ_ID_MARK: u64 = 0x0fffffff00000000;

pub const J_DREC_LEN_MASK: u32 = 0x000003ff;
pub const J_DREC_HASH_MASK: u32 = 0xfffff400;
pub const J_DREC_HASH_SHIFT: u32 = 10;

pub const PEXT_LEN_MASK: u64 = 0x0fffffffffffffff;
pub const PEXT_KIND_MASK: u64 = 0xf000000000000000;
pub const PEXT_KIND_SHIFT: u64 = 60;

pub const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ffffffffffffff;
pub const J_FILE_EXTENT_FLAG_MASK: u64 = 0xff00000000000000;
pub const J_FILE_EXTENT_FLAG_SHIFT: u64 = 56;

pub const DREC_TYPE_MASK: u16 = 0xf;

// Key types.

pub const APFS_TYPE_ANY: u8 = 0;
pub const APFS_TYPE_SNAP_METADATA: u8 = 1;
pub const APFS_TYPE_EXTENT: u8 = 2;
pub const APFS_TYPE_INODE: u8 = 3;
pub const APFS_TYPE_XATTR: u8 = 4;
pub const APFS_TYPE_SIBLING_LINK: u8 = 5;
pub const APFS_TYPE_DSTREAM_ID: u8 = 6;
pub const APFS_TYPE_CRYPTO_STATE: u8 = 7;
pub const APFS_TYPE_FILE_EXTENT: u8 = 8;
pub const APFS_TYPE_DIR_REC: u8 = 9;
pub const APFS_TYPE_DIR_STATS: u8 = 10;
pub const APFS_TYPE_SNAP_NAME: u8 = 11;
pub const APFS_TYPE_SIBLING_MAP: u8 = 12;
pub const APFS_TYPE_FILE_INFO: u8 = 13;
pub const APFS_TYPE_MAX_VALID: u8 = 13;
pub const APFS_TYPE_MAX: u8 = 15;
pub const APFS_TYPE_INVALID: u8 = 15;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFIFO: u16 = 0o010000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFWHT: u16 = 0o160000;

// Xfields constants.
pub const DEFAULT_XF_LEN: usize = 1024;
pub const INO_EXT_TYPE_NAME: u8 = 4;
pub const INO_EXT_TYPE_DSTREAM: u8 = 8;

pub const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub trait XFieldsInterepretable: Clone + Debug {
    /// Gets the raw byte array of the xfields.
    fn get_xfields(&self) -> &[u8];

    /// Interpret the xfields.
    fn interpret_xfields(&self, ty: u8) -> KResult<Vec<Vec<u8>>> {
        let xf_blob = unsafe { &*(self.get_xfields().as_ptr() as *const XfBlob) };
        let xf_num_exts = xf_blob.xf_num_exts as usize;
        let xf_used_data = xf_blob.xf_used_data as usize;
        // Locate the data.
        let mut xf_data_offset = xf_num_exts * core::mem::size_of::<Xfields>();

        // Iterate over xfields.
        let mut xfields = Vec::new();
        for idx in 0..xf_num_exts {
            let xf = unsafe { &*(xf_blob.xf_data.as_ptr().add(idx * DWORD_LEN) as *const Xfields) };
            let mut xf_size = xf.x_size as usize;

            // Check the type
            let xf_type = xf.x_type;
            if xf_type == ty {
                xfields.push(xf_blob.xf_data[xf_data_offset..xf_data_offset + xf_size].to_vec());
            }

            // Since xfields data are aligned to 8-byte, we need to round up the offset
            // if not properly aligned.
            if xf_size % QWORD_LEN != 0 {
                xf_size += QWORD_LEN - xf_size % QWORD_LEN;
            }
            xf_data_offset += xf_size;
        }

        Ok(xfields)
    }
}

/// Defines how a b-tree key should behave.
pub trait BTreeKey: Clone + Eq + Ord + PartialEq + PartialOrd + Sized {
    /// Imports a raw byte array into `self`.
    fn import(buf: &[u8]) -> Self {
        unsafe { &*(buf.as_ptr() as *const Self) }.clone()
    }

    fn as_any(&self) -> &dyn Any;

    fn ty(&self) -> KeyType;

    /// Checks the type.
    fn check(&self) -> bool {
        true
    }
}

pub trait BTreeValue: Clone + Sized {
    fn import(buf: &[u8]) -> Self {
        // todo: check header? => dispatch to each implementation.
        unsafe { &*(buf.as_ptr() as *const Self) }.clone()
    }
}

bitflags! {
    /// Values used as types and subtypes by the obj_phys_t structure.
    #[derive(Default)]
    pub struct ObjectTypes: u16 {
        const OBJECT_TYPE_NX_SUPERBLOCK = 0x00000001;
        const OBJECT_TYPE_BTREE = 0x00000002;
        const OBJECT_TYPE_BTREE_NODE = 0x00000003;
        const OBJECT_TYPE_SPACEMAN = 0x00000005;
        const OBJECT_TYPE_SPACEMAN_CAB = 0x00000006;
        const OBJECT_TYPE_SPACEMAN_CIB = 0x00000007;
        const OBJECT_TYPE_SPACEMAN_BITMAP = 0x00000008;
        const OBJECT_TYPE_SPACEMAN_FREE_QUEUE = 0x00000009;
        const OBJECT_TYPE_EXTENT_LIST_TREE = 0x0000000a;
        const OBJECT_TYPE_OMAP = 0x0000000b;
        const OBJECT_TYPE_CHECKPOINT_MAP = 0x0000000c;
        const OBJECT_TYPE_FS = 0x0000000d;
        const OBJECT_TYPE_FSTREE = 0x0000000e;
        const OBJECT_TYPE_BLOCKREFTREE = 0x0000000f;
        const OBJECT_TYPE_SNAPMETATREE = 0x00000010;
        const OBJECT_TYPE_NX_REAPER = 0x00000011;
        const OBJECT_TYPE_NX_REAP_LIST = 0x00000012;
        const OBJECT_TYPE_OMAP_SNAPSHOT = 0x00000013;
        const OBJECT_TYPE_EFI_JUMPSTART = 0x00000014;
        const OBJECT_TYPE_FUSION_MIDDLE_TREE = 0x00000015;
        const OBJECT_TYPE_NX_FUSION_WBC = 0x00000016;
        const OBJECT_TYPE_NX_FUSION_WBC_LIST = 0x00000017;
        const OBJECT_TYPE_ER_STATE = 0x00000018;
        const OBJECT_TYPE_GBITMAP = 0x00000019;
        const OBJECT_TYPE_GBITMAP_TREE = 0x0000001a;
        const OBJECT_TYPE_GBITMAP_BLOCK = 0x0000001b;
        const OBJECT_TYPE_ER_RECOVERY_BLOCK = 0x0000001c;
        const OBJECT_TYPE_SNAP_META_EXT = 0x0000001d;
        const OBJECT_TYPE_INTEGRITY_META = 0x0000001e;
        const OBJECT_TYPE_FEXT_TREE = 0x0000001f;
        const OBJECT_TYPE_RESERVED_20 = 0x00000020;
        const OBJECT_TYPE_INVALID = 0x00000000;
        const OBJECT_TYPE_TEST = 0x000000ff;
    }
}

bitflags! {
    /// The flags used in the object type to provide additional information.
    #[derive(Default)]
    pub struct ObjectTypeFlags: u32 {
        const OBJ_VIRTUAL = 0x00000000;
        const OBJ_EPHEMERAL = 0x80000000;
        const OBJ_PHYSICAL = 0x40000000;
        const OBJ_NOHEADER = 0x20000000;
        const OBJ_ENCRYPTED = 0x10000000;
        const OBJ_NONPERSISTENT = 0x08000000;
    }
}

bitflags! {
    /// The flags used by object maps.
    #[derive(Default)]
    pub struct ObjectMapFlags: u32 {
        const OMAP_MANUALLY_MANAGED = 0x00000001;
        const OMAP_ENCRYPTING = 0x00000002;
        const OMAP_DECRYPTING = 0x00000004;
        const OMAP_KEYROLLING = 0x00000008;
        const OMAP_CRYPTO_GENERATION = 0x00000010;
        const OMAP_VALID_FLAGS = 0x0000001f;
    }
}

bitflags! {
    /// The flags used by entries in the object map.
    #[derive(Default)]
    pub struct ObjectMapValueFlags: u32 {
        const OMAP_VAL_DELETED = 0x00000001;
        const OMAP_VAL_SAVED = 0x00000002;
        const OMAP_VAL_ENCRYPTED = 0x00000004;
        const OMAP_VAL_NOHEADER = 0x00000008;
        const OMAP_VAL_CRYPTO_GENERATION = 0x00000010;
    }
}

bitflags! {
    /// The flags used by entries in the object map.
    #[derive(Default)]
    pub struct ObjectMapSnapshotFlags: u32 {
        const OMAP_SNAPSHOT_DELETED = 0x1;
        const OMAP_SNAPSHOT_REVERTED = 0x2;
    }
}

bitflags! {
  /// The flags used by a checkpoint-mapping block.
  #[derive(Default)]
  pub struct CheckpointFlags: u32 {
      const CHECKPOINT_MAP_LAST = 0x1;
  }
}

bitflags! {
    /// The flags used in btree node.
    pub struct BTreeNodeFlags: u16 {
        const BTNODE_ROOT = 0x0001;
        const BTNODE_LEAF = 0x0002;
        const BTNODE_FIXED_KV_SIZE = 0x0004;
        const BTNODE_HASHED = 0x0008;
        const BTNODE_NOHEADER = 0x0010;
        const BTNODE_CHECK_KOFF_INVAL = 0x8000;
    }
}

bitflags! {
    /// The flags used in btree.
    pub struct BTreeFlags: u32 {
        const BTREE_UINT64_KEYS = 0x00000001;
        const BTREE_SEQUENTIAL_INSERT = 0x00000002;
        const BTREE_ALLOW_GHOSTS = 0x00000004;
        const BTREE_EPHEMERAL = 0x00000008;
        const BTREE_PHYSICAL = 0x00000010;
        const BTREE_NONPERSISTENT = 0x00000020;
        const BTREE_KV_NONALIGNED = 0x00000040;
        const BTREE_HASHED = 0x00000080;
        const BTREE_NOHEADER = 0x0000010;
    }
}

bitflags! {
  /// Values used by the flags field of j_drec_val_t to indicate a directory entryʼs type.
  ///
  /// These values are the same as the values defined in File Modes, except for a bit shift.
  pub struct DrecFlags: u16 {
      const DT_UNKNOWN = 0;
      const DT_FIFO = 1;
      const DT_CHR = 2;
      const DT_DIR = 4;
      const DT_BLK = 6;
      const DT_REG = 8;
      const DT_LNK = 10;
      const DT_SOCK = 12;
      const DT_WHT = 14;
  }
}

impl Into<FileType> for DrecFlags {
    fn into(self) -> FileType {
        match self {
            DrecFlags::DT_BLK => FileType::BlockDevice,
            DrecFlags::DT_CHR => FileType::CharDevice,
            DrecFlags::DT_DIR => FileType::Dir,
            DrecFlags::DT_FIFO => FileType::NamedPipe,
            DrecFlags::DT_SOCK => FileType::Socket,
            DrecFlags::DT_LNK => FileType::SymLink,
            DrecFlags::DT_REG => FileType::File,
            ty => panic!("unknown type: {:?}", ty),
        }
    }
}

impl From<FileType> for DrecFlags {
    fn from(value: FileType) -> Self {
        match value {
            FileType::BlockDevice => DrecFlags::DT_BLK,
            FileType::CharDevice => DrecFlags::DT_CHR,
            FileType::Dir => DrecFlags::DT_DIR,
            FileType::NamedPipe => DrecFlags::DT_FIFO,
            FileType::Socket => DrecFlags::DT_SOCK,
            FileType::SymLink => DrecFlags::DT_LNK,
            FileType::File => DrecFlags::DT_REG,
        }
    }
}

/// A range of physical addresses.
#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct Prange {
    pr_start_paddr: u64,
    pr_block_count: u64,
}

#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct ObjectPhysical {
    /// The Fletcher 64 checksum of the object.
    pub o_cksum: [u8; 8],
    /// The object id.
    /// See documentation:
    ///
    /// ```c
    /// typedef pub xid_t: u64,
    /// typedef pub pub: u64: Oid,
    /// ```
    pub o_oid: Oid,
    pub o_xid: Xid,
    /// An object type is a 32-bit value: The low 16 bits indicate the type using the values listed in Object Types,
    /// and the high 16 bits are flags using the values listed in Object Type Flags.
    pub o_type: u32,
    /// The objectʼs subtype.
    /// Subtypes indicate the type of data stored in a data structure such as a B-tree (in Rust, we utilize
    /// [`alloc::collections::BTreeMap`]).
    pub o_subtype: u32,
}

/// Represents an `nx_superblock_t` type that servers as the superblock for the APFS container.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct NxSuperBlock {
    /// The objectʼs header.
    pub nx_o: ObjectPhysical,
    /// The magic number.
    pub nx_magic: [u8; 4],
    /// The block size.
    pub nx_block_size: u32,
    /// The block count.
    pub nx_block_count: u64,
    /// Some features.
    pub nx_features: u64,
    pub nx_readonly_compatible_features: u64,
    pub nx_incompatible_features: u64,
    /// The APFS UUID.
    pub uuid: Uuid,

    pub nx_next_oid: Oid,
    pub nx_next_xid: Xid,
    pub nx_xp_desc_blocks: u32,
    pub nx_xp_data_blocks: u32,
    /// If the highest bit of nx_xp_desc_blocks is zero, the checkpoint descriptor area is contiguous and this field contains
    /// the address of the first block. Otherwise, the checkpoint descriptor area isnʼt contiguous and this field contains
    /// the  physical object identifier of a B-tree. The treeʼs keys are block offsets into the checkpoint descriptor area,
    /// and its values are instances of prange_t that contain the fragmentʼs size and location.
    pub nx_xp_desc_base: u64,
    pub nx_xp_data_base: u64,
    pub nx_xp_desc_next: u32,
    pub nx_xp_data_next: u32,
    pub nx_xp_desc_index: u32,
    pub nx_xp_desc_len: u32,
    pub nx_xp_data_index: u32,
    pub nx_xp_data_len: u32,

    pub nx_spaceman_oid: Oid,
    pub nx_omap_oid: Oid,
    pub nx_reaper_oid: Oid,

    pub nx_test_type: u32,

    pub nx_max_file_systems: u32,
    pub nx_fs_oid: [Oid; 100],
    pub nx_counters: [u64; 32],
    pub nx_blocked_out_prange: Prange,
    pub nx_evict_mapping_tree_oid: u64,
    pub nx_flags: u64,
    pub nx_efi_jumpstart: u64,
    pub nx_fusion_uuid: Uuid,
    pub nx_keylocker: Prange,
    pub nx_ephemeral_info: [u64; 4],

    pub nx_test_oid: Oid,
    pub nx_fusion_mt_oid: Oid,
    pub nx_fusion_wbc_oid: Oid,
    pub nx_fusion_wbc: Prange,

    pub nx_newest_mounted_version: u64,

    pub nx_mkb_locker: Prange,
}

impl AsRef<[u8]> for NxSuperBlock {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

impl AsMut<[u8]> for NxSuperBlock {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

impl NxSuperBlock {
    /// Verifies if the block is not corrupted.
    pub fn verify(&self) -> bool {
        // Check the magic number.
        &self.nx_magic == NX_MAGIC
    }
}

/// A key used to access an entry in the object map.
///
/// As per the doc by Apple, we search the B-tree for a key whose object identifier is the same as the desired object
/// identifier, and whose transaction identifier is less than or equal to the desired transaction identifier. If there are
/// multiple keys that satisfy this test, use the key with the **largest** transaction identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct ObjectMapKey {
    pub ok_oid: Oid,
    pub ok_xid: Xid,
}

impl PartialEq for ObjectMapKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ObjectMapKey {}

impl PartialOrd for ObjectMapKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectMapKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Determine the relationship between their object ids.
        match self.ok_oid.cmp(&other.ok_oid) {
            Ordering::Equal => match self.ok_xid.cmp(&other.ok_xid) {
                // Ensures that we always read the latest record.
                // The BTreemap's comparison is other.cmp(self); so we must reverse the order here.
                Ordering::Less | Ordering::Equal => Ordering::Equal,
                Ordering::Greater => Ordering::Greater,
            },
            res => res,
        }
    }
}

/// A value in the object map.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct ObjectMapValue {
    pub ov_flags: u32,
    pub ov_size: u32,
    pub ov_paddr: u64,
}

/// Information about a snapshot of an object map. When accessing or storing a snapshot in the snapshot tree, use the
/// transaction identifier as the key. This structure is the value stored in a snapshot tree.
#[derive(Clone, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct ObjectMapSnapshot {
    pub oms_flags: u32,
    pub oms_pad: u32,
    pub oms_oid: Oid,
}

/// An object map.
///
/// An object map uses a B-tree to store a mapping from virtual object identifiers and transaction identifiers to the
/// physical addresses where those objects are stored. The keys in the B-tree are instances of omap_key_t and the values are
/// instances of paddr_t.
#[derive(Clone)]
#[repr(C, align(8))]
pub struct ObjectMapPhysical {
    /// The header.
    pub om_o: ObjectPhysical,
    pub om_flags: u32,
    pub om_snap_count: u32,
    pub om_tree_type: u32,
    pub om_snapshot_tree_type: u32,
    pub om_tree_oid: Oid,
    pub om_snapshot_tree_oid: Oid,
    pub om_most_recent_snap: u64,
    pub om_pending_revert_min: u64,
    pub om_pending_revert_max: u64,
}

/// A header used at the beginning of all file-system keys.
///
/// All file-system objects have a key that begins with this information. The key for some object types have additional
/// fields that follow this header, and other object types use [`JKey`] as their entire key.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct JKey {
    /// The objectʼs identifier is a pub value accessed as obj_id_and_type & OBJ_ID_MASK. The objectʼs type is a uint8_: u64,
    /// value accessed as (obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT. The objectʼs type is one of the constants
    /// defined by j_obj_types.
    pub obj_id_and_type: u64,
}

impl JKey {
    #[inline]
    pub fn get_type(&self) -> u8 {
        ((self.obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) as _
    }

    #[inline]
    pub fn get_oid(&self) -> u64 {
        self.obj_id_and_type & OBJ_ID_MASK
    }
}

/// The key half of a directory-information record.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct JInodeKey {
    /// The object identifier in the header is the file-system objectʼs identifier, also known as its inode number. The
    /// type in the header is always `APFS_TYPE_INODE`.
    pub hdr: JKey,
}

impl JInodeKey {
    pub fn new(id: u64) -> Self {
        Self {
            hdr: JKey {
                obj_id_and_type: (APFS_TYPE_INODE as u64) << OBJ_TYPE_SHIFT | id,
            },
        }
    }
}

/// The key half of a directory entry record.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct JDrecKey {
    pub hdr: JKey,
    pub name_len: u16,
    /// The length is undetermined.
    pub name: [u8; 4000],
}

/// The key half of a directory entry record hashed.
///
/// Not sure if we really need this thing, but we keep it here for future usage (perhaps)?
#[derive(Clone)]
#[repr(C, packed)]
pub struct JDrecHashedKey {
    pub hdr: JKey,
    pub name_len_and_hash: u32,
    /// The length is undetermined.
    pub name: [u8; 255],
}

impl JDrecHashedKey {
    pub fn new(id: u64, name: &str) -> Self {
        Self {
            hdr: JKey {
                obj_id_and_type: ((APFS_TYPE_DIR_REC as u64) << OBJ_TYPE_SHIFT) | id,
            },
            name_len_and_hash: (name.len() + 1) as _,
            name: {
                let mut buf = [0u8; 255];
                buf[..name.len().min(255)].copy_from_slice(name.as_bytes());
                buf
            },
        }
    }
}

/// The key half of a physical extent record.
///
/// Short pieces of information like a fileʼs name are stored inside the data structures that contain metadata. Data
/// thatʼs too large to store inline is stored separately, in a data stream. This includes the contents of files, and
/// the value of some attributes.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JPhysExtKey {
    /// The object identifier in the header is the physical block address of the start of the extent.
    pub hdr: JKey,
}

/// The value half of a physical extent record.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JPhysExtVal {
    pub len_and_kind: u64,
    pub owning_obj_id: u64,
    pub refcnt: i32,
}

/// The key half of a file extent record.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JFileExtentKey {
    pub hdr: JKey,
    pub logical_addr: u64,
}

/// The value half of a file extent record.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JFileExtentVal {
    /// The extentʼs length is a `pub` value, accessed as `len_and_kind & PEXT_LEN_MASK`, and measured in blocks: u64,
    /// The extentʼs kind is a `j_obj_kinds` value, accessed as `(len_and_kind & PEXT_KIND_MASK) >> PEXT_KIND_SHIFT`.
    pub len_and_flags: u64,
    pub phys_block_num: u64,
    pub crypto_id: u64,
}

impl JFileExtentVal {
    /// Gets the length of bytes of this data stream.
    #[inline]
    pub fn len(&self) -> usize {
        (self.len_and_flags & J_FILE_EXTENT_LEN_MASK) as _
    }

    /// Checks if empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets the block number of this data stream.
    #[inline]
    pub fn block_len(&self) -> usize {
        // Should be multiple of `BLOCK_SIZE`.
        (self.len_and_flags & J_FILE_EXTENT_LEN_MASK) as usize / BLOCK_SIZE
    }
}

/// The key half of a directory-information record.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JDirStatKey {
    pub hdr: JKey,
}

/// The value half of a directory-information record.
#[derive(Clone, Debug)]
#[repr(C, packed)]
pub struct JDirStatVal {
    pub num_children: u64,
    pub total_size: u64,
    pub chained_key: u64,
    pub gen_count: u64,
}

/// Key types.
#[derive(Debug)]
pub enum KeyType {
    OmapKey,
    JInodeKey,
    JDrecKey,
    JDrecHashedKey,
    JPhysExtKey,
    JFileExtentKey,
    JDirStatKey,
}

/// Value types.
#[derive(Debug)]
pub enum ValueType {
    OmapVal,
    JInodeVal,
    JDrecVal,
    JPhysExtVal,
    JFileExtentVal,
    JDirStatVal,
}

/// A wrapped struct for the filesystem maps.
#[derive(Debug, Default)]
pub struct FsMap {
    pub inode_map: InodeMap,
    pub dir_record_map: DirRecordMap,
    pub phys_ext_map: PhysExtMap,
    pub file_extent_map: FileExtentMap,
    pub dir_stat_map: DirStatMap,
}

impl core::fmt::Debug for JDrecHashedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name_len_and_hash = self.name_len_and_hash;
        f.debug_struct("JDrecHashedKey")
            .field("hdr", &self.hdr)
            .field("name_len_and_hash", &name_len_and_hash)
            .field(
                "name",
                &alloc::string::String::from_utf8(
                    self.name[..(self.name_len_and_hash & J_DREC_LEN_MASK) as usize].to_vec(),
                )
                .unwrap(),
            )
            .finish()
    }
}

/// The value half of a directory entry record.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct JDrecVal {
    pub file_id: u64,
    pub date_added: u64,
    pub flags: u16,
    /// Directory entries (j_drec_val_t) and inodes (j_inode_val_t) use this data type to store their extended fields.
    pub xfields: [u8; DEFAULT_XF_LEN],
}

impl JDrecVal {
    pub fn new(id: u64, date_added: u64, flags: u16) -> Self {
        Self {
            file_id: id,
            date_added,
            flags,
            xfields: [0u8; DEFAULT_XF_LEN],
        }
    }
}

/// A data stream for extended attributes. To access the data in the stream, read the object identifier and
/// then find the corresponding extents.
#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct JXttrDstream {
    pub xattr_obj_id: u64,
    pub dstream: JDstream,
}

/// Information about a data stream.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct JDstream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
}

impl PartialEq for JKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JKey {}

impl PartialOrd for JKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // For sorting file-system records — for example, to keep them ordered in a B-tree — the following comparison
        // rules are used:
        // 1. Compare the object identifiers numerically
        let obj_lhs = self.obj_id_and_type & OBJ_ID_MASK;
        let obj_rhs = other.obj_id_and_type & OBJ_ID_MASK;

        let id_ordering = obj_lhs.cmp(&obj_rhs);

        if id_ordering != Ordering::Equal {
            return id_ordering;
        }

        // 2. Compare the object types numerically.
        let type_lhs = (self.obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
        let type_rhs = (other.obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;

        type_lhs.cmp(&type_rhs)
        // 3. For extended attribute records and directory entry records, compare the names lexicographically.
        // This can be skipped for directory inodes.
    }
}

impl PartialEq for JInodeKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JInodeKey {}

impl Ord for JInodeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hdr.cmp(&other.hdr)
    }
}

impl PartialOrd for JInodeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for JDrecKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JDrecKey {}

impl PartialOrd for JDrecKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JDrecKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hdr.cmp(&other.hdr) {
            Ordering::Equal => {
                let self_name = CStr::from_bytes_until_nul(&self.name).unwrap_or_default();
                let other_name = CStr::from_bytes_until_nul(&other.name).unwrap_or_default();
                self_name.cmp(other_name)
            }
            res => res,
        }
    }
}

impl PartialEq for JDrecHashedKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JDrecHashedKey {}

impl PartialOrd for JDrecHashedKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JDrecHashedKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hdr.cmp(&other.hdr) {
            Ordering::Equal => {
                let self_name = CStr::from_bytes_until_nul(&self.name).unwrap_or_default();
                let other_name = CStr::from_bytes_until_nul(&other.name).unwrap_or_default();
                self_name.cmp(other_name)
            }
            res => res,
        }
    }
}

impl PartialEq for JPhysExtKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JPhysExtKey {}

impl PartialOrd for JPhysExtKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JPhysExtKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hdr.cmp(&other.hdr)
    }
}

impl PartialEq for JFileExtentKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JFileExtentKey {}

impl PartialOrd for JFileExtentKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JFileExtentKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hdr.cmp(&other.hdr)
    }
}

impl Ord for JDirStatKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hdr.cmp(&other.hdr)
    }
}

impl PartialEq for JDirStatKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JDirStatKey {}

impl PartialOrd for JDirStatKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BTreeKey for ObjectMapKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::OmapKey
    }
}

impl BTreeKey for JDrecKey {
    fn check(&self) -> bool {
        self.hdr.get_type() == APFS_TYPE_DIR_REC
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JDrecKey
    }
}

impl BTreeKey for JInodeKey {
    fn check(&self) -> bool {
        self.hdr.get_type() == APFS_TYPE_INODE
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JInodeKey
    }
}

impl BTreeKey for JDrecHashedKey {
    fn check(&self) -> bool {
        if self.hdr.get_type() != APFS_TYPE_DIR_REC {
            return false;
        }

        // We need to check the hash value.
        // The hash is an unsigned 22-bit integer, accessed as
        //    (name_len_and_hash & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT.
        let hash = (self.name_len_and_hash & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT;
        // 1. Start with the filename, represented as a null-terminated UTF-8 string.
        let name_len = self.name_len_and_hash & J_DREC_LEN_MASK;
        // 2. Normalize it with a canonical decomposition.
        let mut nfd_name = String::new();
        let name = match String::from_utf8(self.name[..name_len as usize].to_vec()) {
            Ok(name) => name,
            Err(_) => return false,
        };

        // 3. Represent it in a UTF-32 string.
        name.chars().for_each(|c| {
            decompose_canonical(c, |c| {
                nfd_name.push(c);
            })
        });

        // 4. Compute the CRC-32C hash of the UTF-32 string.
        let nfd_name = nfd_name
            .chars()
            .flat_map(|c| (c as u32).to_be_bytes())
            .collect::<Vec<_>>();
        let hash_res = !CASTAGNOLI.checksum(nfd_name.as_slice()) & 0x7fffff;

        // FIXME: The checksum is always incorrect?...
        kinfo!("hash_res = {hash_res}, hash = {hash}");
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JDrecHashedKey
    }
}

impl BTreeKey for JPhysExtKey {
    fn check(&self) -> bool {
        self.hdr.get_type() == APFS_TYPE_EXTENT
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JPhysExtKey
    }
}

impl BTreeKey for JFileExtentKey {
    fn check(&self) -> bool {
        self.hdr.get_type() == APFS_TYPE_FILE_EXTENT
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JFileExtentKey
    }
}

impl BTreeKey for JDirStatKey {
    fn check(&self) -> bool {
        self.hdr.get_type() == APFS_TYPE_DIR_STATS
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        KeyType::JDirStatKey
    }
}

impl BTreeKey for u64 {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ty(&self) -> KeyType {
        panic!("u64 is not a valid fs key.")
    }
}

impl BTreeValue for ObjectMapValue {}
impl BTreeValue for JInodeVal {}
impl BTreeValue for JDrecVal {}
impl BTreeValue for JPhysExtVal {}
impl BTreeValue for JFileExtentVal {}
impl BTreeValue for JDirStatVal {}
impl BTreeValue for u64 {}

#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct XfBlob {
    pub xf_num_exts: u16,
    pub xf_used_data: u16,
    pub xf_data: [u8; 1000],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Xfields {
    pub x_type: u8,
    pub x_flags: u8,
    pub x_size: u16,
}

/// The value half of an inode record.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct JInodeVal {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    // A C-like union.
    pub nchildren_or_link: i32,
    pub default_protection_class: u32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    pub mode: u16,
    _pad1: u16,
    // Perhaps we won't use it at all because we do not want to do compression for the time being.
    pub uncompressed_size: u64,
    /// Directory entries (j_drec_val_t) and inodes (j_inode_val_t) use this data type to store their extended
    /// fields. Because a dynamic slice cannot be clone-d, we fix a maximum length of the xfields to overcome
    /// this limit. For the time being, we only need to access the j_dstream_t type.
    pub xfields: [u8; DEFAULT_XF_LEN],
}

impl JInodeVal {
    pub fn new(
        parent_id: u64,
        private_id: u64,
        time: u64,
        internal_flags: u64,
        owner: u32,
        group: u32,
        mode: u16,
    ) -> Self {
        Self {
            parent_id,
            private_id,
            mod_time: time,
            change_time: time,
            access_time: time,
            create_time: time,
            nchildren_or_link: 0,
            internal_flags: 0,
            default_protection_class: 0,
            write_generation_counter: 0,
            bsd_flags: 0,
            owner,
            group,
            mode,
            _pad1: 0,
            uncompressed_size: 0,
            xfields: [0u8; DEFAULT_XF_LEN],
        }
    }
}

impl XFieldsInterepretable for JInodeVal {
    fn get_xfields(&self) -> &[u8] {
        &self.xfields
    }
}

impl XFieldsInterepretable for JDrecVal {
    fn get_xfields(&self) -> &[u8] {
        &self.xfields
    }
}

impl JInodeVal {
    /// Get shte actual data stream on the disk.
    pub fn get_dstream(&self) -> KResult<JDstream> {
        let dstream = self
            .interpret_xfields(INO_EXT_TYPE_DSTREAM)
            .unwrap_or_default();
        let dstream = dstream.first().ok_or(Errno::ENOENT)?;

        let ret = unsafe { &*(dstream.as_ptr() as *const JDstream) }.clone();
        Ok(ret)
    }

    /// Get the name of the inode from the xfields.
    pub fn get_name(&self) -> KResult<String> {
        let name = self
            .interpret_xfields(INO_EXT_TYPE_NAME)
            .unwrap_or_default();
        let name = name.first().ok_or(Errno::ENOENT)?;

        Ok(core::ffi::CStr::from_bytes_until_nul(name)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string())
    }
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct CheckpointMap {
    pub cpm_type: u32,
    pub cpm_subtype: u32,
    pub cpm_size: u32,
    pub cpm_pad: u32,
    pub cpm_fs_oid: Oid,
    pub cpm_oid: Oid,
    pub cpm_paddr: u64,
}

/// A checkpoint-mapping block.
#[derive(Clone)]
#[repr(C, align(8))]
pub struct CheckpointMapPhysical {
    pub cpm_o: ObjectPhysical,
    pub cpm_flags: u32,
    pub cpm_count: u32,
    /// If a checkpoint needs to store more mappings than a single block can hold, the checkpoint has multiple
    /// checkpoint-mapping blocks stored contiguously in the checkpoint descriptor area. The last checkpoint-mapping
    /// block is marked with the CHECKPOINT_MAP_LAST flag.
    pub cpm_map: [CheckpointMap; MAX_ALLOWED_CHECKPOINT_MAP_SIZE],
}

impl Debug for CheckpointMapPhysical {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let cpm_map = self
            .cpm_map
            .iter()
            .take_while(|&element| element.cpm_type != 0)
            .collect::<Vec<_>>();
        f.debug_struct("CheckpointMapPhysical")
            .field("cpm_o", &self.cpm_o)
            .field("cpm_flags", &self.cpm_flags)
            .field("cpm_count", &self.cpm_count)
            .field("cpm_map", &cpm_map)
            .finish()
    }
}

#[derive(Debug, Clone)]
#[repr(C, align(2))]
pub struct WrappedMetaCryptoState {
    pub major_version: u16,
    pub minor_version: u16,
    pub cpflags: u32,
    pub persistent_class: u32,
    pub key_os_version: u32,
    pub _pad: u16,
}

#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct ApfsModfiedBy {
    pub id: [u8; 32],
    pub timestamp: u64,
    pub last_xid: Xid,
}

#[derive(Debug, Clone)]
#[repr(C, align(8))]
pub struct ApfsSuperblock {
    pub apfs_o: ObjectPhysical,

    pub apfs_magic: [u8; 4],
    pub apfs_fs_indx: u32,

    pub apfs_features: u64,
    pub apfs_readonly_compatible_features: u64,
    pub apfs_incompatible_features: u64,

    pub apfs_unmount_time: u64,
    pub apfs_fs_reserve_block_count: u64,
    pub apfs_fs_quota_block_count: u64,
    pub apfs_fs_alloc_count: u64,

    pub apfs_meta_crypto: WrappedMetaCryptoState,

    pub apfs_root_tree_type: u32,
    pub apfs_extentref_tree_type: u32,
    pub apfs_snap_meta_tree_type: u32,

    pub apfs_omap_oid: Oid,
    pub apfs_root_tree_oid: Oid,
    pub apfs_extentref_tree_oid: Oid,
    pub apfs_snap_meta_tree_oid: Oid,

    pub apfs_revert_to_xid: Xid,
    pub apfs_revert_to_sblock_oid: Oid,

    pub apfs_next_obj_id: u64,
    pub apfs_num_files: u64,
    pub apfs_num_directories: u64,
    pub apfs_num_symlinks: u64,
    pub apfs_num_other_fsobjects: u64,
    pub apfs_num_snapshots: u64,
    pub apfs_total_blocks_alloced: u64,
    pub apfs_total_blocks_freed: u64,

    pub apfs_vol_uuid: Uuid,
    pub apfs_last_mod_time: u64,

    pub apfs_fs_flags: u64,

    pub apfs_formatted_by: ApfsModfiedBy,
    pub apfs_modified_by: [ApfsModfiedBy; 8],

    pub apfs_volname: [u8; 256],
    pub apfs_next_doc_id: u32,

    pub apfs_role: u16,
    pub _pad: u16,

    pub apfs_root_to_xid: Xid,
    pub apfs_er_state_oid: Oid,

    pub apfs_cloneinfo_id_epoch: u64,
    pub apfs_cloneinfo_xid: u64,

    pub apfs_snap_meta_ext_oid: Oid,
    pub apfs_volume_group_id: Uuid,

    pub apfs_integrity_meta_oid: Oid,
    pub apfs_fext_tree_oid: Oid,
    pub apfs_fext_tree_type: u32,

    pub reserved_type: u32,
    pub reserved_oid: Oid,
}

/// A location within a B-tree node.
#[derive(Clone, Debug)]
#[repr(C, align(4))]
pub struct Nloc {
    pub off: u16,
    pub len: u16,
}

/// A B-tree node.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct BTreeNodePhysical {
    pub btn_o: ObjectPhysical,
    pub btn_flags: u16,
    pub btn_level: u16,
    pub btn_nkeys: u32,
    /// If the BTNODE_FIXED_KV_SIZE flag is set, the table of contents is an array of instances of kvoff_t; otherwise,
    /// itʼs an array of instances of kvloc_t.
    pub btn_table_space: Nloc,
    /// The locationʼs offset is counted from the beginning of the *key area* to the beginning of the free space.
    pub btn_free_space: Nloc,
    /// The offset from the beginning of the key area to the first available space for a key is stored in the off field,
    /// and the total amount of free key space is stored in the len field. Each free space stores an instance of nloc_t
    /// whose len field indicates the size of that free space and whose off field contains the location of the next free
    /// space.
    pub btn_key_free_list: Nloc,
    pub btn_val_free_list: Nloc,

    pub btn_data: [u8; BTREE_STORAGE_SIZE],
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct ChunkInfo {
    pub ci_xid: u64,
    pub ci_addr: u64,
    pub ci_block_count: u32,
    pub ci_free_count: u32,
    pub ci_bitmap_addr: u64,
}

/// A block that contains an array of chunk-info structures.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct ChunkInfoBlock {
    pub cib_o: ObjectPhysical,
    pub cib_index: u32,
    pub cib_chunk_info_count: u32,
    pub cib_chunk_info: [ChunkInfo; 255],
}

/// A block that contains an array of chunk-info block addresses.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct CibAddrBlock {
    pub cab_o: ObjectPhysical,
    pub cab_index: u32,
    pub cab_cib_count: u32,
    pub cab_cib_addr: [u64; 255],
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanFreeQueueKey {
    pub sfqk_xid: Xid,
    pub sfqk_paddr: u64,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanFreeQueueEntry {
    pub sfqe_key: SpacemanFreeQueueKey,
    pub sfqe_count: u64,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanFreeQueue {
    pub sfq_count: u64,
    pub sfq_tree_oid: Oid,
    pub sfq_oldest_xid: Xid,
    pub sfq_tree_node_limit: u16,
    pub sfq_pad16: u16,
    pub sfq_pad32: u32,
    pub _reserved: u64,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanDevice {
    pub sm_block_count: u64,
    pub sm_chunk_count: u64,
    pub sm_cib_count: u32,
    pub sm_cab_count: u32,
    pub sm_free_count: u64,
    pub sm_addr_offset: u32,
    pub sm_reserved: u32,
    pub sm_reserved2: u64,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanAllocationZoneBoundaries {
    pub saz_zone_start: u64,
    pub saz_zone_end: u64,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanAllocationZoneInfoPhys {
    pub saz_current_boundaries: SpacemanAllocationZoneBoundaries,
    pub saz_previous_boundaries: [SpacemanAllocationZoneBoundaries; 7],
    pub saz_zone_id: u16,
    pub saz_previous_boundary_index: u16,
    pub saz_reserved: u32,
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanDatazoneInfoPhys {
    pub sdz_allocation_zones: [[SpacemanAllocationZoneInfoPhys; 8]; 2],
}

#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct SpacemanPhysical {
    pub sm_o: ObjectPhysical,
    pub sm_block_size: u32,
    pub sm_blocks_per_chunk: u32,
    pub sm_chunks_per_cib: u32,
    pub sm_cibs_per_cab: u32,
    pub sm_dev: [SpacemanDevice; 2],
    pub sm_flags: u32,
    pub sm_ip_bm_tx_multiplier: u32,
    pub sm_ip_block_count: u64,
    pub sm_ip_bm_size_in_blocks: u32,
    pub sm_ip_bm_block_count: u32,
    pub sm_ip_bm_base: u64,
    pub sm_ip_base: u64,
    pub sm_fs_reserve_block_count: u64,
    pub sm_fs_reserve_alloc_count: u64,
    pub sm_fq: [SpacemanFreeQueue; 3],
    pub sm_ip_bm_free_head: u16,
    pub sm_ip_bm_free_tail: u16,
    pub sm_ip_bm_xid_offset: u32,
    pub sm_ip_bitmap_offset: u32,
    pub sm_ip_bm_free_next_offset: u32,
    pub sm_version: u32,
    pub sm_struct_size: u32,
    pub sm_datazone: SpacemanAllocationZoneInfoPhys,
}

impl BTreeNodePhysical {
    /// Traverses the B-Tree level by level. `insert_func` indicates how the caller inserts into a map.
    pub fn level_traverse<F>(
        &self,
        device: &Arc<dyn Device>,
        omap: Option<&ObjectMap>,
        mut insert_func: F,
    ) -> KResult<()>
    where
        F: FnMut(&Vec<u8>, &Vec<u8>),
    {
        let mut queue = VecDeque::new();

        queue.push_back(self.clone());
        while let Some(node) = queue.pop_front() {
            if !BTreeNodeFlags::from_bits_truncate(node.btn_flags)
                .contains(BTreeNodeFlags::BTNODE_LEAF)
                && node.btn_level != 0
            {
                let values = self
                    .interpret_as_values()?
                    .iter()
                    .map(|elem| Oid::from_le_bytes(elem.as_slice().try_into().unwrap()))
                    .collect::<Vec<_>>();

                // Insert the next-level nodes.
                values.iter().for_each(|value| {
                    let node_oid = match omap {
                        Some(omap) => omap
                            .get(&ObjectMapKey {
                                ok_oid: *value,
                                ok_xid: Oid::MIN,
                            })
                            .map(|val| val.ov_paddr)
                            .unwrap_or(*value),
                        None => *value,
                    };
                    let node_buf = read_object(device, node_oid).unwrap();
                    let node_cur =
                        unsafe { &*(node_buf.as_ptr() as *const BTreeNodePhysical) }.clone();
                    if ObjectTypes::from_bits_truncate((self.btn_o.o_type & 0xff) as _).intersects(
                        ObjectTypes::OBJECT_TYPE_BTREE_NODE | ObjectTypes::OBJECT_TYPE_BTREE,
                    ) {
                        queue.push_back(node_cur);
                    }
                });
            } else {
                let keys = node.interpret_as_keys()?;
                let values = node.interpret_as_values()?;

                if keys.len() != values.len() {
                    kerror!("keys and values have different lengths?!");
                    return Err(Errno::EINVAL);
                }

                let kv = keys.into_iter().zip(values).collect::<Vec<_>>();
                // It is the leaf node. We read into the memory.
                kv.iter().cloned().for_each(|(key, value)| {
                    insert_func(&key, &value);
                });
            }
        }

        Ok(())
    }

    /// Reads the root node and construct a B-Tree in the memory.
    pub fn parse_as_object_map(&self, device: &Arc<dyn Device>) -> KResult<ObjectMap> {
        // Check if we are using object map root node.
        if !ObjectTypeFlags::from_bits_truncate(self.btn_o.o_type)
            .contains(ObjectTypeFlags::OBJ_PHYSICAL)
        {
            kerror!("cannot parse object map because the node is physical!");
            return Err(Errno::EINVAL);
        }
        if !ObjectTypes::from_bits_truncate((self.btn_o.o_type & 0xff) as _)
            .intersects(ObjectTypes::OBJECT_TYPE_BTREE_NODE | ObjectTypes::OBJECT_TYPE_BTREE)
        {
            kerror!("cannot parse object map because this is not a B-Tree.");
            return Err(Errno::EINVAL);
        }
        if !ObjectTypes::from_bits_truncate((self.btn_o.o_subtype & 0xff) as _)
            .contains(ObjectTypes::OBJECT_TYPE_OMAP)
        {
            kerror!("cannot parse object map because this is not a omap.");
            return Err(Errno::EINVAL);
        }

        let mut omap = ObjectMap::new();
        self.level_traverse(device, None, |key, val| unsafe {
            let key_obj = (*(key.as_ptr() as *const ObjectMapKey)).clone();
            let val_obj = (*(val.as_ptr() as *const ObjectMapValue)).clone();
            omap.insert(key_obj, val_obj);
        })?;

        Ok(omap)
    }

    /// Interprets the u8 array and returns a human-readable array of toc.
    pub fn interpret_as_toc(&self) -> KResult<Vec<TocEntry>> {
        let fixed = BTreeNodeFlags::BTNODE_FIXED_KV_SIZE
            .intersects(BTreeNodeFlags::from_bits_truncate(self.btn_flags));

        let mut toc = Vec::new();
        let toc_off = self.btn_table_space.off as u32;
        // The real length, not the capacity.
        let toc_len = self.btn_nkeys;
        let key_size = if fixed {
            core::mem::size_of::<KvOff>()
        } else {
            core::mem::size_of::<KvLoc>()
        };

        for i in (toc_off..toc_off + toc_len * key_size as u32).step_by(key_size) {
            let entry = unsafe {
                if fixed {
                    TocEntry::Off((*(self.btn_data.as_ptr().add(i as _) as *const KvOff)).clone())
                } else {
                    TocEntry::Loc((*(self.btn_data.as_ptr().add(i as _) as *const KvLoc)).clone())
                }
            };
            toc.push(entry);
        }

        Ok(toc)
    }

    /// Extracts the tree keys as a vector.
    pub fn interpret_as_keys(&self) -> KResult<Vec<Vec<u8>>> {
        let toc = self.interpret_as_toc()?;
        let key_off = self.btn_table_space.off + self.btn_table_space.len;
        // Need to first check the key header.
        let mut vec = Vec::new();
        for entry in toc.iter() {
            let key = match entry {
                TocEntry::Off(kv) => {
                    let start = (key_off + kv.k) as usize;
                    // Because this is fixed, we do not need to give a size.
                    let end = start + core::mem::size_of::<ObjectMapKey>();
                    self.btn_data[start..end].to_vec()
                }
                TocEntry::Loc(kv) => {
                    let start = (key_off + kv.k.off) as usize;
                    let end = start + kv.k.len as usize;
                    self.btn_data[start..end].to_vec()
                }
            };

            vec.push(key);
        }

        Ok(vec)
    }

    /// Extacts the map values as a vector.
    pub fn interpret_as_values(&self) -> KResult<Vec<Vec<u8>>> {
        let toc = self.interpret_as_toc()?;
        let mut values = Vec::new();
        let data_rev = self.btn_data.iter().copied().rev().collect::<Vec<_>>();

        // kinfo!("self = {:x?}", self);

        let value_off = if BTreeNodeFlags::from_bits_truncate(self.btn_flags)
            .contains(BTreeNodeFlags::BTNODE_ROOT)
        {
            core::mem::size_of::<BTreeInfo>()
        } else {
            0
        };

        for (idx, entry) in toc.iter().enumerate() {
            let (offset, len) = match entry {
                TocEntry::Loc(kv) => (kv.v.off, kv.v.len),
                TocEntry::Off(kv) => (kv.v, 0),
            };

            let range = if self.btn_level == 0 {
                match len {
                    0 => value_off..value_off + offset as usize,
                    len => value_off + (offset - len) as usize..value_off + offset as usize,
                }
            } else {
                // Because all values stored in non-leaf nodes are object identifiers of the child nodes,
                // it is always safe to assume that the layout is u64 aligned for values.
                value_off + idx * QWORD_LEN..value_off + (idx + 1) * QWORD_LEN
            };

            let slice = data_rev[range].iter().copied().rev().collect::<Vec<_>>();
            values.push(slice);
        }

        Ok(values)
    }

    pub fn parse_as_fs_tree(&self, device: &Arc<dyn Device>, omap: &ObjectMap) -> KResult<FsMap> {
        let mut fs_map = FsMap::default();

        self.level_traverse(device, Some(omap), |key, val| unsafe {
            let ty = &*(key.as_ptr() as *const JKey);
            match ty.get_type() {
                APFS_TYPE_DIR_REC => {
                    let key_obj = (*(key.as_ptr() as *const JDrecHashedKey)).clone();
                    let mut val_obj = (*(val.as_ptr() as *const JDrecVal)).clone();

                    let pad_start = core::mem::size_of::<JDrecVal>() - val.len();
                    val_obj.xfields[pad_start..].fill(0);
                    fs_map.dir_record_map.insert(key_obj, val_obj);
                }
                APFS_TYPE_INODE => {
                    // We may need to exert some special care on the `xfields`?
                    let key_obj = (*(key.as_ptr() as *const JInodeKey)).clone();
                    let mut val_obj = (*(val.as_ptr() as *const JInodeVal)).clone();

                    let pad_start = core::mem::size_of::<JInodeVal>() - val.len();
                    val_obj.xfields[pad_start..].fill(0);
                    fs_map.inode_map.insert(key_obj, val_obj);
                }
                APFS_TYPE_EXTENT => {
                    let key_obj = (*(key.as_ptr() as *const JPhysExtKey)).clone();
                    let val_obj = (*(val.as_ptr() as *const JPhysExtVal)).clone();
                    fs_map.phys_ext_map.insert(key_obj, val_obj);
                }
                APFS_TYPE_FILE_EXTENT => {
                    let key_obj = (*(key.as_ptr() as *const JFileExtentKey)).clone();
                    let val_obj = (*(val.as_ptr() as *const JFileExtentVal)).clone();
                    fs_map.file_extent_map.insert(key_obj, val_obj);
                }
                APFS_TYPE_DIR_STATS => {
                    let key_obj = (*(key.as_ptr() as *const JDirStatKey)).clone();
                    let val_obj = (*(val.as_ptr() as *const JDirStatVal)).clone();
                    fs_map.dir_stat_map.insert(key_obj, val_obj);
                }
                other => (),
            }
        })?;

        Ok(fs_map)
    }
}

/// Static information about a B-tree
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct BTreeInfoFixed {
    pub bt_flags: u32,
    pub bt_node_size: u32,
    pub bt_key_size: u32,
    pub bt_val_size: u32,
}

/// Information about a B-tree.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct BTreeInfo {
    pub bt_fixed: BTreeInfoFixed,
    pub bt_longest_key: u32,
    pub bt_longest_val: u32,
    pub bt_key_count: u64,
    pub bt_node_count: u64,
}

/// The location, within a B-tree node, of a key and value. The B-tree nodeʼs table of contents uses this structure when
/// the keys and values are not both fixed in size.
#[derive(Clone, Debug)]
#[repr(C, align(4))]
pub struct KvOff {
    pub k: u16,
    pub v: u16,
}

/// The location, within a B-tree node, of a fixed-size key and value.
///
/// The B-tree nodeʼs table of contents uses this structure when the keys and values are both fixed in size. The meaning
/// of the offsets stored in this structureʼs k and v fields is the same as the meaning of the off field in an instance
/// of nloc_t. This structure doesnʼt have a field thatʼs equivalent to the len field of nloc_t — the key and value
/// lengths are always the same, and omitting them from the table of contents saves space.
#[derive(Clone, Debug)]
#[repr(C, align(8))]
pub struct KvLoc {
    pub k: Nloc,
    pub v: Nloc,
}

/// The toc entry.
#[derive(Clone, Debug)]
pub enum TocEntry {
    Off(KvOff),
    Loc(KvLoc),
}

/// This is the in-memory representation of the object map.
#[derive(Debug)]
pub struct Omap {
    pub omap: ObjectMap,
    pub root_node: BTreeNodePhysical,
    pub btree_info: BTreeInfo,
}

/// A simpler wrapper for the volumn.
pub struct ApfsVolumn {
    pub name: String,
    pub superblock: ApfsSuperblock,
    pub object_map: ObjectMap,
    pub fs_map: RwLock<MaybeDirty<FsMap>>,
    pub occupied_inode_numbers: RwLock<BTreeSet<u64>>,
    pub apfs: Arc<AppleFileSystem>,
}

impl ApfsVolumn {
    /// Parses the raw `apfs_superblock` struct and constructs a Self.
    pub fn from_raw(
        device: &Arc<dyn Device>,
        apfs: Arc<AppleFileSystem>,
        apfs_superblock: ApfsSuperblock,
    ) -> KResult<Arc<Self>> {
        let apfs_omap_oid = apfs_superblock.apfs_omap_oid;
        // Note that this is the *virtual object identifier*.
        let apfs_root_tree_oid = apfs_superblock.apfs_root_tree_oid;
        // Read omap.
        let apfs_omap = read_omap(device, apfs_omap_oid)?;
        // Read root node's oid.
        let apfs_root_addr = apfs_omap
            .omap
            .get(&ObjectMapKey {
                ok_oid: apfs_root_tree_oid,
                ok_xid: Xid::MIN,
            })
            .ok_or(Errno::ENOENT)?
            .ov_paddr;

        // Read the file system tree.
        let apfs_tree = read_fs_tree(device, apfs_root_addr, &apfs_omap.omap)?;

        kdebug!("apfs tree: {:x?}", apfs_tree);

        // Get occupied INode numbers.
        let occupied_inode_numbers = apfs_tree
            .inode_map
            .keys()
            .map(|k| k.hdr.get_oid())
            .collect::<BTreeSet<_>>();

        let name = CStr::from_bytes_until_nul(&apfs_superblock.apfs_volname)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string();
        Ok(Arc::new(Self {
            name,
            superblock: apfs_superblock,
            object_map: apfs_omap.omap,
            fs_map: RwLock::new(MaybeDirty::new(apfs_tree)),
            occupied_inode_numbers: RwLock::new(occupied_inode_numbers),
            apfs,
        }))
    }
}

/// The Inode types.
#[derive(Ord, PartialEq, PartialOrd, Eq, Clone, Debug)]
#[repr(u8)]
pub enum INodeType {
    DtUnknown = 0,
    DtFifo = 1,
    DtChr = 2,
    DtDir = 4,
    DtBlk = 6,
    DtReg = 8,
    DtLnk = 10,
    DtSock = 12,
    DtWht = 14,
}

impl INodeType {
    pub fn from_u8(other: u8) -> Self {
        unsafe { core::mem::transmute::<u8, Self>(other) }
    }
}

#[inline]
pub fn get_timespec(time: u64) -> Timespec {
    let duration = Duration::from_nanos(time);
    Timespec {
        sec: duration.as_secs() as _,
        nsec: duration.subsec_nanos() as _,
    }
}

#[inline]
pub fn get_timestamp(time: Timespec) -> Duration {
    Duration::new(time.sec as u64, time.nsec as u32)
}
