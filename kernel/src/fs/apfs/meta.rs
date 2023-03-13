//! Defines some important metadata.

use core::cmp::Ordering;

use alloc::collections::BTreeMap;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::{arch::DWORD_LEN, error::KResult};

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
/// We may need to serialize this thing.
pub type ObjectMap = BTreeMap<ObjectMapKey, ObjectMapValue>;

// Some important constants.

pub const BLOCK_SIZE: usize = 0x1000;
pub const NX_MAGIC: &[u8; 4] = b"BSXN";
pub const APFS_MAGIC: &[u8; 4] = b"BSPA";
pub const OBJECT_HDR_SIZE: usize = core::mem::size_of::<ObjectPhysical>();
pub const MAX_ALLOWED_CHECKPOINT_MAP_SIZE: usize = 100;

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
    /// typedef pub oid_t: u64,
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

    /// Do some post-processing like endianness conversions.
    pub fn post_process(&mut self) {
        // Convert the endianess of the magic.
        self.nx_magic.reverse();
    }
}

/// A key used to access an entry in the object map.
///
/// As per the doc by Apple, we search the B-tree for a key whose object identifier is the same as the desired object
/// identifier, and whose transaction identifier is less than or equal to the desired transaction identifier. If there are
/// multiple keys that satisfy this test, use the key with the **largest** transaction identifier.
#[derive(Clone, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct ObjectMapKey {
    pub ok_oid: Oid,
    pub ok_xid: Xid,
}

impl PartialEq for ObjectMapKey {
    fn eq(&self, other: &Self) -> bool {
        self.ok_oid == other.ok_oid && self.ok_xid == other.ok_xid
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
            Ordering::Equal => self.ok_xid.cmp(&other.ok_xid),
            res => res,
        }
    }
}

/// A value in the object map.
#[derive(Clone, Serialize, Deserialize)]
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

impl ObjectMapPhysical {
    /// Parse the raw content of the block and then return an in-memory representation of the object map.
    pub fn parse(&self) -> ObjectMap {
        todo!()
    }
}

/// A header used at the beginning of all file-system keys.
///
/// All file-system objects have a key that begins with this information. The key for some object types have additional
/// fields that follow this header, and other object types use [`JKey`] as their entire key.
#[repr(C, packed)]
pub struct JKey {
    /// The objectʼs identifier is a pub value accessed as obj_id_and_type & OBJ_ID_MASK. The objectʼs type is a uint8_: u64,
    /// value accessed as (obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT. The objectʼs type is one of the constants
    /// defined by j_obj_types.
    pub obj_id_and_type: u64,
}

/// The key half of a directory-information record.
#[repr(C, packed)]
pub struct JInodeKey {
    /// The object identifier in the header is the file-system objectʼs identifier, also known as its inode number. The type
    /// in the header is always `APFS_TYPE_INODE`.
    pub hdr: JKey,
}

/// The value half of an inode record.
#[repr(C, packed)]
pub struct JInodeVal {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    pub nchildren: i32,
    pub nlink: i32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    pub mode: u16,
    _pad1: u16,
    // Perhaps we won't use it at all because we do not want to do compression for the time being.
    pub uncompressed_size: u64,
    // DISABLED.
    pub xfields: [u8],
}

#[derive(Clone)]
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

/// A volume superblock.
#[derive(Clone)]
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
}

/// A location within a B-tree node.
#[derive(Clone)]
#[repr(C, align(4))]
pub struct Nloc {
    pub off: u16,
    pub len: u16,
}

/// A B-tree node.
#[repr(C, align(8))]
pub struct BTreeNodePhysical {
    pub btn_o: ObjectPhysical,
    pub btn_flags: u16,
    pub btn_level: u16,
    pub btn_nkeys: u32,
    pub btn_table_space: Nloc,
    pub btn_free_space: Nloc,
    pub btn_key_free_list: Nloc,
    pub btn_val_free_list: Nloc,
    /// We do not know the exact size of this struct.
    pub btn_data: [u8],
}

/// Static information about a B-tree
#[derive(Clone)]
#[repr(C, align(8))]
pub struct BTreeInfoFixed {
    pub bt_flags: u32,
    pub bt_node_size: u32,
    pub bt_key_size: u32,
    pub bt_val_size: u32,
}

/// Information about a B-tree.
#[derive(Clone)]
#[repr(C, align(8))]
pub struct BTreeInfo {
    pub bt_fixed: BTreeInfoFixed,
    pub bt_longest_key: u32,
    pub bt_longest_val: u32,
    pub bt_key_count: u64,
    pub bt_node_count: u64,
}
