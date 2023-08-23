# 实验四：文件系统
## 实验目的

- 了解基本的文件系统系统调用的实现
- 了解一个Linux APFS文件系统的设计与实现

## 相关知识

### 文件系统
文件系统是操作系统中用于管理和组织文件的一种机制。它定义了文件的存储方式、访问权限、目录结构等。文件系统可以将文件存储在物理设备上，如硬盘、固态硬盘等，也可以将文件存储在虚拟设备上，如内存、网络存储等。持久性的数据是存储在磁盘上的，如果没有文件系统，访问这些数据就需要直接读写磁盘的sector，实在太不方便了。而文件系统存在的意义，就是能更有效的组织、管理和使用磁盘上的这些raw data。

文件系统通常由文件、目录和文件操作相关的功能组成。文件是存储数据的基本单位，可以是文本文件、图像文件、音频文件等。目录是一种特殊的文件，用于组织和管理其他文件和目录。文件操作包括创建、删除、复制、移动、重命名、读取和写入等。

虚拟文件系统是操作系统中的一种抽象层，它将不同类型的文件系统统一起来，使得应用程序可以通过统一的接口来访问不同类型的文件系统。虚拟文件系统隐藏了底层文件系统的细节，提供了一种统一的视图，使得应用程序可以像访问本地文件系统一样访问远程文件系统或其他类型的文件系统。

虚拟文件系统的主要功能包括文件系统的挂载与卸载、文件和目录的创建与删除、文件的读取与写入等。它还提供了一些高级功能，如文件访问控制、文件缓存、文件系统日志等。

通过虚拟文件系统，应用程序可以通过统一的接口访问不同类型的文件系统，而不需要关心底层文件系统的具体实现。这使得应用程序的开发更加灵活和可移植，同时也提高了系统的可扩展性和可维护性。

### 文件系统的组成

由于磁盘上的数据需要和内存交互，内存通常以4KB为单位，所以在磁盘上的一个4KB就成为一个block。blocks中，分为文件本身包含的数据user data和文件的访问权限、大小和创建时间等控制信息，这些信息被称为meta data。meta data可理解为是关于文件user data的data，这些meta data存储的数据结构就是inode。

### Linux APFS

Linux APFS（Apple File System）是苹果公司开发的的文件系统，最初用于苹果的macOS和iOS操作系统。Linux APFS是对APFS的开源实现，用于在Linux系统上支持APFS文件系统。

APFS是一种现代的、高性能的文件系统，具有许多先进的功能和优势。它支持快照（Snapshot）功能，可以在不占用额外存储空间的情况下保存文件系统的状态，以便在需要时进行恢复。此外，APFS还支持文件和目录的副本（Clone）功能，可以在不占用额外存储空间的情况下创建文件和目录的副本。

APFS还具有对文件和目录的元数据（Metadata）进行加密的功能，可以保护用户的数据安全。它还支持文件和目录的快速压缩和解压缩，以节省存储空间。此外，APFS还提供了更高的文件系统容量限制，更好的文件系统恢复能力以及更高的性能和可靠性。

Linux APFS的开源实现是为了让Linux系统能够与使用APFS文件系统的苹果设备进行兼容和交互。通过在Linux系统上安装和使用Linux APFS，用户可以读取和写入APFS格式的存储设备，如硬盘、固态硬盘、闪存驱动器等。这使得用户可以在Linux系统上方便地访问和管理APFS文件系统中的文件和目录。

### mount

mount是一个在Linux系统中用于挂载文件系统的命令。挂载是将一个文件系统连接到文件树的特定位置的过程，使得文件系统中的文件和目录可以在该位置访问。

mount命令的基本语法如下：

    mount [-t 文件系统类型] [-o 选项] 设备文件名 挂载点
    其中，常用的选项包括：

    -t：指定文件系统类型，如ext4、ntfs等。
    -o：指定挂载选项，如读写权限、允许执行等。
常见的用法示例：

- mount /dev/sdb1 /mnt：将/dev/sdb1设备上的文件系统挂载到/mnt目录。
- mount -t ntfs-3g /dev/sdb1 /mnt：将/dev/sdb1设备上的NTFS文件系统以读写权限挂载到/mnt目录。
- mount -o remount,rw /mnt：重新挂载/mnt目录，并设置为可读写权限。
- mount命令还可以通过/etc/fstab文件实现开机自动挂载。该文件记录了系统中需要挂载的文件系统信息，包括设备文件、挂载点、文件系统类型和挂载选项等。

## 练习

NeoOS文件系统使用了 LINUX-APFS 作为支持，在kernel/src/fs文件夹中定义了实现文件系统的相关代码，实现了以下功能：

- Apple Filesystem（只读，内存写）
- rCore Simple Filesystem（支持读写）
- /dev 设备虚拟文件系统（fs/devfs）
- /proc 进程相关文件系统，可用于获取内存映射等进程对应的元数据（fs/proc）

文件对象为 fs/file.rs，与 unix 一样做了抽象。文件系统的 filesystem和Inode的抽象层使用 trait 设计。

在本节学习中，我们主要学习APFS，代码实现位于/kernel/src/fs/apfs文件夹中。meta.fs定义了一些重要的元数据，mod.rs中实现了APFS的具体代码。

一个APFS分区有一个单独的容器，它实现空间管理和崩溃保护。一个容器可以包含多个卷（也称为文件系统），每个卷都包含文件和文件夹的目录结构。虽然只有一个容器，但是容器超级块（的实例）有多个副本存储在磁盘上。这些副本保存了容器在过去时间点的状态。

许多类型的前缀都是nx_或j_，这表明它们是容器层或文件系统层的一部分。

NeoOS的APFS大多数实现都直接取自苹果的APFS开发者手册。

### 练习一：APFS的定义
在mod.rs中，APFS类抽象如下。在该类中，所有成员都应该使用像`Arc`或`RwLock`这样的包装器来保护，以防止出现自变性问题。

```rust
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
    /// The spaceman instance. TODO: make it a high-level struct.
    spaceman: RwLock<SpacemanPhysical>,
}
```

### 练习二：mount命令的实现

APFS类的成员方法mount_container实现了通过设备驱动程序(AHCI SATA)挂载APFS容器并返回一个arc-ed实例。实现可能需要调用`self.Mount_volumns`使其他卷存在。

首先，读取分区的第0块。这个块包含一个容器超级块的副本（一个`nx_superblock_t`的实例）。它可能是最新版本的副本，也可能是旧版本的副本，这取决于驱动器是否被干净地卸载。

```rust
let mut nx_superblock = device.load_struct::<NxSuperBlock>(0)?;

// Verify the block.
if !nx_superblock.verify() {
    kerror!("the superblock is corrupted.");
    return Err(Errno::EINVAL);
}
```

接下来，通过读取`nx_xp_desc_base`字段，使用容器超块的第零副本来定位检查点描述符区域。

```rust
let nx_xp_desc_base = nx_superblock.nx_xp_desc_base;
let mut highest_bit = nx_superblock.nx_xp_desc_blocks & (1 << 31);
if highest_bit != 0 {
    kerror!("currently we do not support non-contiguous checkpoint descriptor area");
    return Err(Errno::EACCES);
}
let nx_xp_data_base = nx_superblock.nx_xp_data_base;
highest_bit = nx_superblock.nx_xp_data_blocks & (1 << 31);
if highest_bit != 0 {
    kerror!("currently we do not support non-contiguous checkpoint data area");
    return Err(Errno::EACCES);
}
```

接下来，读取检查点描述符区域中的entry，这些entry是`checkpoint_map_phys_t`或`nx_superblock_t`的实例。最后，读取检查点的数据区域。

```rust
let mut best_superblock_xid = 0;
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
            if map_object.cpm_o.o_xid > best_superblock_xid {
                best_superblock_xid = map_object.cpm_o.o_xid;
                nx_superblock = cur_superblock.clone();
            }
        }

        _ => continue,
    }
}
```
mount_volumns_all实现了挂载所有卷，mount_volunm实现了挂载特定的卷。对于每个卷，在容器对象映射中查找指定的虚拟对象标识符来定位卷的超级块。因为oid不能为零，所以我们可以跳过零。


```rust
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

            kdebug!("mounting {:x?}", key);
            self.mount_volumn(&key)?;
        }

        Ok(())
    }
```

## 参考文档

[Apfsprogs](https://github.com/linux-apfs/apfsprogs)

[linux-apfs,2023](https://github.com/linux-apfs/linux-apfs-rw)