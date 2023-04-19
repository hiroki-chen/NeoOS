# 正式编写 bootloader

在本节中，我们聚焦在 bootloader 主函数的编写。正如前文所述，我们的 bootloader 的主函数将在`boot/src/main.rs`中定义，其函数原型为

```rust
#[entry]
fn _main(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status;
```

我们的内核 bootloader 大致会完成如下几件事情，从而启动操作系统内核。

1. 从 BIOS 读取 ACPI 硬件表并存储到某个物理地址。
2. 从 ESP 分区读入操作系统内核镜像，并将其加载到一个物理地址。
3. 解析 memory map。
4. 建立内核页表：
    1. 将内核的物理地址重新映射到一个给定的虚拟地址。
    2. 为内核建立对应的栈区。
    3. 将剩余的物理地址线性映射到一段给定的虚拟地址上去。
    4. 映射初始 GDT 表并让内核重新建立 GDT。
5. 将控制权转交给内核的第一行代码。这一步是通过一个长跳转实现的。

## 初始化 UEFI 并且读取硬件信息

准确来说，这一步是初始化 UEFI 的 boot service。UEFI Boot Service 是指 UEFI 固件提供的一组服务，用于启动操作系统并在系统启动期间提供一些基本的系统功能。UEFI Boot Service 的主要功能包括：加载操作系统内核、初始化系统硬件、管理系统内存、处理系统异常等。这些服务都是在操作系统启动前由 UEFI 固件提供的。我们可以通过`uefi-rs`提供的接口进行一键初始化。

```rust
// `st` comes from the function argument.
uefi_services::init(&mut st).expect("Failed to launch the system table!");
let bs = st.boot_services();
```

ACPI 硬件描述表可以通过 `ConfigTableEntry` 这个数组来访问。UEFI 的 Config Table 是一个结构体数组，每个元素都是一个 EFI Configuration Table Entry 结构体，用于描述系统中的各种配置信息。在这个结构体中，VendorGuid 表示 Configuration Table Entry 的供应商 ID，通常是一个 GUID（全局唯一标识符），用于标识这个 Entry 的类型和用途。VendorTable 则是指向 Configuration Table Entry 的数据结构的指针。UEFI 固件通过在 EFI System Table 中添加 Configuration Table Entry 来向操作系统提供系统配置信息。操作系统可以通过遍历 Config Table 中的 Entry，找到并使用其中的某些信息。常见的 Configuration Table Entry 包括 ACPI 表、SMBIOS 表、SMBIOS3 表等，它们用于描述系统的硬件配置、性能参数等。

```c
typedef struct {
  EFI_GUID  VendorGuid;   // 表示 Configuration Table Entry 的供应商ID
  VOID      *VendorTable; // 指向 Configuration Table Entry 的数据结构
} EFI_CONFIGURATION_TABLE;
```

```rust
let config_table = st.config_table();
// Get the base address of the ACPI2 data structure.
let acpi_address = config_table
    .iter()
    .find(|entry| entry.guid == ACPI2_GUID)
    .unwrap()
    .address;
```

### ACPI

ACPI（Advanced Configuration and Power Interface，高级配置与电源接口）是一种由 Intel、Microsoft 和其他公司共同制定的电源管理标准。ACPI 定义了一种描述系统硬件配置和操作系统使用的系统管理信息的结构化数据格式，它的主要作用是实现操作系统的高级电源管理和设备管理功能。ACPI 表是系统中的一种特殊数据表，用于存储 ACPI 规范定义的各种数据结构和系统信息。ACPI 表通常被存储在系统 BIOS 或 UEFI 固件中，它们可以由操作系统通过解析固件中的 ACPI 表来获取系统配置信息和控制电源管理等功能。常见的 ACPI 表包括 DSDT 表、SSDT 表、FACP 表、APIC 表等。

ACPI 表的主要作用有：

* 电源管理：ACPI 规范定义了一组电源管理方法，可以使操作系统通过 ACPI 表中的数据来实现更精细的电源管理，如休眠、待机、唤醒等功能。
* 设备管理：ACPI 表描述了系统中各种设备的配置和属性信息，使操作系统能够自动检测和配置硬件设备，而不需要在安装过程中手动配置硬件。
* 系统性能和事件跟踪：ACPI 表中包含了系统的性能和事件跟踪信息，可以帮助系统管理员分析系统性能和故障，提高系统运行的稳定性和可靠性。

总之，ACPI 表是系统中的一个重要组成部分，它提供了操作系统管理电源、设备和性能等方面所需的重要信息，是实现高级电源管理和设备管理功能的关键。在内核的许多初始化过程中，这个表的作用非常大，因为它还经常包含硬件的拓扑结构和元数据等。

## 从 ESP 分区读入操作系统内核镜像并加载到一个给定的物理地址

前面已经提到，Rust 的动态内存分配是依赖于一个`global_allocator`的，这个分配器能够为我们分配物理栈帧。在当前的实现中，我们采用了`uefi-rs`这个仓库，它已经在启动 UEFI 之后正确地给我们实现了一个默认的分配器，所以我们并不需要手动实现了。此时，类似于`alloc::vec::Vec`或者`alloc::boxed::Box`等基于堆的数据结构和工具都是可以使用的。因此，在这一步，我们只需要实现从 ESP 分区读取内核即可。

熟悉 UEFI 的读者可能已经知道，UEFI 是一个协议，它也支持文件系统的读写，所以我们可以直接利用 UEFI 的协议去读取内核镜像。在`uefi-rs`的实现中，我们是采用句柄（handle）的方式来获取对磁盘对象的访问的。这一步代码在`boot/src/utils.rs`中，具体步骤可以分为：

1. 获取对文件系统的句柄。

```rust
// Get a handle to the simple filesystem implemented by the UEFI standard (FAT32).
let handle = bs.get_handle_for_protocol::<SimpleFileSystem>().unwrap();
// Open the filesystem.
let mut file_system = bs.open_protocol_exclusive::<SimpleFileSystem>(handle).unwrap();
```

2. 获取对文件对象的句柄。

```rust
// Get the root node.
let mut root = file_system.open_volume().unwrap();
let mut buf = [0u16; 0x40];
let filename = CStr16::from_str_with_buf(path, &mut buf).unwrap();
// Open the file object.
let handle = root.open(filename, FileMode::Read, FileAttribute::empty()).expect("Failed to open file");
// Parse the file.
let file = match handle.into_type().unwrap() {
    FileType::Regular(f) => f,
    _ => panic!("This file does not exist!"),
};
```

3. 根据文件的元数据，分配对应的动态内存空间。

```rust
// Prepare a buffer for holding the metadata of the given file.
let mut file_ino = vec![0u8; 4096];
// Parse the file size field.
let info: &mut FileInfo = file.get_info(&mut file_info).unwrap();
let size = usize::try_from(info.file_size()).unwrap();

// Allocate some pages in the memory.
let file_mem_ptr = bs
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((size - 1) / crate::PAGE_SIZE as usize) + 1,
        )
        .expect("Cannot allocate memory in the ramdisk!") as *mut u8;
let buf = unsafe { core::slice::from_raw_parts_mut(file_mem_ptr, size) };
```

4. 读入文件。

```rust
let file_len = file.read(buf).expect("Cannot read file into the memory!");
// Return the buffer.
return &mut buf[..file_len]
```

> **注意**：读者只需要谨记，通过 UEFI 访问各种设备的唯一方式就是通过 UEFI 事先定义好的各种协议。

## 解析 Memory Map（UEFI）并退出 Boot Service

e820 memory map是指BIOS提供的一种机制，用于描述可用的物理内存地址范围和类型。这个机制在启动时由BIOS提供，操作系统可以通过读取这个信息来确定系统可用的内存资源。e820 memory map通常包括多个内存段，每个段描述了一段连续的物理内存地址范围和其所属的类型，例如RAM、ROM、ACPI等。这个信息在操作系统启动时被BIOS读取，并通过传递给操作系统内核来帮助操作系统初始化和管理内存资源。e820 memory map是在早期的x86架构上广泛使用的一种机制，它提供了一种简单且可靠的方法来描述可用的内存资源。然而，在现代的计算机体系结构中，它已经被更先进的内存管理技术所取代，如UEFI的内存描述表（Memory Descriptor Table，MDT）和ACPI中的系统描述表（System Description Table，SDT）。

我们通过这个 memory map 信息主要的目的是想要获取物理内存的分布和信息，以便确定哪些部分的内存信息是可以被内核分配并使用的。我们从 UEFI 中读取这一信息过程如下：

1. 获取 memory map 描述数组的大概大小并分配一段动态内存：

```rust
// In the context of UEFI (Unified Extensible Firmware Interface),
// the memory_map_size parameter specifies the size of the memory
// map that is provided by the UEFI firmware. The memory map is a
// table that contains information about the memory regions that
// are available to the operating system, such as the size and type
// of each region. This information is important for the operating
// system to properly allocate and manage memory resources.
let mmap_storage = {
    let max_mmap_size =
        bs.memory_map_size().map_size + 8 * core::mem::size_of::<MemoryDescriptor>();
    let ptr = bs
        .allocate_pool(MemoryType::LOADER_DATA, max_mmap_size)
        .unwrap();
    unsafe { core::slice::from_raw_parts_mut(ptr, max_mmap_size) }
};
mmap_storage.fill(0);
let mmap_ptr = mmap_storage.as_mut_ptr();
```

2. 在操作系统启动过程中，UEFI firmware通常在加载操作系统后立即退出boot service。此时，操作系统就可以自己管理系统资源，并使用UEFI runtime service来访问UEFI firmware的其他功能。此时，我们已经完成了内核加载的主要部分，接下来的步骤不需要 UEFI 的服务进行辅助了，因此我们需要退出 Boot Service 然后保存 memory map 信息。

```rust
// Save the memory map information to `mmap_storage`.
let (_system_table, memory_map) = st
    .exit_boot_services(handle, mmap_storage)
    .expect("_main(): Failed to exit boot services");
let mmap_len = memory_map.len();
```

## 建立内核页表

### 栈帧分配

我们来到了最重要的一个环节，对内核本身的页表进行初始化和建立。由于前面一个步骤已经将正确的 memory map 从 UEFI 中读取出来了，为了方便我们分配物理栈帧并进行映射，我们还需要一个辅助工具 `OsFrameAllocator`，它定义在 `boot/src/page_table.rs`中，声明如下。

```rust
/// A physical frame allocator based on a BIOS or UEFI provided memory map.
pub struct OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
{
    #[allow(unused)]
    original: M,
    /// The memory map currently tracked.
    memory_map: M,
    /// The current memory descriptor.
    current_descriptor: Option<&'static MemoryDescriptor>,
    /// The next free physical frame.
    next_frame: PhysFrame,
}
```

这个结构体存储了之前读取的 memory map 信息并寻找空闲的物理内存，然后记录内存使用信息，为之后需要的分配物理栈帧提供协助。它最重要的一个接口就是`allocate`，其函数原型如下：

```rust
fn allocate(&mut self, d: &MemoryDescriptor) -> Option<PhysFrame<Size4KiB>>;
```

这个函数的作用是检查`d`指向的内存映射空间还能不能继续分配一个物理栈帧，若可以，我们记录下来，并递增`next_frame`，若不能，则返回一个空`None`值。

随后我们可以实现栈帧分配器了，主要是将 `PageFrameAllocator`这个 trait 实现：

```rust
unsafe impl<M> FrameAllocator<Size4KiB> for OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
{
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        todo!();
    }
}
```

这个函数要做的事情其实很简单：

1. 查询`self.current_descriptor`是否还有剩余的未使用空间，这一步可以通过`self.allocate`来实现。
2. 如果有剩余空间，则通过`allocate`函数分配栈帧并返回。
3. 如果没有剩余空间，清空`self.current_descriptor`然后访问 memory map，查询是否有空闲内存可以分配。
4. 如果都没有，则系统内存不足，直接宕机。

> **任务**：尝试在`boot/src/page_table.rs`中实现一个简易的栈帧分配器！

接下来，我们可以操作页表了。

> **注意：** UEFI 已经正确设置了一个页表，不过这个页表是一对一映射的，也就是说，虚拟地址和物理地址是**一致**的。但是我们并不需要这个页表。

首先我们需要开启权限保护，防止页表被 Ring 3 的应用程序篡改，这一部很简单，只需要写入控制寄存器即可。

```rust
pub fn enable_nxe_efer() {
    unsafe {
        Efer::update(|efer| efer.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
}

pub fn enable_write_protect() {
    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
    }
}
```

其次，我们需要将内核的 ELF 文件正确进行映射。这一步实现的函数为

```rust
/// Loads the kernel ELF executable into memory and switches to it.
/// Returns the entry point of the kernel in virtual address.
pub fn map_kernel(
    kernel: &Kernel,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
);
```

### ELF 文件结构

每个 ELF 文件都由一个 ELF 首部和紧跟其后的文件数据部分组成。数据部分可以包含：

* 程序头表（Program header table）：描述 0 个或多个内存段信息。这个表主要描述 ELF 本身的信息。
* 分段头表（Section header table）：描述 0 段或多段链接与重定位需要的数据。这个表主要描述每个段的信息。
* 程序头表与分段头表引用的数据，比如 .text .data。

读者可以在 Linux 系统中使用 `readelf` 命令来解析任意一个 ELF 文件。例如：

```sh
$  readelf -h ./target/x86_64/debug/kernel
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xffffffff80575550
  Start of program headers:          64 (bytes into file)
  Start of section headers:          60778864 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         8
  Size of section headers:           64 (bytes)
  Number of section headers:         28
  Section header string table index: 26
```

内核关心的部分主要是一些可以加载的部分（loadable section），要判断一个段是否可加载，可以通过程序头来读取对应的标识符。

在 bootloader 实现中，我们用了`xmas_elf`这个库来解析 ELF 文件，我们只需要把之前读入到内存的文件内容（可以通过指针获取到起始物理地址）用这个库解析即可获取程序头和每个段了。映射过程很简单，我们只需要遍历程序头，然后找到那些可以加载的段，随后进行映射即可。

```rust
for segment in kernel.elf.program_iter() {
    if program::sanity_check(segment, &kernel.elf).is_err() {
        panic!();
    }

    map_segment(&segment, frame_allocator, page_tables, kernel_start);
}
```

![img](Elfdiagram.png)

> **注意：** 对于.rodata, .bss等含有未初始化数据的段，常常存在一个问题：它们的文件大小（file size）和内存大小（memory size）不一样的，一般都是内存大小更大一些。这些多余的内存空间要使用 0 来填充。
>
> **任务：** 对内核文件进行重新映射。你要做的是：
>
> 1. 遍历程序头，检查是否可加载。若是，则确定其在文件中的偏移（通过`paddr`可以获取在文件中的基址），然后将其读出（通过`filesz`可以知道其大小）。因为我们直接读取到内存了，只需要知道相对于这个内存地址的偏移即可。
> 2. 将其映射到`vaddr`对应的地址，注意，若实现中给定了内核映射的基址（map_base等），则要加上这个基址。
> 3. 如果`memsz > filesz`的话，将剩余的部分通过之前的栈帧分配器进行物理栈帧分配，并进行映射，然后填充 0.
>
> 进行物理页表映射方式是
>
> ```rust
> unsafe {
>      page_tables.map_to(page, frame, page_table_flags, frame_allocator).unwrap().flush();
> }
> ```
>
> 即将`page`映射到`frame`指向的物理栈帧，页的标识符（可写可读等标记位）是`page_table_flags`，使用的物理栈帧分配器是`frame_allocator`。
