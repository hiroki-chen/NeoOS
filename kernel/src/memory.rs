//! This module manages the kernel memory as well as the user space memory.
//!
//! Below is the memory layout of the Linux kernel.
//!
//! ```text
//! =============================================================================================
//! Start addr    |   Offset   |     End addr     |  Size   | VM area description
//! =============================================================================================
//!                   |            |                  |         |
//!  0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory
//! __________________|____________|__________________|_________|________________________________
//!                   |            |                  |         |
//!  0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | huge, almost 64 bits wide hole of non-canonical
//!                   |            |                  |         | virtual memory addresses up to the -128 TB
//!                   |            |                  |         | starting offset of kernel mappings.
//! __________________|____________|__________________|_________|________________________________
//!                                                             |
//!                                                             | Kernel-space virtual memory,
//!                                                             | shared between *all* processes:
//! ____________________________________________________________|________________________________
//!                   |            |                  |         |
//!  ffff800000000000 | -128    TB | ffff87ffffffffff |    8 TB | ... guard hole, also reserved for hypervisor
//!  ffff880000000000 | -120    TB | ffff887fffffffff |  0.5 TB | LDT remap for PTI
//!  ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
//!  ffffc88000000000 |  -55.5  TB | ffffc8ffffffffff |  0.5 TB | ... unused hole
//!  ffffc90000000000 |  -55    TB | ffffe8ffffffffff |   32 TB | vmalloc/ioremap space (vmalloc_base)
//!  ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
//!  ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
//!  ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
//!  ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
//! ==================|============|==================|=========|================================
//! ```

use bit_field::BitField;
use core::{ffi::c_void, fmt::Debug, ops::Range, sync::atomic::Ordering};
use num_traits::AsPrimitive;

use crate::{
    arch::{
        mm::paging::{KernelPageTable, PageTableBehaviors},
        KERNEL_BASE, KERNEL_HEAP_SIZE, PAGE_MASK, PAGE_SIZE, PHYSICAL_MEMORY_START, USER_MEM_TOP,
    },
    error::{Errno, KResult},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};
use alloc::{
    alloc::{alloc, dealloc, Layout},
    boxed::Box,
    vec::Vec,
};

use buddy_system_allocator::Heap;
use x86_64::{PhysAddr, VirtAddr};

pub const USER_STACK_SIZE: usize = 0x0040_0000;
pub const USER_STACK_START: usize = 0x0000_8000_0000_0000 - USER_STACK_SIZE;
pub const HEAP_UNIT: usize = 0x4000;
pub const BITMAP_SIZE: usize = 256_000_000usize;
pub const ELF_DEFAULT_ENTRY: u64 = 0x400000;
/// The locked frame allocator for user-space processes.
pub static LOCKED_FRAME_ALLOCATOR: Mutex<Chunk256MiB> = Mutex::new(Chunk256MiB::DEFAULT);

/// Expose the interface into user space.
#[inline(never)]
#[link_section = ".text.copy_user"]
unsafe extern "C" fn __copy_from_user<T>(dst: *mut T, src: *const T) -> usize {
    dst.copy_from_nonoverlapping(src, 1);
    0
}

/// Expose the interface into user space.
#[inline(never)]
#[link_section = ".text.copy_user"]
unsafe extern "C" fn __copy_to_user<T>(dst: *mut T, src: *const T) -> usize {
    dst.copy_from_nonoverlapping(src, 1);
    0
}

/// Allows user application to track memory allocation.
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn mmap_hook() {}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn brk_hook() {}

/// A helper function for bitmap allocation that finds a contiguous free memory region given `size`.
fn find_contiguous(
    ba: &impl BitMapAlloc,
    capacity: usize,
    size: usize,
    align_log2: usize,
) -> KResult<usize> {
    if capacity < (1 << align_log2) || ba.is_empty() {
        return Err(Errno::ENOMEM);
    }
    let mut base = 0;
    let mut offset = base;
    while offset < capacity {
        if let Ok(next) = ba.next(offset) {
            if next != offset {
                // it can be guarenteed that no bit in (offset..next) is free
                // move to next aligned position after next-1
                assert!(next > offset, "find_contiguous(): sanity check failed.");
                base = (((next - 1) >> align_log2) + 1) << align_log2;
                assert_ne!(offset, next, "find_contiguous(): sanity check failed.");
                offset = base;
                continue;
            }
        } else {
            return Err(Errno::EINVAL);
        }
        offset += 1;
        if offset - base == size {
            return Ok(base);
        }
    }

    Err(Errno::ENOMEM)
}

/// Implements the bitmap allocation.
pub trait BitMapAlloc: Default {
    /// The bitmap has a total of CAP bits, numbered from 0 to CAP-1 inclusively.
    const CAPBILITY: usize;
    /// Hack for non-const `new` functions while we intend to initialize a trait statically.
    const DEFAULT: Self;
    /// Allocate a free bit.
    fn alloc(&mut self) -> KResult<usize>;

    /// Allocate a free block with a given size, and return the first bit position.
    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> KResult<usize>;

    /// Find a index not less than a given key, where the bit is free.
    fn next(&self, key: usize) -> KResult<usize>;

    /// Free an allocated bit.
    fn dealloc(&mut self, key: usize) -> KResult<()>;

    /// Mark bits in the range as unallocated (available)
    fn insert(&mut self, range: Range<usize>) -> KResult<()>;

    /// Reverse of insert
    fn remove(&mut self, range: Range<usize>) -> KResult<()>;

    /// Returns true if it is empty.
    fn is_empty(&self) -> bool;

    /// Gets the correpsonding bit.
    fn get_bit(&self, key: usize) -> bool;
}

/// Implement the bit allocator by segment tree algorithm. This allocator is used to support user-space memory allocations.
/// Ported from rCore.
#[derive(Default)]
pub struct BitAllocUnit<T>
where
    T: BitMapAlloc,
{
    bitset: u16, // for each bit, 1 indicates available, 0 indicates inavailable
    sub: [T; 16],
}

/// A bitmap consisting of only 16 bits => the minimal one.
/// BitAlloc16 acts as the leaf (except the leaf bits of course) nodes in the segment trees.
/// An adaptive port of <https://github.com/rcore-os/bitmap-allocator/blob/main/src/lib.rs>
#[derive(Default)]
pub struct BitAlloc16bit(u16);

impl BitMapAlloc for BitAlloc16bit {
    const CAPBILITY: usize = u16::BITS as usize;
    const DEFAULT: Self = Self(0);

    fn alloc(&mut self) -> KResult<usize> {
        let i = self.0.trailing_zeros() as usize;
        if i < Self::CAPBILITY {
            self.0.set_bit(i, false);
            Ok(i)
        } else {
            Err(Errno::ENOMEM)
        }
    }

    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> KResult<usize> {
        find_contiguous(self, Self::CAPBILITY, size, align_log2).map(|base| {
            self.remove(base..base + size).unwrap();
            base
        })
    }

    fn dealloc(&mut self, key: usize) -> KResult<()> {
        // Check if the bit is set.
        match self.0.get_bit(key) {
            true => Err(Errno::EINVAL),
            false => {
                // Free this bit.
                self.0.set_bit(key, true);

                Ok(())
            }
        }
    }

    fn insert(&mut self, range: Range<usize>) -> KResult<()> {
        self.0.set_bits(range.clone(), 0xffff.get_bits(range));
        Ok(())
    }

    fn next(&self, key: usize) -> KResult<usize> {
        match (key..Self::CAPBILITY).find(|&i| self.0.get_bit(i)) {
            Some(v) => Ok(v),
            None => Err(Errno::ENOMEM),
        }
    }

    fn remove(&mut self, range: Range<usize>) -> KResult<()> {
        self.0.set_bits(range, 0);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn get_bit(&self, key: usize) -> bool {
        self.0.get_bit(key)
    }
}

impl<T> BitAllocUnit<T>
where
    T: BitMapAlloc,
{
    fn for_range(&mut self, range: Range<usize>, f: impl Fn(&mut T, Range<usize>)) -> KResult<()> {
        let start = range.start;
        let end = range.end;

        if start > end || end > Self::CAPBILITY {
            return Err(Errno::EINVAL);
        }

        for i in start / T::CAPBILITY..=(end - 1) / T::CAPBILITY {
            let begin = if start / T::CAPBILITY == i {
                start % T::CAPBILITY
            } else {
                0
            };
            let end = if end / T::CAPBILITY == i {
                end % T::CAPBILITY
            } else {
                T::CAPBILITY
            };
            f(&mut self.sub[i], begin..end);
            self.bitset.set_bit(i, !self.sub[i].is_empty());
        }

        Ok(())
    }
}

impl<T> BitMapAlloc for BitAllocUnit<T>
where
    T: BitMapAlloc,
{
    const CAPBILITY: usize = 0x10 * T::CAPBILITY;
    const DEFAULT: Self = Self {
        bitset: 0,
        sub: [T::DEFAULT; 16],
    };

    fn alloc(&mut self) -> KResult<usize> {
        match self.is_empty() {
            false => {
                let i = self.bitset.trailing_zeros() as usize;
                let res = self.sub[i].alloc().unwrap() + i * T::CAPBILITY;
                self.bitset.set_bit(i, !self.sub[i].is_empty());
                Ok(res)
            }
            true => Err(Errno::ENOMEM),
        }
    }

    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> KResult<usize> {
        find_contiguous(self, Self::CAPBILITY, size, align_log2).map(|base| {
            self.remove(base..base + size).unwrap();
            base
        })
    }

    fn dealloc(&mut self, key: usize) -> KResult<()> {
        let i = key / T::CAPBILITY;
        self.sub[i].dealloc(key % T::CAPBILITY)?;
        self.bitset.set_bit(i, true);

        Ok(())
    }

    fn insert(&mut self, range: Range<usize>) -> KResult<()> {
        self.for_range(range, |sub: &mut T, range| sub.insert(range).unwrap())
    }

    fn next(&self, key: usize) -> KResult<usize> {
        let idx = key / T::CAPBILITY;

        match (idx..16).find(|i| self.bitset.get_bit(*i)) {
            Some(i) => {
                let key = if i == idx {
                    key - T::CAPBILITY * idx
                } else {
                    0
                };
                self.sub[i].next(key).map(|x| x + T::CAPBILITY * i)
            }
            None => Err(Errno::ENOMEM),
        }
    }

    fn remove(&mut self, range: Range<usize>) -> KResult<()> {
        self.for_range(range, |sub: &mut T, range| sub.remove(range).unwrap())
    }

    fn is_empty(&self) -> bool {
        self.bitset == 0
    }

    fn get_bit(&self, key: usize) -> bool {
        self.sub[key / T::CAPBILITY].get_bit(key % T::CAPBILITY)
    }
}

// A sequence of chunks managed by the bitmap. The minimal unit is 16 bits.
/// A bitmap of 256 bits
pub type Chunk256bit = BitAllocUnit<BitAlloc16bit>;
/// A bitmap of 4K bits
pub type Chunk4KiB = BitAllocUnit<Chunk256bit>;
/// A bitmap of 64K bits
pub type Chunk64KiB = BitAllocUnit<Chunk4KiB>;
/// A bitmap of 1M bits
pub type Chunk1MiB = BitAllocUnit<Chunk64KiB>;
/// A bitmap of 16M bits
pub type Chunk16MiB = BitAllocUnit<Chunk1MiB>;
/// A bitmap of 256M bits
pub type Chunk256MiB = BitAllocUnit<Chunk16MiB>;

/// The kernel frame allocator.
#[derive(Debug, Clone)]
pub struct KernelFrameAllocator;

pub trait FrameAlloc: Debug + Clone + Send + Sync + 'static {
    /// Allocates a physical frame and returns it virtual address.
    fn alloc(&self) -> KResult<PhysAddr>;
    /// Allocates a contiguous physical memory and returns the start virtual address.
    fn alloc_contiguous(&self, size: usize, align_log2: usize) -> KResult<PhysAddr>;
    /// Decalloate the given physical address.
    fn dealloc(&self, addr: u64) -> KResult<()>;
}

impl FrameAlloc for KernelFrameAllocator {
    fn alloc(&self) -> KResult<PhysAddr> {
        LOCKED_FRAME_ALLOCATOR
            .lock()
            .alloc()
            .map(|v| PhysAddr::new(v as u64 * PAGE_SIZE as u64))
    }

    fn alloc_contiguous(&self, size: usize, align_log2: usize) -> KResult<PhysAddr> {
        LOCKED_FRAME_ALLOCATOR
            .lock()
            .alloc_contiguous(size, align_log2)
            .map(|v| PhysAddr::new(v as u64 * PAGE_SIZE as u64))
    }

    fn dealloc(&self, addr: u64) -> KResult<()> {
        LOCKED_FRAME_ALLOCATOR
            .lock()
            .dealloc((addr / PAGE_SIZE as u64) as usize)
    }
}

#[inline(always)]
pub const fn phys_to_virt(phys: u64) -> u64 {
    phys + PHYSICAL_MEMORY_START
}

#[inline(always)]
pub const fn virt_to_phys(virt: u64) -> u64 {
    virt - PHYSICAL_MEMORY_START
}

pub const fn offset_from_kernel_base(virt: u64) -> u64 {
    virt - KERNEL_BASE
}

/// The memory can be used only after we have initialized the heap!
pub fn init_heap() -> usize {
    const MACHINE_ALIGN: usize = core::mem::size_of::<usize>();
    const HEAP_BLOCK: usize = KERNEL_HEAP_SIZE / MACHINE_ALIGN;
    static mut HEAP: [usize; HEAP_BLOCK] = [0; HEAP_BLOCK];

    unsafe {
        // Initialize the heap.
        super::ALLOCATOR
            .lock()
            .init(HEAP.as_ptr() as usize, HEAP_BLOCK * MACHINE_ALIGN);
        HEAP.as_ptr() as usize
    }
}

/// When OOM occurs, we try to grow the heap to prevent the kernel from panicking.
pub fn grow_heap_on_oom(mem: &mut Heap<32>, layout: &core::alloc::Layout) {
    kinfo!(
        "grow_heap_on_oom(): Heap is OOM at {:?}. Trying to grow the heap.",
        layout
    );

    let mut addrs = [(0, 0); 32];
    let mut addr_len = 0;
    for _i in 0..0x4000 {
        let page = KernelFrameAllocator.alloc().unwrap();
        let virtual_addr = page + PHYSICAL_MEMORY_START;
        addrs[addr_len] = (virtual_addr.as_u64(), PAGE_SIZE);
        addr_len += 1;
    }

    // TODO: Need an OOM killer for this function so that the kernel won't panic.

    for (addr, len) in addrs[..addr_len].iter() {
        kinfo!(
            "grow_heap_on_oom(): created {:#x} with length {:#x}",
            addr,
            len
        );
        unsafe {
            mem.init(*addr as usize, *len);
        }
    }
}

/// Allocate the kernel stack from the heap.
/// The kernel stack is used by the kernel to store a variety of data, including the current
/// state of the process, the parameters of a function call, and the return address when a
/// function is called. This allows the kernel to manage the execution of processes and to
/// switch between them efficiently.
///
/// Note that this kernel stack is allocated for *each process*.
///
/// There is another `kernel_stack` which is used for the kernel itself and initialized upon
/// boot. See `boot.cfg` under `esp/efi/boot/boot.cfg`.
pub struct KernelStack(usize);
pub const STACK_SIZE: usize = 0x8000;
impl KernelStack {
    pub fn new() -> Self {
        let kernel_bottom =
            unsafe { alloc(Layout::from_size_align(STACK_SIZE, STACK_SIZE).unwrap()) } as usize;

        Self(kernel_bottom)
    }

    /// Returns the current stack top.
    pub fn top(&self) -> usize {
        self.0 + STACK_SIZE
    }
}

/// Automatically reclaim the stack into the heap.
impl Drop for KernelStack {
    fn drop(&mut self) {
        unsafe {
            dealloc(
                self.0 as *mut u8,
                Layout::from_size_align(STACK_SIZE, STACK_SIZE).unwrap(),
            );
        }
    }
}

/// Checks whether the given address is within the kernel stack.
#[inline(always)]
pub fn check_within_stack(bp: u64) -> bool {
    (0xFFFF_FFFF_F000_0000..=0xFFFF_FFFF_F000_0000 + 512 * PAGE_SIZE as u64).contains(&bp)
}

/// Checks whether the given memory region is within the kernel memory space.
#[inline(always)]
pub fn check_within_kernel(addr: u64, size: usize) -> bool {
    !(addr < USER_MEM_TOP && (addr + size as u64) < USER_MEM_TOP)
}

/// Checks whether the given memory region is within the user space (0x0 - 0xffff7fffffffffff) below kernel space.
#[inline(always)]
pub fn check_within_user(addr: u64, size: usize) -> bool {
    addr < PHYSICAL_MEMORY_START && (addr + size as u64) < PHYSICAL_MEMORY_START
}

/// Copies a buffer from the user space into kernel space. This is useful for kernel modules / drivers.
///
/// # Safety
///
/// This function is unsafe because it requires that the kernel reads a valid data from a given pointer. Even though
/// this function checks the pointer address is within the thread's virtual memory, there is no guarantee that the
/// data read from the user thread is always valid at all.
pub unsafe fn copy_from_user<T>(src: *const T) -> KResult<T> {
    // Check the memory address first.
    let addr = src as u64;
    if !check_within_user(addr, core::mem::size_of::<T>()) {
        return Err(Errno::ERANGE);
    }

    // Copy from user.
    let mut kern_repr = core::mem::MaybeUninit::<T>::zeroed();
    let ret = __copy_from_user::<T>(kern_repr.as_mut_ptr(), src);
    match ret {
        0 => Ok(kern_repr.assume_init()),
        _ => Err(Errno::EFAULT),
    }
}

/// Copies a buffer to the user space into kernel space. This is useful for kernel modules / drivers.
///
/// # Safety
///
/// Similar to [`copy_from_user`], this function is unsafe because we require that the user thread does not always read
/// valid data from the kernel even though the input pointers are valid.
pub unsafe fn copy_to_user<T>(src: *const T, dst: *mut T) -> KResult<()> {
    // Check the memory address first.
    let kern_addr = src as u64;
    let user_addr = dst as u64;
    let size = core::mem::size_of::<T>();
    if !check_within_kernel(kern_addr, size) || !check_within_user(user_addr, size) {
        return Err(Errno::ERANGE);
    }

    // Copy into user.
    let ret = __copy_to_user::<T>(dst, src);
    match ret {
        0 => Ok(()),
        _ => Err(Errno::EFAULT),
    }
}

/// Checks whether the lower 3 bits are zero.
#[inline]
pub fn is_page_aligned<T>(num: T) -> bool
where
    T: AsPrimitive<usize>,
{
    num.as_() & !PAGE_MASK == 0
}

/// Ignores the lower bits of 0xfff.
#[inline]
pub fn page_mask<T>(num: T) -> T
where
    T: AsPrimitive<usize>,
    usize: AsPrimitive<T>,
{
    (num.as_() & !PAGE_MASK).as_()
}

/// Extract the page frame number.
#[inline]
pub fn page_frame_number<T>(addr: T) -> T
where
    T: AsPrimitive<usize>,
    usize: AsPrimitive<T>,
{
    (addr.as_() & PAGE_MASK).as_()
}

/// Asks the [`KernelFrameAllocator`] to allocate exactly one physical frame for storing the data.
///
/// The caller may need to map the physical frame to a valid virtual address.
pub fn allocate_frame() -> KResult<PhysAddr> {
    KernelFrameAllocator.alloc()
}

/// Asks the [`KernelFrameAllocator`] to allocate exactly a continuous area of physical frames for storing the data.
/// Also, the caller can choose an appropriate value of `align_log2` that indicates the alignment of the physical frame.
///
/// The caller may need to map the physical frame to a valid virtual address.
pub fn allocate_frame_contiguous(size: usize, align_log2: usize) -> KResult<PhysAddr> {
    KernelFrameAllocator.alloc_contiguous(size, align_log2)
}

/// Drops a physical frame and adds it to the bitmap. An invalid input is allowed.
pub fn deallocate_frame(addr: u64) -> KResult<()> {
    KernelFrameAllocator.dealloc(addr)
}

/// kmalloc: Allocate heap from kernel memory. This function ensures that we always return
/// a contiguous *physical* memory region.
///
/// # Safety
///
/// This function is unsafe because the allocator must ensure that the memory is dropped.
///
/// # Examples
///
/// ```rust
/// let ptr = kmalloc(0x1000).expect("kmalloc(): memory allocation failed!");
/// unsafe {
///     core::ptr::write_bytes(ptr, 1u8, 0x1000);
/// }
/// ```
pub unsafe fn kmalloc(size: usize) -> KResult<*mut u8> {
    if size >= 0x0001_0000 {
        Err(Errno::ENOMEM)
    } else {
        // Allocate and leak it.
        let mut mem = Vec::with_capacity(size);
        mem.fill(0u8);
        let mem = Vec::leak(mem);

        Ok(mem.as_mut_ptr())
    }
}

pub unsafe fn kfree(ptr: *mut u8) {
    unimplemented!()
}

/// Unlike [`virt_to_phys`], this function converts non-linear mapping into a physical address by page table walking.
///
/// If you have an address that does not belong to the physical mapping area (e.g., you want to determine the
/// physical address of an instruction in the kernel space), you must ask this function for the physical address.
///
/// Note however, that this function can only called if you have set a valid page table.
///
/// # Examples
///
/// ```rust
/// let inst_addr = some_function as u64;
/// let phys_addr = get_physical_address(inst_addr);
///
/// println!("addr: {:#x}", phys_addr);
/// ```
pub fn get_physical_address(virt: u64) -> u64 {
    KernelPageTable::active()
        .get_entry_with(VirtAddr::new(virt), Box::new(|_| {}))
        .unwrap()
        .phys_addr()
        .as_u64()
}

/// Dangerous operation: Read something typed `T` from a given raw pointer at `offset`. This function does not
/// create any copy of the raw pointer and just reads the untouched memory region, which is different from the
/// pointer read operation [`core::ptr::read`].
///
/// One may find this function helpful in case when there is need to access some C/C++/Rust struct but in raw
/// formats like u8 array.
///
/// Just note that the pointer `ptr` does not require to be aligned.
///
/// # Safety
///
/// This function requires that:
/// * The pointer itself points to a valid address
/// * The offset must not exceed the length of the object `ptr` represents
/// * The type `T` is statically sized; in other words, you must ensure there is *no* fat pointer.
///   For example, [`u64`] is statically sized, and so is function pointer, but things like `dyn Trait`
///   are not since they must be stored within a [`alloc::boxed::Box`] due to heap allocations.
///
/// # Examples
///
/// ```rust
/// let ptr = 0xdeadbeef;
/// let data: Vec<u8> = unsafe {
///     kernel::memory::read_at(ptr as *const _, 0x0)
/// };
///
/// println!("{:?}", data);
/// ```
#[cfg(target_pointer_width = "64")]
pub unsafe fn read_at<T>(ptr: *const c_void, offset: usize) -> &'static T
where
    T: 'static + Sized,
{
    if ptr as usize % core::mem::size_of::<u64>() != 0 {
        kwarn!(
            "read_at(): trying to read pointer address at {:#x} because it is not aligned; this may cause unwanted results.",
            ptr as u64
        );
    }

    &*(ptr.add(offset) as *const T)
}

/// A C/C++ like `memset` function with the constraint that this operation is memory-ordered according to `ordering`.
///
/// For ordering, only three orderings are sane:
/// * [`Ordering::Relaxed`]
/// * [`Ordering::Release`]
/// * [`Ordering::SeqCst`]
///
/// Why do we need this function instead of using [`core::ptr::write_bytes`]? This is because the memset-like function
/// [`core::ptr::write_bytes`] provided by the core library does not give us the guarantee that the memory is ordered.
/// Although unordered memory read/write does not affect the result of single-threaded programs. There would be, however,
/// synchronization problems with multiple cores.
///
/// Any other orderings are ignored and converted to `unordered`.
///
/// # Safety
///
/// This function is unsafe because we have no guarantee that `ptr` points to a valid memory region; it is the caller's
/// responsibility to check this address is valid.
///
/// # Examples
///
/// ```rust
/// let ptr = 0xdeadbeef;
///
/// ap_start(); // From this timepoint, other cores are awake.
///
/// unsafe {
///     kernel::memory::atomic_memset::<ApHeader>(ptr as *const _, 0u8, core::sync::atomic::Ordering::SeqCst);
/// }
/// ```
pub unsafe fn atomic_memset<T>(ptr: *const c_void, val: u8, ordering: Ordering)
where
    T: 'static + Sized,
{
    let len = core::mem::size_of::<T>();
    (0..len).for_each(|idx| match ordering {
        Ordering::Relaxed => {
            core::intrinsics::atomic_store_relaxed((ptr as *mut u8).add(idx), val);
        }
        Ordering::Release => {
            core::intrinsics::atomic_store_release((ptr as *mut u8).add(idx), val);
        }
        Ordering::SeqCst => {
            core::intrinsics::atomic_store_seqcst((ptr as *mut u8).add(idx), val);
        }
        _ => {
            core::intrinsics::atomic_store_unordered((ptr as *mut u8).add(idx), val);
        }
    });
}

/// Fast conversion from numerics to VirtAddr.
#[macro_export]
#[cfg(target_pointer_width = "64")]
macro_rules! virt {
    ($e:expr) => {
        x86_64::VirtAddr::new(($e) as u64)
    };
    () => {
        x86_64::VirtAddr::new(0u64)
    };
}

/// Fast conversion from numerics to PhysAddr.
#[macro_export]
#[cfg(target_pointer_width = "64")]
macro_rules! phys {
    ($e:expr) => {
        x86_64::PhysAddr::new(($e) as u64)
    };
    () => {
        x86_64::PhysAddr::new(0)
    };
}

/// Fast conversion from numerics to Frames.
#[macro_export]
#[cfg(target_pointer_width = "64")]
macro_rules! frame {
    ($e:expr) => {
        x86_64::structures::paging::frame::PhysFrame::
            <x86_64::structures::paging::page::Size4KiB>::containing_address(phys!($e))
    };
    () => {
        x86_64::structures::paging::frame::PhysFrame::
            <x86_64::structures::paging::page::Size4KiB>::containing_address(phys!())
    }
}

/// Fast conversion from numerics to pages.
#[macro_export]
#[cfg(target_pointer_width = "64")]
macro_rules! page {
    ($e:expr) => {
        x86_64::structures::paging::page::Page::
            <x86_64::structures::paging::page::Size4KiB>::containing_address(virt!($e))
    };
    () => {
        x86_64::structures::paging::page::Page::
            <x86_64::structures::paging::page::Size4KiB>::containing_address(virt!())
    }
}
