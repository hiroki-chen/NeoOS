use core::ops::Range;

use crate::{
    arch::{KERNEL_BASE, KERNEL_HEAP_SIZE, PHYSICAL_MEMORY_START},
    sync::mutex::SpinLockNoInterrupt,
};
use alloc::alloc::{GlobalAlloc, Layout};
use buddy_system_allocator::Heap;
use x86_64::VirtAddr;

/// Must create an instance statically.

pub const HEAP_UNIT: usize = 0x4000;
pub const BITMAP_SIZE: usize = 256_000_000usize;
pub static LOCKED_FRAME_ALLOCATOR: SpinLockNoInterrupt<Chunk256MiB> =
    SpinLockNoInterrupt::new(Chunk256MiB::DEFAULT);

/// Implements the bitmap allocation.
pub trait BitMapAlloc: Default {
    const DEFAULT: Self;
    /// Allocate a free bit.
    fn alloc(&mut self) -> Option<usize>;

    /// Allocate a free block with a given size, and return the first bit position.
    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> Option<usize>;

    /// Find a index not less than a given key, where the bit is free.
    fn next(&self, key: usize) -> Option<usize>;

    /// Free an allocated bit.
    fn dealloc(&mut self, key: usize);

    /// Mark bits in the range as unallocated (available)
    fn insert(&mut self, range: Range<usize>);

    /// Reverse of insert
    fn remove(&mut self, range: Range<usize>);
}

/// Implement the bit allocator by segment tree algorithm.
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
#[derive(Default)]
pub struct BitAlloc16bit(u16);

impl BitMapAlloc for BitAlloc16bit {
    const DEFAULT: Self = Self(0);

    fn alloc(&mut self) -> Option<usize> {
        todo!()
    }

    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> Option<usize> {
        todo!()
    }

    fn dealloc(&mut self, key: usize) {
        todo!()
    }

    fn insert(&mut self, range: Range<usize>) {
        todo!()
    }

    fn next(&self, key: usize) -> Option<usize> {
        todo!()
    }

    fn remove(&mut self, range: Range<usize>) {
        todo!()
    }
}

impl<T> BitMapAlloc for BitAllocUnit<T>
where
    T: BitMapAlloc,
{
    const DEFAULT: Self = Self {
        bitset: 0,
        sub: [T::DEFAULT; 16],
    };

    fn alloc(&mut self) -> Option<usize> {
        todo!()
    }

    fn alloc_contiguous(&mut self, size: usize, align_log2: usize) -> Option<usize> {
        todo!()
    }

    fn dealloc(&mut self, key: usize) {
        todo!()
    }

    fn insert(&mut self, range: Range<usize>) {
        todo!()
    }

    fn next(&self, key: usize) -> Option<usize> {
        todo!()
    }

    fn remove(&mut self, range: Range<usize>) {
        todo!()
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
#[derive(Debug)]
pub struct KernelFrameAllocator;

pub trait FrameAlloc {
    /// Allocates a physical frame and returns it virtual address.
    fn alloc(&self) -> Option<VirtAddr>;
    /// Allocates a contiguous physical memory and returns the start virtual address.
    fn alloc_contiguous(&self, size: usize) -> Option<VirtAddr>;
    /// Decalloate the given virtual address.
    fn dealloc(&self, addr: u64);
}

impl FrameAlloc for KernelFrameAllocator {
    fn alloc(&self) -> Option<VirtAddr> {
        // let ret = VirtAddr::new(
        // LOCKED_FRAME_ALLOCATOR.lock().
        // );

        todo!()
    }

    fn alloc_contiguous(&self, size: usize) -> Option<VirtAddr> {
        todo!()
    }

    fn dealloc(&self, addr: u64) {
        todo!()
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
pub fn init_heap() {
    const MACHINE_ALIGN: usize = core::mem::size_of::<usize>();
    const HEAP_BLOCK: usize = KERNEL_HEAP_SIZE / MACHINE_ALIGN;
    static mut HEAP: [usize; HEAP_BLOCK] = [0; HEAP_BLOCK];

    unsafe {
        // Initialize the heap.
        super::ALLOCATOR
            .lock()
            .init(HEAP.as_ptr() as usize, HEAP_BLOCK * MACHINE_ALIGN);
    }
}

/// When OOM occurs, we try to grow the heap to prevent the kernel from panicking.
pub fn grow_heap_on_oom(mem: &mut Heap<32>, _layout: &core::alloc::Layout) {
    todo!()
}

/// Safe and simple drop-in allocator for Rust running on embedded or bare metal systems (`no_std`)
/// The buddy memory allocation technique is a memory allocation algorithm that divides memory into
/// partitions to try to satisfy a memory request as suitably as possible.
///
/// # Safety
/// This allocator will use a `Mutex` to protect the memory region.
pub struct BuddyAllocator {}

unsafe impl GlobalAlloc for BuddyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        todo!()
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        todo!()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        todo!()
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        todo!()
    }
}

/// Allocate the kernel stack from the heap.
pub struct KernelStack(usize);
pub const STACK_SIZE: usize = 0x8000;
impl KernelStack {
    pub fn new() -> Self {
        let kernel_bottom = unsafe {
            use alloc::alloc;
            alloc::alloc(alloc::Layout::from_size_align(STACK_SIZE, STACK_SIZE).unwrap())
        } as usize;

        Self(kernel_bottom)
    }

    /// Returns the current stack top.
    pub fn top(&self) -> usize {
        self.0 + STACK_SIZE
    }
}
