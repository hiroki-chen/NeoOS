use alloc::alloc::{GlobalAlloc, Layout};

/// Safe and simple drop-in allocator for Rust running on embedded or bare metal systems (`no_std`)
/// The buddy memory allocation technique is a memory allocation algorithm that divides memory into
/// partitions to try to satisfy a memory request as suitably as possible.
///
/// # Safety
/// This allocator will use a `RwLock` and `Mutex` to protect the memory region.
pub struct BuddyAllocator {}

unsafe impl GlobalAlloc for BuddyAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        todo!()
    }

    unsafe fn alloc_zeroed(&self, _layout: Layout) -> *mut u8 {
        todo!()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        todo!()
    }

    unsafe fn realloc(&self, _ptr: *mut u8, _layout: Layout, _new_size: usize) -> *mut u8 {
        todo!()
    }
}
