//! A wrapper for raw pointer.

/// A workaround for sending and syncing raw pointers between different threads because compile rejects sending something
/// like `*const c_void` to another thread, although, in fact, it is safe to do so.
///
/// This struct eliminates the annoying compiler error.
///
/// # Examples
///
/// ```
/// let mut v = vec![1, 2, 3];
/// let ptr = Ptr::new(v.as_mut_ptr());
///
/// // You can play with the pointer.
/// let res = some_async_function(ptr).await;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct Ptr<T> {
    ptr: *mut T,
}

unsafe impl<T> Send for Ptr<T> {}
unsafe impl<T> Sync for Ptr<T> {}

impl<T> Ptr<T> {
    /// Constructs a mutable pointer wrapper from a mutable pointer.
    pub fn new(raw_ptr: *mut T) -> Self {
        Self { ptr: raw_ptr }
    }

    /// Constructs a mutable pointer wrapper from a *const* pointer.
    ///
    /// # Safety
    ///
    /// This function is unsafe because we assume the internal immutability *can* be broken; or the caller knows that
    /// the reference is mutable, although marked as `const`. Note however, that this function provideds no guarantee
    /// that the data behind the pointer is valid or can be modified by this wrapper.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = vec![1, 2, 3];
    /// let ptr = unsafe { Ptr::new_with_const(v.as_ptr()) };
    /// ```
    pub unsafe fn new_with_const(raw_ptr: *const T) -> Self {
        Self::new(raw_ptr as *mut _)
    }

    /// Returns `true` if the pointer is null.
    ///
    /// Note that unsized types have many possible null pointers, as only the
    /// raw data pointer is considered, not their length, vtable, etc.
    /// Therefore, two pointers that are null may still not compare equal to
    /// each other.
    ///
    /// ## Behavior during const evaluation
    ///
    /// When this function is used during const evaluation, it may return `false` for pointers
    /// that turn out to be null at runtime. Specifically, when a pointer to some memory
    /// is offset beyond its bounds in such a way that the resulting pointer is null,
    /// the function will still return `false`. There is no way for CTFE to know
    /// the absolute position of that memory, so we cannot tell if the pointer is
    /// null or not.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut s = [1, 2, 3];
    /// let ptr = Ptr::new(s.as_mut_ptr());
    /// assert!(!ptr.is_null());
    /// ```
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    pub unsafe fn add(&self, count: usize) -> Self {
        Self {
            ptr: self.ptr.add(count),
        }
    }

    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}
