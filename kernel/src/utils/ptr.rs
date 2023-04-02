//! A wrapper for raw pointer.

use core::ffi::CStr;

use alloc::string::{String, ToString};

use crate::{
    error::KResult,
    memory::{copy_from_user, copy_to_user},
};

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

    /// Reads from this pointer. If the pointer is invalid, an error will be reported.
    pub unsafe fn read(&self) -> KResult<T> {
        copy_from_user(self.ptr)
    }

    /// Writes to thie pointer.
    pub unsafe fn write(&self, data: T) -> KResult<()> {
        copy_to_user(&data as *const T, self.ptr)
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr as _
    }

    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Writes a Rust-style string into the buffer pointed by this pointer. Appends a null byte `\0` to the end
    /// of the target buffer area.
    ///
    /// # Safety
    ///
    /// Similar to other pointer-manipulating functions, this function is unsafe because there is no guarantee that
    /// the buffer pointed by this pointer is valid. Any incautios use of the function can cause undefined behavior.
    /// It is recommended that the caller always check the pointer before use.
    pub unsafe fn write_c_string(&self, src: &str) {
        (self.ptr as *mut u8).copy_from(src.as_ptr(), src.len());
        // Write a null byte to the end of the buffer.
        (self.ptr as *mut u8).add(src.len()).write(0u8);
    }

    /// Writes a byte array to the area pointed by this pointer.
    pub unsafe fn write_slice(&self, src: &[T]) {
        core::ptr::copy(src.as_ptr(), self.ptr, src.len());
    }
}

impl ToString for Ptr<u8> {
    /// Implements the `to_string` method for a pointer that points to a byte array. Note however, that this function
    /// assumes the pointer points to a canonical C-char array that ends with a null terminator `\0`.
    ///
    /// This function returns an empty string if the pointer is invalid.
    ///
    /// # Examples
    ///
    ///```
    /// let bytes = [0x41, 0x41, 0x41, 0x41, 0x0, 0x0, 0x0];
    /// let ptr = Ptr::<u8>::new_from_const(bytes.as_ptr());
    /// println!("{}", ptr.to_string());
    ///```
    fn to_string(&self) -> String {
        unsafe {
            CStr::from_ptr(self.ptr as _)
                .to_str()
                .unwrap_or_default()
                .to_string()
        }
    }
}
