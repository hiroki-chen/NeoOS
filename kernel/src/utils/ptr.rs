//! A wrapper for raw pointer.

use core::{ffi::CStr, marker::PhantomData};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    error::{Errno, KResult},
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
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ptr<T>
where
    T: Sized,
{
    ptr: u64,
    _marker: PhantomData<T>,
}

unsafe impl<T> Send for Ptr<T> {}
unsafe impl<T> Sync for Ptr<T> {}

impl<T> Ptr<T>
where
    T: Sized,
{
    /// Constructs a pointer wrapper from a given address.
    pub fn new(raw_ptr: u64) -> Self {
        Self {
            ptr: raw_ptr,
            _marker: PhantomData,
        }
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
        self.ptr == 0
    }

    pub unsafe fn add(&self, count: usize) -> Self {
        Self {
            ptr: self.ptr + (count * core::mem::size_of::<T>()) as u64,
            _marker: self._marker,
        }
    }

    /// Reads from this pointer. If the pointer is invalid, an error will be reported.
    pub unsafe fn read(&self) -> KResult<T> {
        copy_from_user(self.ptr as _)
    }

    /// Writes to thie pointer.
    pub unsafe fn write(&self, data: T) -> KResult<()> {
        copy_to_user(&data as *const T, self.ptr as _)
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr as _
    }

    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr as _
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
        core::ptr::copy(src.as_ptr(), self.ptr as _, src.len());
    }
}

impl Ptr<u8> {
    /// Reads a C-stryle string into the kernel and converts it to a Rust-style one.
    ///
    /// # Examples
    ///
    /// ```
    /// let ptr = 0xdeadbeef as *const u8;
    /// let s = Ptr::new(ptr as *mut u8).read_c_string().expect("failed to read!");
    /// ```
    pub fn read_c_string(&self) -> KResult<String> {
        let ptr = self.ptr as *const u8;
        if ptr.is_null() {
            Ok("".to_string())
        } else {
            let mut s = Vec::new();
            for i in 0.. {
                let byte = unsafe { copy_from_user(ptr.add(i)) }?;
                if byte == 0 {
                    break;
                }
                s.push(byte);
            }

            String::from_utf8(s).map_err(|_| Errno::EFAULT)
        }
    }

    /// Reads a C-stryle string array (i.e., const char* arr[]) into the kernel and converts it to a [`Vec<String>`].
    ///
    /// # Examples
    ///
    /// ```
    /// let ptr = 0xdeadbeef as *const u8;
    /// let s = Ptr::new(ptr as *mut u8).read_c_string_array().expect("failed to read!");
    /// println!("the array is {:?}", s);
    /// ```
    pub fn read_c_string_array(&self) -> KResult<Vec<String>> {
        if self.is_null() {
            return Ok(Vec::new());
        } else {
            let mut res = Vec::new();
            let ptr = self.ptr as *const *const u8;

            for i in 0.. {
                let str_ptr = unsafe { copy_from_user(ptr.add(i)) }?;
                if str_ptr.is_null() {
                    break;
                }
                res.push(Ptr::new(str_ptr as _).read_c_string()?);
            }

            Ok(res)
        }
    }
}

impl<T> Default for Ptr<T> {
    fn default() -> Self {
        Self {
            ptr: 0,
            _marker: PhantomData,
        }
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
