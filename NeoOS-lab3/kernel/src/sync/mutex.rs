//! Reference: https://docs.rs/spin/0.5.2/spin/struct.Mutex.html

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::cpu::cpu_id;
use crate::arch::interrupt;

use atomic_enum::atomic_enum;
use log::error;

pub const MAX_LOCK_ATTEMPT: usize = 0x100000;

#[atomic_enum]
enum MutexStatus {
    Uninitialized,
    Initializing,
    Initialized,
}

pub type SpinLock<T> = Mutex<T, Spin>;
pub type SpinLockNoInterrupt<T> = Mutex<T, SpinNoInterrupt>;

unsafe impl<T: ?Sized + Send, S: MutexSupport> Sync for Mutex<T, S> {}

pub trait MutexSupport {
    type GuardData;

    fn new() -> Self;

    /// A strategy that rapidly spins while informing the CPU that it should power down non-essential components.
    /// Performs the relaxing operation during a period of contention.
    fn cpu_relax(&self) {
        // The spin loop is a hint to the CPU that we're waiting, but probably
        // not for very long.
        core::hint::spin_loop();
    }

    /// Disables interrupt when you tries to obtain the lock.
    /// Kernel-side locks, such as `SpinLock`s do indeed block interrupts (on that processor core) to ensure that
    /// other processes/threads do not get scheduled during this process.
    fn lock_prologue() -> Self::GuardData;

    /// Releases when `MutexGuard` drops itself.
    fn lock_epilogue(&self);
}

/// The implementation of `SpinLock`.
pub struct Spin;
/// Spin lock that masks all interrupts.
pub struct SpinNoInterrupt;

impl MutexSupport for Spin {
    type GuardData = PhantomData<()>;
    fn new() -> Self {
        Self
    }

    fn lock_prologue() -> Self::GuardData {
        PhantomData
    }

    fn lock_epilogue(&self) {}
}

impl MutexSupport for SpinNoInterrupt {
    type GuardData = FlagsGuard;
    fn new() -> Self {
        Self
    }

    fn lock_prologue() -> Self::GuardData {
        FlagsGuard {
            flags: unsafe { interrupt::disable_and_store() },
        }
    }

    fn lock_epilogue(&self) {
        // Notify.
    }
}

pub struct MutexGuard<'a, T: ?Sized + 'a, S: MutexSupport + 'a> {
    pub(super) mutex: &'a Mutex<T, S>,

    #[allow(unused)]
    guard: S::GuardData,
}

/// Contains RFLAGS before disable interrupt, will auto restore it when dropping
pub struct FlagsGuard {
    flags: usize,
}

/// A generic type for mutual exclusive variable. We use the spin lock to implement it.
/// The low-level implementation is wrapped within `MutexSupport`.
pub struct Mutex<T: ?Sized, S: MutexSupport> {
    lock: AtomicBool,
    support: MaybeUninit<S>,
    // 0 = uninitialized, 1 = initializing, 2 = initialized
    support_initialization: MutexStatus,
    user: UnsafeCell<(usize, usize)>, // (cid, tid)
    data: UnsafeCell<T>,
}

impl Drop for FlagsGuard {
    fn drop(&mut self) {
        unsafe { interrupt::restore(self.flags) };
    }
}

impl FlagsGuard {
    pub fn no_irq_region() -> Self {
        Self {
            flags: unsafe { interrupt::disable_and_store() },
        }
    }
}

impl<T, S: MutexSupport> Mutex<T, S> {
    /// Creates a new spinlock wrapping the supplied data.
    ///
    /// # Example
    /// ```
    /// lazy_static! {
    ///     static ref LOCK: Mutex<()> = Mutex::new();
    /// }
    /// ```
    pub const fn new(user_data: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(user_data),
            // After `MaybeUninit` is created, do not do anything on this unless it is properly initialized
            // and `assume_init` is called. Otherwise we will encounter UB.
            support: MaybeUninit::uninit(),
            support_initialization: MutexStatus::Uninitialized,
            user: UnsafeCell::new((0, 0)),
        }
    }

    /// Consumes this mutex, returning the underlying data.
    pub fn into_inner(self) -> T {
        let data = self.data;

        // Move inner values.
        {
            let _lock = self.lock;
            let _support = self.support;
            let _support_initialization_ = self.support_initialization;
            let _user = self.user;
        }

        data.into_inner()
    }
}

impl<T: ?Sized, S: MutexSupport> Mutex<T, S> {
    /// Acquires the lock. If the lock is acquired by other threads, puts the current thread into loop.
    fn get_lock(&self) {
        // Equivalent to `compare_and_swap` that is deprecated.
        while let Ok(true) =
            self.lock
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
        {
            let mut loop_count = 0usize;
            while self.lock.load(Ordering::Relaxed) {
                unsafe {
                    self.support.assume_init_ref().cpu_relax();
                }

                loop_count += 1;

                if loop_count == MAX_LOCK_ATTEMPT {
                    // Possible dead lock detected.
                    let (cpu_id, thread_id) = unsafe { *self.user.get() };
                    error!("Mutex.get_lock(): Failed to get the lock. Possible dead lock found. Mutex address {:p} created by CPU #{}, Thread #{}.",
                    self, cpu_id, thread_id);
                }

                let cpu_id = cpu_id();
                unsafe {
                    self.user.get().write((cpu_id, 0));
                }
            }
        }
    }

    /// Locks the [`Mutex`] and returns a guard that permits access to the inner data.
    ///
    /// The returned value may be dereferenced for data access
    /// and the lock will be dropped when the guard falls out of scope.
    ///
    /// ```
    /// use kernel::sync::SpinLock as Mutex;
    ///
    /// let lock = Mutex::new(0);
    /// {
    ///     let mut data = lock.lock();
    ///     // The lock is now locked and the data can be accessed
    ///     *data += 1;
    ///     // The lock is implicitly dropped at the end of the scope
    /// }
    /// ```
    #[inline(always)]
    pub fn lock(&self) -> MutexGuard<T, S> {
        let guard = S::lock_prologue();
        self.get_lock();

        MutexGuard { mutex: self, guard }
    }
}

/// Allows direct operation on `MutexGuard`.
impl<'a, T: ?Sized, S: MutexSupport> Deref for MutexGuard<'a, T, S> {
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }

    type Target = T;
}

impl<'a, T: ?Sized, S: MutexSupport> DerefMut for MutexGuard<'a, T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexSupport> Drop for MutexGuard<'a, T, S> {
    fn drop(&mut self) {
        // Release the lock and die.
        self.mutex.lock.store(false, Ordering::Release);
        unsafe {
            (*self.mutex.support.as_ptr()).lock_epilogue();
        }
    }
}
