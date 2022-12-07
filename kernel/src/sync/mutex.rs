//! Reference: https://docs.rs/spin/0.5.2/spin/struct.Mutex.html

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicBool;

use atomic_enum::atomic_enum;

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
  // TODO.
  fn new() -> Self;
  
  /// When the lock is failed to acquire, we call `cpu_relax` to temporarily suspend it.
  fn cpu_relax();
}

/// The implementation of `SpinLock`.
pub struct Spin {

}

/// Spin lock that masks all interrupts.
pub struct SpinNoInterrupt {

}

impl MutexSupport for Spin {
    fn new() -> Self {

    }

    fn cpu_relax() {
        
    }
}

impl MutexSupport for SpinNoInterrupt {
    fn new() -> Self {

    }

    fn cpu_relax() {
        
    }
}

pub struct MutexGuard<'a, T: ?Sized + 'a, S: MutexSupport + 'a> {
    pub(super) mutex: &'a Mutex<T, S>,
    guard: S::GuardData,
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

impl<T, S: MutexSupport> Mutex<T, S> {
    /// Creates a new spinlock wrapping the supplied data.
    ///
    /// # Example
    /// ```
    /// lazy_static! {
    ///     static REF LOCK: Mutex<()> = Mutex::new();
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
}
