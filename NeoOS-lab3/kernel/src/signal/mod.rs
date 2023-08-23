//! Signals are standardized messages sent to a running program to trigger specific behavior, such as quitting or
//! error handling. They are a limited form of inter-process communication (IPC), typically used in Unix, Unix-like,
//! and other POSIX-compliant operating systems.
//!
//! A signal is an asynchronous notification sent to a process or to a specific thread within the same process to
//! notify it of an event.

use bitflags::bitflags;

/// Specifies a set of signals. Used when a thread is able to accept some signals but
/// avoids the boilerplate definitions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Default)]
#[repr(C)]
pub struct SignalSet(u64);

impl SignalSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, other: u64) {
        self.0 |= other;
    }

    pub fn add_signal(&mut self, other: Signal) {
        self.0 |= 1 << other as u64;
    }

    pub fn remove(&mut self, other: u64) {
        self.0 ^= self.0 & other;
    }

    pub fn remove_signal(&mut self, other: Signal) {
        self.0 ^= self.0 & 1 << other as u64;
    }
}

/// Signals
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    SIGPWR = 30,
    SIGSYS = 31,
    SIGRTMIN = 32,
    SIGRTMAX = 63,
}

bitflags! {
    pub struct StackFlag: u32 {
      const ONSTACK = 0b0001;
      const DISABLE = 0b0010;
      const AUTODISARM = 0x80000000;
    }
}

/// The signal stack.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Stack {
    sp: u64,
    size: usize,
    flags: u32,
}

impl Default for Stack {
    fn default() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: StackFlag::DISABLE.bits,
        }
    }
}
