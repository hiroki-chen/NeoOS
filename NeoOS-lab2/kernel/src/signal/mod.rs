//! Implements a Linux-like signal handling routine.
//!
//! Signals are standardized messages sent to a running program to trigger specific behavior, such as quitting or
//! error handling. They are a limited form of inter-process communication (IPC), typically used in Unix, Unix-like,
//! and other POSIX-compliant operating systems.
//!
//! A signal is an asynchronous notification sent to a process or to a specific thread within the same process to
//! notify it of an event.

use core::{fmt::Debug, mem::MaybeUninit};

use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use num_enum::FromPrimitive;

use crate::{
    arch::{interrupt::Context, signal::SigContext},
    process::{event::Event, thread::Thread, Process},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

/// SIG_DFL specifies the default action for the particular signal. The default actions for various kinds of signals
/// are stated in Standard Signals.
pub const SIG_DFL: isize = 0;
/// SIG_IGN specifies that the signal should be ignored.
///
/// Your program generally should not ignore signals that represent serious events or that are normally used to request
/// termination. You cannot ignore the SIGKILL or SIGSTOP signals at all. You can ignore program error signals like SIGSEGV,
/// but ignoring the error won’t enable the program to continue executing meaningfully. Ignoring user requests such as
/// SIGINT, SIGQUIT, and SIGTSTP is unfriendly.
///
/// When you do not wish signals to be delivered during a certain part of the program, the thing to do is to block them,
/// not ignore them. See Blocking Signals.
pub const SIG_IGN: isize = 1;
/// error return from signal
pub const SIG_ERR: isize = -1;

/// A constant for the prevention of breaking the alignment of `SiFields`.
const X64_PAD: usize = 0x100 - 2 * core::mem::size_of::<i32>() - core::mem::size_of::<usize>();
const SIGFRAME_SIZE: usize = core::mem::size_of::<SigFrame>();
/// Equivalent to
/// ```asm
/// mov eax, 0xf  ; b8 0x 00 00 00
/// syscall       ; 0f 05
/// ```
const SYSRETURN: &[u8] = b"\xB8\x0F\x00\x00\x00\x0F\x05";
/// Specifies a set of signals. Used when a thread is able to accept some signals but
/// avoids the boilerplate definitions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Default)]
#[repr(C)]
pub struct SigSet(pub usize);

impl SigSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, other: usize) {
        self.0 |= other;
    }

    pub fn add_sigset(&mut self, other: SigSet) {
        self.0 |= other.0;
    }

    pub fn add_signal(&mut self, other: Signal) {
        self.0 |= 1 << other as usize;
    }

    pub fn remove(&mut self, other: usize) {
        self.0 ^= self.0 & other;
    }

    pub fn remove_signal(&mut self, other: Signal) {
        self.0 ^= self.0 & 1 << other as usize;
    }

    pub fn remove_set(&mut self, other: SigSet) {
        self.0 ^= self.0 & other.0 as usize;
    }

    pub fn contains(&self, other: Signal) -> bool {
        (self.0 >> other as u64 & 1) != 0
    }
}

/// Signals
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u64)]
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

    #[num_enum(default)]
    SIGUNKNOWN,
}

bitflags! {
    pub struct StackFlag: u32 {
      const ONSTACK = 0b0001;
      const DISABLE = 0b0010;
      const AUTODISARM = 0x80000000;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SignalActionFlags : usize {
        const NOCLDSTOP = 1;
        const NOCLDWAIT = 2;
        const SIGINFO = 4;
        const ONSTACK = 0x08000000;
        const RESTART = 0x10000000;
        const NODEFER = 0x40000000;
        const RESETHAND = 0x80000000;
        const RESTORER = 0x04000000;
    }
}

/// The signal stack.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SigStack {
    sp: usize,
    size: usize,
    flags: u32,
}

/// Be careful when extending this union. On 32bit siginfo_t is 32bit aligned, which means that a 64bit field or any other
/// field that would increase the alignment of siginfo_t will break the ABI.
#[repr(C)]
pub union SiFields {
    inner: MaybeUninit<[u8; X64_PAD]>,
}

impl Clone for SiFields {
    fn clone(&self) -> Self {
        Self {
            inner: unsafe { self.inner },
        }
    }
}

impl Default for SiFields {
    fn default() -> Self {
        let inner = MaybeUninit::new([0u8; X64_PAD]);
        Self { inner }
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct SigInfo {
    pub signo: usize,
    pub code: usize,
    pub errno: usize,
    pub sifields: SiFields,
}

impl Debug for SigInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigInfo")
            .field("signo", &self.signo)
            .field("code", &self.code)
            .field("errno", &self.errno)
            .finish()
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SigAction {
    /// Should be a function pointer. E.g., `typedef void __signalfn_t(int);`
    pub sa_handler: isize,
    pub sa_flags: SignalActionFlags,
    pub sa_restorer: usize,
    pub sa_mask: SigSet,
}

/// See <https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/ucontext.h#L5>
#[repr(C)]
pub struct SigUcontext {
    pub uc_flags: usize,
    /// The original one should be like `SigUcontext* uc_link`, but we avoid using raw pointers due to safety reasons.
    /// Do not use smart pointers because we need to produce `repr(C)`.
    pub uc_link: usize,
    pub uc_stack: SigStack,
    pub uc_context: SigContext,
    pub uc_mask: SigSet,
}

/// Whenever a signal is delivered, the kernel needs to context switch to the installed signal handler. To do so, the
/// kernel saves the current execution context in a frame on the stack.
///
/// The layout the of stack frame would be:
///
/// ```text
/// --------------+
/// FPSTATE       |
/// MASK          |
/// --------------+
/// SigContext    |
/// --------------+
/// SigStack      |
/// --------------+
/// uc_link       |
/// uc_flags      |
/// --------------+
/// rip = sigreturn
/// ```
/// where, `sigstack` + `sigcontext` + `uc_*` = SigUContext.
///
/// # Some Interesting Facts
///
/// There exists a kind of 'Sigreturn-oriented programming' in pwn exploitation, which was proposed in S&P'14 paper. This
/// attack exploits the vulnerability of the `sigreturn` syscall to allow the adversary to execute the malicious code after
/// overwriting the RIP. The problem of signal handling is, that user process can install signal handler can call `sysreturn`
/// to trap into the kernel, but the data pushed onto the stack is *unchecked*. Therefore, it is possible for the user to
/// construct fake user context on the stack and cheat the kernel to perform `sysreturn`.
///
/// So, the attack proceeds as follows.
///
/// stack overflow -> construct a fake context on the stack -> execute sysreturn by gadget -> sysreturn let the rip point
/// to the fake rip (can be syscall to execve '/bin/shell') -> shell obtained
#[repr(C)]
pub struct SigFrame {
    pub pretcode: u64,
    pub info: SigInfo,
    pub ucontext: SigUcontext,
    pub retcode: [u8; 7],
}

impl Default for SigStack {
    fn default() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: StackFlag::DISABLE.bits,
        }
    }
}

fn get_sigstack_sp(
    sigstack: &SigStack,
    thread: &Arc<Thread>,
    flags: SignalActionFlags,
) -> Option<u64> {
    if flags.contains(SignalActionFlags::ONSTACK) {
        let stack_flags = StackFlag::from_bits_truncate(sigstack.flags);

        if stack_flags.contains(StackFlag::DISABLE) {
            None
        } else {
            let mut inner = thread.inner.lock();
            inner.sigaltstack.flags |= StackFlag::ONSTACK.bits();

            if stack_flags.contains(StackFlag::AUTODISARM) {
                inner.sigaltstack.flags |= StackFlag::DISABLE.bits();
            }

            Some((sigstack.sp + sigstack.size) as _)
        }
    } else {
        // Fallback to default sp.
        None
    }
}

/// Signal generation: kernel updates the data structures of the receiving process to record that the signal was sent.
///
/// # Note
///
/// Kernels make a distinction between *generating* a signal and *delivering* the signal.
pub fn send_signal(current_process: Arc<Mutex<Process>>, dest: i64, info: SigInfo) {
    let signal = Signal::from(info.signo as u64);

    let mut process = current_process.lock();
    // If the process already has a pending signal of that type, the new signal is ignored.
    // Our kernel is not real-time, meaning that doing so is OK.
    // If the process is ignoring the signal, nothing is done.
    if process.pending_sigset.contains(signal)
        || process
            .sig_queue
            .iter()
            .any(|item| item.0.signo == info.signo)
    {
        return;
    }

    // Proceed, but a few signal types are not added to signal queue? These signals are enforced immediately by the kernel
    // the next time the process runs.
    match signal {
        Signal::SIGABRT | Signal::SIGKILL | Signal::SIGSTOP | Signal::SIGALRM => {
            process.sig_queue.push_front((info, dest));
            // TODO: Maybe other alerts to, e.g., the scheduler.
        }
        _ => {
            process.sig_queue.push_back((info, dest));
        }
    }
    process.event_bus.lock().set(Event::RECEIVE_SIGNAL);
    process.pending_sigset.add_signal(signal);
}

/// The system defines a set of signals that may be delivered to a process. Signal delivery resembles the occurrence of a
/// hardware interrupt: the signal is normally blocked from further occurrence, the current process context is saved, and a
/// new one is built.  A process may specify a handler to which a signal is delivered, or specify that a signal is to be
/// ignored.
///
/// A process may also specify that a default action is to be taken by the system when a signal occurs.  A signal may also
/// be blocked, in which case its delivery is postponed until it is unblocked.  The action to be taken on delivery is
/// determined at the time of delivery.  Normally, signal handlers execute on the current stack of the process.
pub fn handle_signal(thread: &Arc<Thread>, ctx: &mut Context) -> bool {
    let mut process = thread.parent.lock();

    // Iterate over the signal queue. Linux 2.6 do_signal() uses a loop.
    // If no more pending signals, the kernel returns to the user process.
    let queue = process
        .sig_queue
        .iter()
        .enumerate()
        .filter_map(|(idx, (info, dest))| {
            if *dest == -1 || *dest as u64 == thread.id {
                let signal = Signal::from(info.signo as u64);
                if thread.inner.lock().sigmask.contains(signal) {
                    None
                } else {
                    Some((idx, info.clone()))
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for (idx, info) in queue.into_iter() {
        let signal = Signal::from(info.signo as u64);
        process.sig_queue.remove(idx);
        process.pending_sigset.remove_signal(signal);

        let sa = process.actions[idx];
        let sa_flags = sa.sa_flags;

        // Two ways a signal can be handled.
        // * Signal is ignored, or default action is to be performed;
        // * Signal has a user-mode handler. For user-process-handled signals, only one signal is handled.
        //
        // And there are other special cases. E.g., the child process terminates => SIGCHLD is sent.
        // How do we handle SIGCHLD?
        match sa.sa_handler {
            SIG_DFL => {
                // FIXME: NOT IMPLEMENTED FOR ALL.
                match signal {
                    Signal::SIGHUP
                    | Signal::SIGTERM
                    | Signal::SIGINT
                    | Signal::SIGABRT
                    | Signal::SIGKILL
                    | Signal::SIGSEGV => {
                        // May be too simple?
                        if signal == Signal::SIGKILL {
                            println!(
                                "[{}]\t{} killed\t{}",
                                idx + 1,
                                thread.id,
                                thread.parent.lock().exec_path
                            );
                        }
                        if signal == Signal::SIGSEGV {
                            println!(
                                "[{}]\t{} segmentation fault (core dumped)\t{}",
                                idx + 1,
                                thread.id,
                                thread.parent.lock().exec_path
                            );
                        }
                        // quit the program.
                        process.exit(make_unix_error_code!(signal));
                        return true;
                    }

                    Signal::SIGCHLD => {
                        kinfo!("handle_signal(): SIGCHILD is ignored by default.");
                        continue;
                    }

                    _ => unimplemented!(),
                }
            }
            // A signal may be ignored if the process has set its handler to SIG_IGN.
            SIG_IGN => {
                // Do nothing.
                kinfo!("handle_signal(): signal {:?} is ignored.", signal);
                continue;
            }

            SIG_ERR => {
                // Error occurred. Exit the program.
                kerror!("handle_signal(): error occurred.");
                // Find an error code.
                process.exit((SIG_ERR as u8) as _);
            }

            _ => {
                // Must set up a new CPU context for the signal handler to use.

                kinfo!("handle_signal(): use user handler.");
                // We can override how the signal is being processed by specifying a new action handler.
                let mut inner = thread.inner.lock();
                let sig_mask = inner.sigmask;

                // Update so that the current process blocks this type of signal.
                // Prevents a given signal handler from interrupting itself.
                // One kind of signal can interrupt another kind of signal.
                inner.sigmask.add_signal(signal);
                inner.sigmask.add(sa.sa_mask.0);

                let sigstack = inner.sigaltstack.clone();
                drop(inner);

                // Get the signal stack's stack pointer.
                let sp = match get_sigstack_sp(&sigstack, thread, sa_flags) {
                    Some(sp) => sp,
                    None => ctx.get_rsp(),
                } - SIGFRAME_SIZE as u64;

                // Write the sigframe to the memory.
                let sig_frame = unsafe { &mut *(sp as *mut SigFrame) };
                sig_frame.info = info.clone();
                sig_frame.ucontext = SigUcontext {
                    uc_flags: 0,
                    uc_link: 0,
                    uc_stack: sigstack,
                    uc_context: SigContext::from_uctx(ctx),
                    uc_mask: sig_mask,
                };

                if sa_flags.contains(SignalActionFlags::RESTORER) {
                    sig_frame.pretcode = sa.sa_restorer as _;
                } else {
                    sig_frame.pretcode = sig_frame.retcode.as_ptr() as _;

                    if sig_frame.retcode.len() <= SYSRETURN.len() {
                        kwarn!("handle_signal(): the return code length is insufficient. This should be reported.");
                    }
                    sig_frame.retcode.copy_from_slice(SYSRETURN);
                }

                ctx.set_rsp(sp);
                ctx.set_rip(sa.sa_handler as _);
                ctx.regs.rdi = info.signo as _;
                ctx.regs.rsi = &sig_frame.info as *const _ as _;
                ctx.regs.rdx = &sig_frame.ucontext as *const _ as _;
            }
        }
    }

    false
}
