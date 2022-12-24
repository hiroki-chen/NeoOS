//!  An executing program consists of a collection of native OS threads, each with their
//! own stack and local state. Threads can be named, and provide some built-in support for
//! low-level synchronization.
//!
//! Communication between threads can be done through signals, shared memory, along with
//! other forms of thread synchronization and shared-memory data structures. In particular,
//! types that are guaranteed to be threadsafe are easily shared between threads using the
//! atomically-reference-counted container, Arc.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use lazy_static::lazy_static;
use spin::RwLock;

use crate::{
    arch::{cpu::cpu_id, interrupt::Context, mm::paging::KernelPageTable, PAGE_SIZE},
    error::{Errno, KResult},
    memory::{KernelFrameAllocator, KernelStack, USER_STACK_SIZE, USER_STACK_START},
    mm::{callback::SystemArenaCallback, Arena, ArenaFlags, MemoryManager},
    signal::{SignalSet, Stack},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::Process;

/// Describes a thread.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreadState {
    /// The thread is currently being executed by the processor.
    RUNNING,
    /// The thread is waiting for a resource or event to become available.
    WAITING,
    /// The thread is sleeping for a specified amount of time.
    SLEEPING,
    /// The thread has been stopped by a signal or other external event.
    STOPPED,
    /// The thread has terminated but its parent process has not yet waited on it.
    ZOMBIE,
}

pub struct Thread {
    /// The thread id.
    pub id: u64,
    /// The parent process.
    pub parent: Arc<Mutex<Process>>,
    /// The inner thread context.
    pub inner: Arc<Mutex<ThreadInner>>,
    /// Proc.vm
    pub vm: Arc<Mutex<MemoryManager<KernelPageTable>>>,
}

/// Finds a free tid and assigns it to the current thread by `register`.
pub fn find_available_tid() -> KResult<u64> {
    (1u64..)
        .find(|id| THREAD_TABLE.read().get(&id).is_none())
        .ok_or(Errno::EBUSY)
}

impl Thread {
    /// Prepares the user stack. Returns the stack top.
    fn prepare_user_stack(vm: &mut MemoryManager<KernelPageTable>) -> KResult<usize> {
        let user_stack_bottom = USER_STACK_START;
        let user_stack_top = USER_STACK_START + USER_STACK_SIZE;

        // reserve 4 pages for init info.
        let mut flags = ArenaFlags::default();
        flags.non_executable = false;
        flags.user_accessible = true;
        vm.add(Arena {
            range: user_stack_bottom as u64..(user_stack_top - PAGE_SIZE * 4) as u64,
            flags,
            callback: Box::new(SystemArenaCallback::new(KernelFrameAllocator)),
        });

        todo!()
    }

    /// Activates this thread and registers it to the global thread table `THREAD_TABLE`.
    pub fn register(mut self) -> KResult<Arc<Self>> {
        let mut table = THREAD_TABLE.write();

        let id = find_available_tid()?;
        self.id = id;
        let arced_self = Arc::new(self);
        table.insert(id, arced_self.clone());

        Ok(arced_self)
    }

    /// Forks this thread.
    pub fn fork(&mut self, context: &Context) -> Arc<Self> {
        // Cow the vm.
        let vm = Arc::new(Mutex::new(self.vm.lock().clone()));

        todo!()
    }

    /// Creates a raw thread with in-memory instructions.
    /// Returns the user stack top.
    ///
    /// # Safety
    /// This function is unsafe because `inst_addr` must be valid.
    pub unsafe fn from_raw(inst_addr: u64) -> KResult<u64> {
        let mut vm = Arc::new(Mutex::new(MemoryManager::<KernelPageTable>::new(false)));

        let mut context = Context::default();
        context.set_rip(inst_addr);
        context.set_rsp(0x0); // todo.
        context.regs.rflags = 0x3202;

        let thread = Thread {
            id: 0,
            parent: todo!(),
            inner: todo!(),
            vm,
        };

        Ok(context.get_rsp())
    }
}

#[derive(Default)]
pub struct ThreadInner {
    /// Signals that this thread ignores.
    sigmask: SignalSet,
    /// The thread context.
    thread_context: Option<ThreadContext>,
    /// The signal alternative stack.
    sigaltstack: Stack,
}

pub struct ThreadContext {
    user_context: Box<Context>,
}

static mut CURRENT_THREAD_PER_CPU: [Option<Arc<Thread>>; 0x20] = [const { None }; 0x20];

lazy_static! {
    pub static ref THREAD_TABLE: RwLock<BTreeMap<u64, Arc<Thread>>> = RwLock::new(BTreeMap::new());
}

/// Gets a handle to the thread that invokes it.
pub fn current() -> KResult<Arc<Thread>> {
    let cpuid = cpu_id();

    if cpuid < 0x20 {
        unsafe {
            Ok(CURRENT_THREAD_PER_CPU[cpuid]
                .as_ref()
                .ok_or(Errno::EINVAL)?
                .clone())
        }
    } else {
        Err(Errno::EINVAL)
    }
}
