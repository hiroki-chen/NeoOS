//!  An executing program consists of a collection of native OS threads, each with their
//! own stack and local state. Threads can be named, and provide some built-in support for
//! low-level synchronization.
//!
//! Communication between threads can be done through signals, shared memory, along with
//! other forms of thread synchronization and shared-memory data structures. In particular,
//! types that are guaranteed to be threadsafe are easily shared between threads using the
//! atomically-reference-counted container, Arc.

use core::arch::global_asm;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::lazy_static;
use log::info;
use spin::RwLock;

use crate::{
    arch::{
        cpu::{cpu_id, FpState, MAX_CPU_NUM},
        interrupt::{Context, PAGE_FAULT_INTERRUPT},
        mm::paging::{get_pf_addr, handle_page_fault, KernelPageTable, PageTableBehaviors},
        PAGE_SIZE,
    },
    error::{Errno, KResult},
    memory::{get_physical_address, KernelFrameAllocator, USER_STACK_SIZE, USER_STACK_START},
    mm::{callback::SystemArenaCallback, Arena, ArenaFlags, FutureWithPageTable, MemoryManager},
    signal::{SignalSet, Stack},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::{event::EventBus, register, scheduler::FIFO_SCHEDULER, Process};

const DEBUG_THREAD_ID: u64 = 0xdeadbeef;
const DEBUG_PROC_ID: u64 = 0xbeefdead;

// Test script.
global_asm!(
    r#"
.global __debug_thread
__debug_thread:
    hlt
    mov rcx, 100

    xor rax, rax
    mov rax, rcx

    sub rcx, 1
"#
);

extern "C" {
    fn __debug_thread();
}

/// An enum representing the state of a thread.
///
/// This enum has five variants: `RUNNING`, `WAITING`, `SLEEPING`, `STOPPED`, and `ZOMBIE`.
///
/// # Examples
///
/// ```
/// # use kernel::process::thread::ThreadState;
/// let state = ThreadState::RUNNING;
/// println!("The thread is currently {:?}", state);
/// ```
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
        .find(|id| THREAD_TABLE.read().get(id).is_none())
        .ok_or(Errno::EBUSY)
}

impl Thread {
    /// Prepares the user stack. Returns the stack top.
    fn prepare_user_stack(vm: &mut MemoryManager<KernelPageTable>) -> KResult<usize> {
        let user_stack_bottom = USER_STACK_START;
        let user_stack_top = USER_STACK_START + USER_STACK_SIZE;

        // Reserve 4 pages for init info.
        // This is because the execution of the ELF file must requrie argc, argc, envp things.
        let flags = ArenaFlags {
            user_accessible: true,
            non_executable: false,
            ..Default::default()
        };

        // This stack is allocated for the user thread.
        vm.add(Arena {
            range: user_stack_bottom as u64..(user_stack_top - PAGE_SIZE * 4) as u64,
            flags: flags.clone(),
            callback: Box::new(SystemArenaCallback::new(KernelFrameAllocator)),
        });
        // This stack is allocated for storing the auxiliary information such as argv, envp, etc.
        vm.add(Arena {
            range: (user_stack_top - PAGE_SIZE * 4) as u64..user_stack_top as u64,
            flags,
            callback: Box::new(SystemArenaCallback::new(KernelFrameAllocator)),
        });

        Ok(user_stack_top)
    }

    /// Activates this thread and registers it to the global thread table `THREAD_TABLE`.
    pub fn register(mut self) -> KResult<Arc<Self>> {
        let mut table = THREAD_TABLE.write();

        let id = match self.id {
            0 => find_available_tid()?,
            id => id,
        };
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

    pub fn take(&self) -> ThreadContext {
        self.inner.lock().thread_context.take().unwrap()
    }

    pub fn restore(&self, ctx: ThreadContext) {
        self.inner.lock().thread_context.replace(ctx);
    }

    /// Creates a raw thread with in-memory instructions.
    /// Returns the user stack top.
    ///
    /// # Note
    ///
    /// Do *not directly* use this function unless you need to debug if kernel correctly handles multi-threading.
    ///
    /// # Safety
    ///
    /// This function is unsafe because `inst_addr` must be valid.
    pub unsafe fn from_raw(inst_addr: u64) -> KResult<Arc<Thread>> {
        let mut vm: MemoryManager<KernelPageTable> = MemoryManager::new(false);
        let func_phys_addr = get_physical_address(__debug_thread as u64);
        info!(
            "from_raw(): the test function's physical address is {:#x}",
            func_phys_addr
        );
        vm.page_table().map(virt!(inst_addr), phys!(func_phys_addr));

        let stack_top = Self::prepare_user_stack(&mut vm)? as u64;
        let vm = Arc::new(Mutex::new(vm));

        let mut context = Context::default();
        context.set_rip(inst_addr);
        context.set_rsp(stack_top);
        context.regs.rflags = 0x3202;

        let thread = Thread {
            id: DEBUG_THREAD_ID,
            parent: Arc::new(Mutex::new(Process {
                process_id: DEBUG_PROC_ID,
                process_group_id: DEBUG_PROC_ID,
                threads: Vec::new(),
                vm: vm.clone(),
                exec_path: "".into(),
                pwd: ".".into(),
                opened_files: BTreeMap::new(),
                exit_code: 0u64,
                event_bus: EventBus::new(),
                futexes: BTreeMap::new(),
                parent: (0xffff_ffff, Weak::new()),
                children: Vec::new(),
            })),
            inner: Arc::new(Mutex::new(ThreadInner {
                sigmask: SignalSet::new(),
                thread_context: Some(ThreadContext {
                    user_context: Box::new(context),
                    fp_state: Box::new(FpState::new()),
                }),
                sigaltstack: Stack::default(),
            })),
            vm,
        };

        // Add itself into the global thread table.
        let thread_ref = thread.register()?;
        register(thread_ref.parent.clone(), DEBUG_PROC_ID);

        Ok(thread_ref)
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

/// A structure representing the context of a thread.
///
/// This struct contains two fields: `user_context` and `fp_state`.
/// `user_context` is a boxed [`Context`] struct, which represents the user-mode
/// state of the thread. `fp_state` is a boxed [`FpState`] struct, which represents
/// the floating-point state of the thread.
///
/// # Examples
///
/// ```
/// # use kernel::process::thread::ThreadContext;
/// let mut ctx = ThreadContext::new();
/// ```
pub struct ThreadContext {
    user_context: Box<Context>,
    fp_state: Box<FpState>,
}

pub static mut CURRENT_THREAD_PER_CPU: [Option<Arc<Thread>>; MAX_CPU_NUM] = {
    const THREAD: Option<Arc<Thread>> = None;
    [THREAD; MAX_CPU_NUM]
};

lazy_static! {
    pub static ref THREAD_TABLE: RwLock<BTreeMap<u64, Arc<Thread>>> = RwLock::new(BTreeMap::new());
}

/// Gets a handle to the thread that invokes it.
pub fn current() -> KResult<Arc<Thread>> {
    unsafe {
        Ok(CURRENT_THREAD_PER_CPU[cpu_id()]
            .as_ref()
            .ok_or(Errno::EEXIST)?
            .clone())
    }
}

/// This function spawns a new kernel thread from the given [`Thread`] object.
///
/// This function returns a [`KResult`] object, indicating whether the operation was successful. If the thread was
/// successfully spawned, Ok(()) is returned. If an error occurred, an appropriate error code is returned.
pub fn spawn(thread: Arc<Thread>) -> KResult<()> {
    let cr3 = thread
        .vm
        .lock()
        .page_table()
        .page_table_frame
        .start_address()
        .as_u64();
    let thread_clone = thread.clone();

    let thread_future = async move {
        loop {
            let mut ctx = thread.take();
            // Perform a context switch.
            ctx.fp_state.fxrstor();
            ctx.user_context.start();
            ctx.fp_state.fxsave();

            // syscall / trap: anyway, a context switch happens here.
            let tf = ctx.user_context.trapno as usize;
            match tf {
                PAGE_FAULT_INTERRUPT => {
                    let cr2 = get_pf_addr();
                    info!(
                        "spawn(): thread {:#x} triggered page fault @ {:#x}",
                        thread.id, cr2
                    );

                    if !handle_page_fault(cr2) {
                        // Report SEGSEV.
                        panic!("spawn(): Segmentation fault.");
                    }
                }
                tf => unimplemented!("spawn(): not supported {:#x}.", tf),
            }

            thread.restore(ctx);

            // Handle signal or other errors.
        }
    };

    FIFO_SCHEDULER.spawn(
        FutureWithPageTable::new(Box::pin(thread_future), cr3, thread_clone),
        None,
    );
    Ok(())
}

/// Spawn a debug thread with in-memory instructions.
pub fn debug_threading() {
    // TODO: We may need to copy to user space first?
    info!(
        "debug_threading(): creating a dummy thread. RIP @ {:#x}",
        __debug_thread as u64
    );

    let thread = unsafe { Thread::from_raw(0x400000u64) }.unwrap();
    spawn(thread).unwrap();
}
