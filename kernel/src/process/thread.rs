//!  An executing program consists of a collection of native OS threads, each with their
//! own stack and local state. Threads can be named, and provide some built-in support for
//! low-level synchronization.
//!
//! Communication between threads can be done through signals, shared memory, along with
//! other forms of thread synchronization and shared-memory data structures. In particular,
//! types that are guaranteed to be threadsafe are easily shared between threads using the
//! atomically-reference-counted container, Arc.

use core::{fmt::Debug, time::Duration};

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    string::String,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use lazy_static::lazy_static;
use rcore_fs::vfs::INode;
use spin::RwLock;

use crate::{
    arch::{
        cpu::{cpu_id, FpState, MAX_CPU_NUM},
        interrupt::{dispatcher::trap_dispatcher_user, Context},
        mm::paging::{KernelPageTable, PageTableBehaviors},
        pit::countdown,
        PAGE_SIZE,
    },
    elf::ElfFile,
    error::{Errno, KResult},
    fs::{
        devfs::tty::TTY,
        file::{File, FileObject, FileOpenOption, FileType},
        ROOT_INODE,
    },
    memory::{
        page_frame_number, page_mask, KernelFrameAllocator, USER_STACK_SIZE, USER_STACK_START,
    },
    mm::{
        callback::SystemArenaCallback, Arena, ArenaFlags, ArenaType, FutureWithPageTable,
        MemoryManager,
    },
    process::ld::{AT_BASE, AT_ENTRY},
    signal::{handle_signal, SigAction, SigSet, SigStack},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::{event::EventBus, ld::InitInfo, register, scheduler::FIFO_SCHEDULER, Process, Yield};

// For testing. pid_t is a *signed* integer. So we do not want to make it overflow to negative.
const DEBUG_THREAD_ID: u64 = 0xbeef;
const DEBUG_PROC_ID: u64 = 0xdead;

/// A naked function that is used to test if ring switch works. If it works, this function would trigger general
/// protection fault (0xd) indicating that `hlt` is privileged instruction so that the user-level application is
/// expected to abort immediately.
///
/// Since we haven't implemented filesystem, we cannot load the program from the filesystem. So, the solution for
/// the time being is, to simply load the instruction from the memory and make that memory user-accessible.
#[naked]
#[allow(unused)]
unsafe extern "C" fn __debug_thread_invalid() {
    unsafe { core::arch::asm!("hlt", options(noreturn)) }
}

#[naked]
#[allow(unused)]
unsafe extern "C" fn __debug_thread() {
    unsafe { core::arch::asm!("int3; lea rax, [rip]; jmp rax", options(noreturn)) }
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
    /// Need schedule?
    pub need_schedule: bool,
}

/// Finds a free tid and assigns it to the current thread by `register`.
pub fn find_available_tid() -> KResult<u64> {
    let thread_table = THREAD_TABLE.read();
    (1u64..)
        .find(|id| thread_table.get(id).is_none())
        .ok_or(Errno::EBUSY)
}

/// Put the current core into sleeping state and wake it up after `duration` time.
///
/// Note, however, that this operation can be interrupted by, e.g., a syscall. The target of this function is to ensure
/// a sleep in the current thread, but not the whole system; the current thread cannot make the system suspend.
pub fn sleep(duration: Duration) {
    // The granularity is 10 ms.
    const TIME_SLICE: u128 = 10_000;

    let mut cnt = (duration.as_millis() / TIME_SLICE).min(u64::MAX as u128) as u64;
    while cnt != 0 {
        countdown(TIME_SLICE as _);
        cnt -= 1;
    }
}

impl Thread {
    /// Prepares the user stack. Returns the stack top.
    ///
    /// The initial stack should contain the arguments as well as some necessary environment variables. One can
    /// easily use gdb to check the top of the user stack, or simply execute the following command.
    ///
    /// ```sh
    /// $ cat /proc/self/map
    ///
    /// 7fded5a5e000-7fded5a5f000 rw-p 00000000 00:00 0
    /// 7ffdbec15000-7ffdbec36000 rw-p 00000000 00:00 0                          [stack]
    /// 7ffdbed9b000-7ffdbed9e000 r--p 00000000 00:00 0                          [vvar]
    /// 7ffdbed9e000-7ffdbed9f000 r-xp 00000000 00:00 0                          [vdso]
    /// ```
    fn prepare_user_stack(
        vm: &mut MemoryManager<KernelPageTable>,
        args: Vec<String>,
        envs: Vec<String>,
        auxv: BTreeMap<u8, usize>,
    ) -> KResult<usize> {
        let user_stack_bottom = USER_STACK_START;
        let mut user_stack_top = USER_STACK_START + USER_STACK_SIZE;

        // Reserve 4 pages for init info.
        // This is because the execution of the ELF file must requrie argc, argc, envp things.
        let flags = ArenaFlags {
            user_accessible: true,
            non_executable: true,
            writable: true,
            mmio: 0,
        };

        // This stack is allocated for the user thread.
        vm.add(Arena {
            range: user_stack_bottom as u64..(user_stack_top - PAGE_SIZE * 4) as u64,
            flags: flags.clone(),
            callback: Box::new(SystemArenaCallback::new(KernelFrameAllocator)),
            ty: ArenaType::Stack,
            name: "[stack]".into(),
        });
        // This stack is allocated for storing the auxiliary information such as argv, envp, etc.
        vm.add(Arena {
            range: (user_stack_top - PAGE_SIZE * 4) as u64..user_stack_top as u64,
            flags,
            callback: Box::new(SystemArenaCallback::new(KernelFrameAllocator)),
            ty: ArenaType::Stack,
            name: "[stack]".into(),
        });

        unsafe {
            vm.with(|| {
                user_stack_top = InitInfo { args, envs, auxv }.push_at(user_stack_top as _) as _;
            });
        }
        Ok(user_stack_top)
    }

    /// Activates this thread and registers it to the global thread table `THREAD_TABLE`.
    pub fn register(mut self) -> KResult<Arc<Self>> {
        let id = match self.id {
            0 => find_available_tid()?,
            id => id,
        };
        self.id = id;
        let arced_self = Arc::new(self);
        THREAD_TABLE.write().insert(id, arced_self.clone());

        Ok(arced_self)
    }

    /// Forks this thread.
    pub fn fork(&self, context: &Context) -> Arc<Self> {
        // Cow the vm.
        let vm = Arc::new(Mutex::new(self.vm.lock().clone()));

        let mut ctx = context.clone();
        ctx.regs.rax = 0;

        let mut lock = self.parent.lock();
        let id = find_available_tid().unwrap();
        let forked_process = Arc::new(Mutex::new(Process {
            process_id: id,
            process_group_id: lock.process_group_id,
            threads: Vec::new(),
            vm: vm.clone(),
            exec_path: lock.exec_path.clone(),
            cwd: lock.cwd.clone(),
            opened_files: lock.opened_files.clone(),
            exit_code: 0,
            name: lock.name.clone(),
            event_bus: EventBus::new(),
            futexes: BTreeMap::new(),
            parent: (lock.process_id, Arc::downgrade(&self.parent)),
            children: Vec::new(),
            pending_sigset: SigSet::default(),
            sig_queue: VecDeque::new(),
            actions: lock.actions,
        }));

        register(&forked_process, id);

        let thread = Thread {
            id,
            parent: forked_process,
            inner: Arc::new(Mutex::new(ThreadInner {
                sigmask: self.inner.lock().sigmask,
                thread_context: Some(ThreadContext {
                    user_context: Box::new(ctx),
                    fp_state: Box::new(FpState::new()),
                }),
                sigaltstack: self.inner.lock().sigaltstack.clone(),
                clear_child_tid: self.inner.lock().clear_child_tid,
            })),
            vm,
            need_schedule: false,
        }
        .register()
        .unwrap();

        thread.parent.lock().threads.push(id);
        lock.children
            .push((thread.id, Arc::downgrade(&thread.parent)));

        thread
    }

    pub fn take(&self) -> ThreadContext {
        self.inner.lock().thread_context.take().unwrap()
    }

    pub fn restore(&self, ctx: ThreadContext) {
        self.inner.lock().thread_context.replace(ctx);
    }

    /// Creates a new user-space thread and returns the user stack top and the entry point.
    ///
    /// # Arguments
    ///
    /// - inode: the current directory where this thread is created.
    /// - path: the execution path of this thread.
    /// - name: the name of the running program.
    /// - args: the argument string. Same as `const char** argv`.
    /// - envp: the environment strings.
    ///
    /// For our kernel, the layout of the application memory should look like this:
    ///
    /// ```txt
    /// +--------------+ <----- 0x8000_0000_0000
    /// |     env      |
    /// +--------------+
    /// |     argv     |
    /// +--------------+
    /// |     argc     |
    /// +--------------+
    /// |              |
    /// |  user stack  |
    /// |              |
    /// +--------------+
    /// |  ld-musl.so  |
    /// +--------------+
    /// |    dylib     |
    /// +--------------+
    /// |  user  heap  |
    /// +--------------+ <-----   brk()
    /// |   malloced   |
    /// +--------------+
    /// |     .bss     |
    /// +--------------+
    /// |.data/.rodata |
    /// +--------------+
    /// |  staticlib   |
    /// +--------------+
    /// |    main()    |
    /// +--------------+
    /// |    crt       |
    /// +--------------+
    /// |   reserved   |
    /// +--------------+
    /// ```
    pub fn create_memory(
        inode: &Arc<dyn INode>,
        path: &str,
        name: &str,
        args: Vec<String>,
        envp: Vec<String>,
        vm: &mut MemoryManager<KernelPageTable>,
    ) -> KResult<(u64, u64)> {
        // Ensure vm is properly cleared.
        vm.clear();

        let elf = ElfFile::load(inode)?;
        let mem_offset = elf.load_elf_and_map(vm, name)?;

        let mut elf_entry = elf.entry_point();
        let mut auxv = elf.get_auxv()?;

        let addr_end = (page_mask(vm.iter().last().unwrap().range.end) + 1) * 0x1000;
        vm.set_heap_end(addr_end);
        vm.set_reserved();

        if let Ok(elf_interpreter) = elf.get_interpreter() {
            kinfo!("loading the ELF interpreter {elf_interpreter}");

            let ld = ROOT_INODE
                .lookup_follow(elf_interpreter, 5)
                .map_err(|_| Errno::ENOENT)?;
            // The program's memory should be determined by the loader.
            let ld_elf = ElfFile::load(&ld)?;
            let ld_elf_size = page_frame_number(ld_elf.memsize() + PAGE_SIZE as u64 - 1);
            let ld_addr = USER_STACK_START as u64 - ld_elf_size;
            ld_elf.load_as_interpreter(vm, ld_addr, elf_interpreter)?;

            elf_entry = ld_addr + ld_elf.entry_point();
            kinfo!("original entry is {:#x}", elf.entry_point());
            kinfo!("interpreter entry is {:#x}", elf_entry);
            // Insert auxiliary vectors.
            auxv.insert(AT_ENTRY, elf.entry_point() as _);
            auxv.insert(AT_BASE, ld_addr as _);
        }

        let stack_top = Self::prepare_user_stack(vm, args, envp, auxv)? as u64;

        Ok((stack_top, elf_entry))
    }

    pub fn create(
        inode: &Arc<dyn INode>,
        path: &str,
        name: &str,
        args: Vec<String>,
        envp: Vec<String>,
    ) -> KResult<Arc<Thread>> {
        let mut vm: MemoryManager<KernelPageTable> = MemoryManager::new(false);
        let (stack_top, elf_entry) = Self::create_memory(inode, path, name, args, envp, &mut vm)?;
        let vm = Arc::new(Mutex::new(vm));

        // So we must pretend that 'interrupt' occurs here so that CPU allows to perform `IRETQ`.
        // To this end, we must carefully construct the stack upon return, whose layout should be:
        //
        // SS           <- stack selector before interrupt
        // RSP          <- stack pointer before interrupt
        // RFLAGS       <- flag register before interrupt
        // CS           <- code selector before interrupt
        // RIP          <- instruction pointer register before interupt
        // error_code   <- error code / trap number / syscall number
        // blahblah     <- SS:RSP
        let mut context = Context::default();

        kinfo!(
            "the ELF entry point is 0x{:x}; stack top is 0x{:x}",
            elf_entry,
            stack_top
        );
        context.set_rip(elf_entry);
        context.set_rsp(stack_top);
        // IOPL | IF | RSVD
        context.regs.rflags = 0x3202;

        // Get stdio files.
        let stdio = init_stdio();

        let thread = Thread {
            id: 0,
            parent: Arc::new(Mutex::new(Process {
                process_id: DEBUG_PROC_ID,
                process_group_id: 0,
                threads: Vec::new(),
                vm: vm.clone(),
                exec_path: path.into(),
                cwd: "/".into(),
                name: name.into(),
                opened_files: stdio,
                exit_code: 0u8,
                event_bus: EventBus::new(),
                futexes: BTreeMap::new(),
                parent: (0xffff_ffff, Weak::new()),
                children: Vec::new(),
                pending_sigset: SigSet::default(),
                sig_queue: VecDeque::new(),
                actions: [SigAction::default(); 0x41],
            })),
            inner: Arc::new(Mutex::new(ThreadInner {
                sigmask: SigSet::new(),
                thread_context: Some(ThreadContext {
                    user_context: Box::new(context),
                    fp_state: Box::new(FpState::new()),
                }),
                sigaltstack: SigStack::default(),
                clear_child_tid: 0, // NULL by default.
            })),
            vm,
            need_schedule: false,
        };

        // Add itself into the global thread table.
        let thread_ref = thread.register()?;
        register(&thread_ref.parent, thread_ref.id);

        Ok(thread_ref)
    }
}

#[derive(Default)]
pub struct ThreadInner {
    /// Signals that this thread ignores.
    pub sigmask: SigSet,
    /// The thread context.
    pub thread_context: Option<ThreadContext>,
    /// The signal alternative stack.
    pub sigaltstack: SigStack,
    /// The clear_child_td thing. See <https://man7.org/linux/man-pages/man2/set_tid_address.2.html>
    pub clear_child_tid: u64,
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

impl ThreadContext {
    pub fn switch(&mut self) {
        self.fp_state.fxrstor();
        self.user_context.start();
        self.fp_state.fxsave();
    }

    pub fn get_trapno(&self) -> usize {
        self.user_context.trapno as usize
    }

    pub fn get_user_context(&mut self) -> &mut Box<Context> {
        &mut self.user_context
    }
}

impl Debug for ThreadContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadContext")
            .field("User Context", self.user_context.as_ref())
            .field("Float Point State", self.fp_state.as_ref())
            .finish()
    }
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

/// A helper function that initializes the default stdio for the thread.
fn init_stdio() -> BTreeMap<u64, FileObject> {
    let mut files = BTreeMap::new();

    // IO. stdin, stdout, stderr.
    files.insert(
        0,
        FileObject::File(File::new(
            TTY.clone(),
            "/dev/tty",
            false,
            FileOpenOption::READ,
            FileType::CONVENTIONAL,
        )),
    );

    files.insert(
        1,
        FileObject::File(File::new(
            TTY.clone(),
            "/dev/tty",
            false,
            FileOpenOption::WRITE,
            FileType::CONVENTIONAL,
        )),
    );

    files.insert(
        2,
        FileObject::File(File::new(
            TTY.clone(),
            "/dev/tty",
            false,
            FileOpenOption::WRITE,
            FileType::CONVENTIONAL,
        )),
    );

    files
}

/// This function spawns a new kernel thread from the given [`Thread`] object.
///
/// This function returns a [`KResult`] object, indicating whether the operation was successful. If the thread was
/// successfully spawned, Ok(()) is returned. If an error occurred, an appropriate error code is returned.
pub fn spawn(thread: Arc<Thread>) -> KResult<()> {
    let cr3 = thread.vm.lock().page_table().cr3();
    let thread_clone = thread.clone();
    let mut exited = false;
    let mut should_yield = false;

    let thread_future = async move {
        loop {
            let mut ctx = thread.take();
            // Perform a context switch.
            ctx.switch();

            // syscall / trap: anyway, a context switch happens here.
            if !trap_dispatcher_user(&thread, &mut ctx, &mut should_yield, &mut exited).await {
                // TODO: Elegantly kill the process and reclaim all the resources it occupies.
                kerror!(
                    "spawn(): cannot handle context switch. Dumped context is {:#x?}",
                    ctx.user_context
                );
                break;
            }

            // Handle signal or other errors.
            if !exited {
                exited = handle_signal(&thread, &mut ctx.user_context);
            }

            thread.restore(ctx);
            if exited {
                break;
            }
            if should_yield {
                // Suspend execution until is ready.
                ktrace!("spawn(): thread {:#x} yields the CPU.", thread.id);
                Yield::default().await
            }
        }
    };

    // Yield <- ThreadFuture <- PageTable <- Scheduler
    FIFO_SCHEDULER.spawn(
        FutureWithPageTable::new(Box::pin(thread_future), cr3, thread_clone),
        None,
    );

    Ok(())
}

/// Initializes the busybox shell (ash).
pub fn init_ash(first_proc: &str, args: &str) {
    kinfo!("this is : {first_proc}");
    let debug_inode = ROOT_INODE.lookup(first_proc).unwrap();
    let mut args = args.split(" ").map(|s| s.into()).collect::<Vec<String>>();
    args.insert(0, first_proc.into());
    let envp = vec![
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin".into(),
        "LD_LIBRARY_PATH=/lib:/usr/lib".into(),
    ];
    let thread = Thread::create(&debug_inode, "/", first_proc, args, envp).unwrap();
    {
        kinfo!("{}", thread.vm.lock().get_maps().unwrap());
    }
    spawn(thread).unwrap();
}
