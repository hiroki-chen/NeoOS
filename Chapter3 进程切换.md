# 实验三：进程与线程
## 实验目的

- 熟悉进程与线程的概念和它们之间的关系
- 理解并编写一个简单的线程调度器

## 相关知识

### 进程

Linux是多任务、多用户的操作系统，其进程/线程调度管理是实现这些特性的关键部分。

Linux的进程是计算机中正在执行的程序的实例。每个进程都独占一部分资源，如内存、文件描述符、寄存器等，并通过进程标识符PID来进行唯一标识。Linux中的进程是独立的，拥有自己的用户空间和内核空间，可以通过系统调用与内核进行交互。系统中的每个程序都是运行在某个进程的上下文（context）中的。上下文是由程序正确运行所需的状态组成的，包括存放在存储器中的程序的代码和数据、它的栈、它的通用目的寄存器的内容、它的程序计数器、环境变量以及打开文件描述符的集合。

在早期面向进程设计的计算机结构中，进程是程序的基本执行实体；在当代面向线程设计的计算机结构中，进程是线程的容器。程序是指令、数据及其组织形式的描述，进程是程序的实体。简而言之，进程是可执行程序与操作系统维护该进程对应的数据结构的集合。当我们在电脑上运行一个程序或在手机上打开一个app，在系统层面上就创建了一个进程。


### 线程

线程（thread）是轻量级的进程，也被称为执行单元。在 Linux 环境下线程的本质仍是进程。线程是进程的一个执行路径，一个进程中至少有一个线程，进程中的多个线程共享进程的资源。与进程不同的是，线程是在进程内部产生的，并共享相同的虚拟地址空间和文件描述符。因此，它们可以共享数据、变量和文件，具有较小的开销和更快的执行速度，这也是线程在并发编程中得到广泛应用的原因之一。

在NeoOS中，一个正在执行的程序由一组本地操作系统线程组成，每个线程都有自己的堆栈和状态，可以内部实现支持低级同步。线程之间的通信可以通过信号、共享内存以及共享内存数据结构实现。

进程和线程都有状态，例如就绪态、运行态、等待态等，这些状态会影响操作系统对它们的调度和使用。操作系统通过进程调度器在进行多任务处理时，会根据不同状态和优先级来分配处理器时间片，从而实现多个进程和线程的并发执行。

在NeoOS中，进程和线程大体上很相近，区别如下：
- 线程共享内存，但具有单独的寄存器。
- 线程共享进程的文件对象。
- 线程有单独的信号处理机制。
- 进程统一管理虚拟内存。


### 进程的调度

在过去，只有高端的服务器才具有多处理器。现在多核处理器更多地出现在个人pc、笔记本电脑上。由于架构师们难以在不增加过多功耗的同时提升单核cpu的速度，多核处理器很快变得流行。在过去，当所有的进程都是单个线程时，调度单位是进程。而所有的现代操作系统都支持多线程进程，这让调度变得更加复杂。

典型的应用程序（比如我们写的C++作业）都只使用单个cpu。为了提升他们的性能，我们可以使用多进程使之可以并行执行。多进程应用可以将工作分散到多个cpu上，cpu资源越多就运行越快。

Linux 是一种支持多核心的操作系统，可以同时利用多个 CPU 核心来执行任务，从而提高系统的性能和效率。Linux 在多核心调度时采用的是多任务轮询（Multitask poll）的方式，即把多个进程或线程安排在一个任务队列里，然后逐个按优先级分配时间片让每个任务执行，以达到系统整体最优。具体来说，Linux 的多核心任务调度机制包括以下几个方面：

- 进程管理：Linux 会将进程分配到不同的 CPU 核心上运行，从而实现多任务并行处理。同时，还有一些负载均衡的算法，可以使得系统中的进程能够公平地使用 CPU 资源。
- 线程管理：Linux 通过轮询的方式按优先级分配时间片，每个线程都可以在自己的时间片内执行。同时还可以根据不同线程的优先级、性能和特性等因素做调整。
- 中断管理：Linux 将中断和数据传输分开，中断处理程序会尽量快地执行完中断处理，以便 CPU 尽快返回上一个任务。
- 负载均衡：在多核心环境中，Linux 通过负载均衡算法协调不同内核的任务调度，以达到系统整体性能的最优化。例如，可以通过向不同 CPU 核心分配不同的任务负载，达到使 CPU 资源具有最佳使用效率。


本节我们的任务是实现FIFO（First in First out）调度算法。在FIFO调度算法中，最先到达的进程将首先被执行，较晚到达的进程将按照到达时间的先后顺序依次执行。操作系统维护一个等待执行的进程队列，CPU分配给队列最前面的进程。如果一个进程已经执行结束，它将从队列中被移除，队列中的下一个进程被执行。

## 练习


### 练习一：熟悉进程的定义

在本实验中，进程的由多个线程组合而成，结构体中的threads即该进程的线程队列。进程的成员变量包含id、内存空间、退出码、执行路径和父进程、子进程（可能有多个）等。

```rust
/// Implementation of the OS-level processes. Each process consists of several threads. See
/// kernel/process/thread.rs
pub struct Process {
    /// The process id.
    pub process_id: u64,
    /// Process group id.
    pub process_group_id: u64,
    /// The thread lists.
    pub threads: Vec<u64>,
    /// struct mm_struct *mm; shared with threads.
    pub vm: Arc<Mutex<MemoryManager<KernelPageTable>>>,
    /// Current exeuction path.
    pub exec_path: String,
    /// Wording directory.
    pub pwd: String,
    /// Opened files.
    pub opened_files: BTreeMap<u64, FileObject>,
    /// Exit code.
    pub exit_code: u64,
    /// Events like exiting
    pub event_bus: Arc<Mutex<EventBus>>,
    pub futexes: BTreeMap<u64, Arc<SimpleFutex>>,
    /// Avoid deadlock, put pid out
    /// can be self-referenced.
    pub parent: (u64, Weak<Mutex<Process>>),
    /// Children process
    pub children: Vec<(u64, Weak<Mutex<Process>>)>,
}
```

在进程类中，实现了一些方法：
- exited: 判断进程是否结束
- get_free_fd: 获取文件描述符
- add_file: 添加新文件到文件队列
- exit: 实现进程退出
- register: 实现进程注册
- search: 通过不同的方式查找进程

练习一中，我们的任务是实现进程的退出(exit)，首先，需要获取进程的所有文件资源并且释放它们，接下来，将事件设置为进程退出，最后，清空线程列表。

```rust
    pub fn exit(&mut self, exit_code: u64) {
        // TODO:make the process exit
        // First, get all file descriptors for the process and release them
        // Second, set event bus to PROCESS_QUIT
        // Third, remove all threads

        info!("process {} exit with {}", self.process_id, self.exit_code);
    }
```

### 练习二：熟悉线程的定义

在NeoOS中，线程有如下五种状态：
- RUNNING: 线程当前正在被处理器执行
- WAITING: 线程正在等待资源或事件
- SLEEPING: 线程正在休眠指定时间
- STOPPED: 线程已被信号或其他外部事件中断
- ZOMBIE: 线程已经终止，但是它的父进程阻塞或死等，形成了僵尸线程
```rust
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
```

线程类Thread定义如下，包含id、父进程、线程上下文和进程的虚拟内存。

```rust
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
```

在Thread类中，实现的方法如下：

- prepare_user_stack: 准备用户栈并初始化栈顶
- register: 激活该线程并将其注册到全局线程表`THREAD_TABLE`
- fork: 分裂线程
- from_raw: 创建具有内存指令的原始线程，返回内存栈顶

在练习二中，我们的任务是补充register和fork代码，理解prepare_user_stack中内存分配的细节。进程和线程的虚拟内存段的分配单位是 Arena，每段内存会有一个 callback来辅助实现内存页的映射、换进换出、缺页中断处理等等。ELF 文件映射通过 kernel/src/elf.rs 实现。

### 练习三：实现FIFO的调度算法

调度器是操作系统内核的一部分，它将CPU时间分配给各种进程和线程。调度器确保每个进程和线程获得相对公平的CPU时间份额，并确定进程和线程执行的顺序。对于我们的简单内核，我们选择设计最简单的FIFO算法。

练习的主要内容是在kernel/process/scheduler.rs中实现调度算法。在调度器中，任务抽象为Task类，它是异步的类。一个任务可以由不同的线程执行，所以我们需要通过互斥锁来保护future。任务有三种状态，分别是`ThreadState::SLEEPING`、`ThreadState::RUNNING`和`ThreadState::WAITING`。此外，任务还有其他的信息。

```rust
pub struct Task {
    /// A task can be executed by different threads, so we need to protect the future by a mutual exclusive lock.
    future: Mutex<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>,
    /// The state of the current task.
    state: Mutex<ThreadState>,
}

/// Some additional task information.
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskInfo {
    arrival_time: u64,
    burst_time: u64,
    completion_time: u64,
    start_time: u64,
    waiting_time: u64,
}
```

在FIFO调度算法中，最先到达的进程将首先被执行，较晚到达的进程将按照到达时间的先后顺序依次执行。操作系统维护一个等待执行的进程队列，CPU分配给队列最前面的进程。如果一个进程已经完成了它的执行，它将被从队列中移除，队列中的下一个进程被执行。

FIFO调度类的接口已经在代码中实现，我们需要补全三个成员函数，保证FIFO调度的正确运行。

```rust
impl SchedAlgorithm for Fifo {
    fn add_task(&self, task: Task, task_info: Option<TaskInfo>) {
        // TODO: add a task to the end of the task list
        unimplemented!()
    }

    fn first_ready(&self) -> Option<Arc<Task>> {
        // TODO: make the task list first ready
        unimplemented!()
    }

    fn schedule(&self) -> Option<Arc<Task>> {
        // TODO: pop a task from the task list
        unimplemented!()
    }

    fn ty(&self) -> ScheduleType {
        ScheduleType::Fifo
    }
}
```

### 练习四：实现RR调度算法（选做）

RR调度算法（Round-Robin Scheduling Algorithm）采用时间片轮转的方式分配任务。该算法中，将一个较小时间单元定义为时间量或时间片。时间片的大小通常为 10~100ms。每个进程被分配一个固定的时间片。当时间片用完后，进程被暂停并放入就绪队列的末尾，然后调度器选择下一个进程执行。

RR调度算法的特点如下：

- 公平性：每个进程都能获得相同的CPU时间片，保证了公平性。
- 响应时间短：由于每个进程都有机会执行，所以对于短作业来说，响应时间较短。
- 高吞吐量：当系统中存在大量短作业时，RR调度算法可以提供较高的吞吐量。
- 适用性：RR调度算法适用于多任务环境，特别是时间片较小的情况下。

在NeoOS中，已经写好了RR算法的定义。task_list为任务列表，ready_queue为任务队列，time_quantum为时间片。此外，已经提供了RR算法的接口。
```rust
impl RoundRobin {
    pub const fn new(time_quantum: u64) -> Self {
        Self {
            task_list: Mutex::new(VecDeque::new()),
            ready_queue: Mutex::new(VecDeque::new()),
            time_quantum,
        }
    }
}
```