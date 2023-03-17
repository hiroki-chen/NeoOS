//! A scheduler is a part of the operating system kernel that manages the allocation of CPU time to various processes and
//! threads. The scheduler ensures that each process and thread receives a fair share of the CPU time, and also determines
//! the order in which processes and threads are executed.
//!
//! For our simple kernel, we choose to design the most popular scheduling algorithm (Round-Robin) and Priority-based one.

use core::{future::Future, pin::Pin, task::Context};

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use lazy_static::lazy_static;
use woke::{waker_ref, Woke};

use crate::sync::mutex::SpinLock as Mutex;

use super::thread::ThreadState;

type RRTask = (Task, TaskInfo);

lazy_static! {
    pub static ref FIFO_SCHEDULER: Scheduler = Scheduler::new(Box::new(Fifo::new()));

    // TODO: Choose time quantum?
    pub static ref RR_SCHEDULER: Scheduler = Scheduler::new(Box::new(RoundRobin::new(100)));
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScheduleType {
    Fifo,
    RoundRobin,
    Priority,
}

/// An abstract task type; must be asynchronous. A task is simply a top most level future. Executors will poll on
/// a list of task futures that will poll their child executors.
pub struct Task {
    /// A task can be executed by different threads, so we need to protect the future by a mutual exclusive lock.
    future: Mutex<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>,
    /// The state of the current task.
    state: Mutex<ThreadState>,
}

impl Task {
    pub fn sleeping(&self) -> bool {
        let state = *self.state.lock();
        matches!(ThreadState::SLEEPING, state)
    }

    pub fn running(&self) -> bool {
        let state = *self.state.lock();
        matches!(ThreadState::RUNNING, state)
    }

    pub fn waiting(&self) -> bool {
        let state = *self.state.lock();
        matches!(ThreadState::WAITING, state)
    }

    pub fn set_sleeping(&self) {
        *self.state.lock() = ThreadState::SLEEPING;
    }

    pub fn set_running(&self) {
        *self.state.lock() = ThreadState::RUNNING;
    }

    pub fn set_waiting(&self) {
        *self.state.lock() = ThreadState::WAITING;
    }
}

impl Woke for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.set_waiting()
    }
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

/// The scheduling algorithm trait.
pub trait SchedAlgorithm: Send + Sync {
    /// Given a task list, decide which one should be executed; is there is no task, the scheduler needs to idle.
    fn schedule(&self) -> Option<Arc<Task>>;
    /// Pops out the first runnable process.
    fn first_ready(&self) -> Option<(Arc<Task>, Option<TaskInfo>)>;
    /// Push a task into the algorithm.
    fn add_task(&self, task: Arc<Task>, task_info: Option<TaskInfo>);
    /// Get the type.
    fn ty(&self) -> ScheduleType;
}

/// The round robin scheduling algorithm, a widely used algorithm in traditional OS. This algorithm is a real-time
/// algorithm as it responds to an event within a specific time limit.
pub struct RoundRobin {
    /// The task list.
    task_list: Mutex<VecDeque<Arc<RRTask>>>,
    ready_queue: Mutex<VecDeque<Arc<RRTask>>>,
    time_quantum: u64,
}

/// The FIFO algorithm. In FIFO scheduling algorithm, the process which arrives first will be executed first, and the
/// process which arrives later will be executed next, in the order of their arrival time. The operating system maintains
/// a queue of processes waiting to be executed, and the CPU is allocated to the process at the head of the queue. Once a
/// process has completed its execution, it is removed from the queue, and the next process in the queue is executed.
pub struct Fifo {
    task_list: Mutex<VecDeque<Arc<Task>>>,
}

impl Fifo {
    pub const fn new() -> Self {
        Self {
            task_list: Mutex::new(VecDeque::new()),
        }
    }
}

impl SchedAlgorithm for Fifo {
    fn add_task(&self, task: Arc<Task>, task_info: Option<TaskInfo>) {
        if task_info.is_some() {
            kwarn!("add_task(): FIFO ignores the `task_info` struct. You are feeding the algorithm the wrong input.");
        }

        self.task_list.lock().push_back(task);
    }

    fn first_ready(&self) -> Option<(Arc<Task>, Option<TaskInfo>)> {
        let mut task_list = self.task_list.lock();
        task_list
            .iter()
            .position(|task| task.waiting())
            .map(|idx| (task_list.remove(idx).unwrap(), None))
    }

    fn schedule(&self) -> Option<Arc<Task>> {
        self.task_list.lock().pop_front()
    }

    fn ty(&self) -> ScheduleType {
        ScheduleType::Fifo
    }
}

impl SchedAlgorithm for RoundRobin {
    fn schedule(&self) -> Option<Arc<Task>> {
        unimplemented!()
    }

    fn add_task(&self, task: Arc<Task>, task_info: Option<TaskInfo>) {
        unimplemented!()
    }

    fn first_ready(&self) -> Option<(Arc<Task>, Option<TaskInfo>)> {
        unimplemented!()
    }

    fn ty(&self) -> ScheduleType {
        ScheduleType::RoundRobin
    }
}

impl RoundRobin {
    pub const fn new(time_quantum: u64) -> Self {
        Self {
            task_list: Mutex::new(VecDeque::new()),
            ready_queue: Mutex::new(VecDeque::new()),
            time_quantum,
        }
    }
}

/// The kernel scheduler. It uses a set of policies and rules to determine how to allocate CPU time. For example, the CFS
/// scheduler uses a concept called "fairness" to determine which process or thread should receive CPU time next. The CFS
/// scheduler also maintains a red-black tree of all runnable processes, which allows it to quickly find the process that
/// has been waiting the longest.
pub struct Scheduler {
    /// The scheduling algorithm trait object.
    algorithm: Box<dyn SchedAlgorithm>,
}

impl Scheduler {
    pub const fn new(algorithm: Box<dyn SchedAlgorithm>) -> Self {
        Self { algorithm }
    }

    pub fn spawn<F>(&self, future: F, task_info: Option<TaskInfo>)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        kinfo!(
            "spawn(): the scheduler {:?} is spawning new thread!",
            self.algorithm.ty()
        );

        self.add_task(
            Arc::new(Task {
                future: Mutex::new(Box::pin(future)),
                state: Mutex::new(ThreadState::WAITING),
            }),
            task_info,
        );
    }

    fn add_task(&self, task: Arc<Task>, task_info: Option<TaskInfo>) {
        self.algorithm.add_task(task, task_info);
    }

    pub fn start_schedule(&self) {
        // Start running!
        while let Some((task, task_info)) = self.algorithm.first_ready() {
            task.set_sleeping();

            // Make an explicit poll.
            let waker = waker_ref(&task);
            let mut ctx = Context::from_waker(&waker);

            // Still not ok. Add to the task list again.
            if task.future.lock().as_mut().poll(&mut ctx).is_pending() {
                self.add_task(task.clone(), task_info);
            }
        }
    }
}
