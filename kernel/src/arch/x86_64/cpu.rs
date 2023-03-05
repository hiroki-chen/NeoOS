//! Rust port of linux/arch/x86/cpu.c

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::{boxed::Box, format, string::String, vec::Vec};

use atomic_float::AtomicF64;
use log::{info, warn};
use raw_cpuid::{CpuId, CpuIdResult, FeatureInfo};
use x86::random::rdrand64;
use x86_64::{
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
    structures::tss::TaskStateSegment,
};

use crate::{
    arch::{
        apic::{AcpiSupport, X2Apic},
        pit::countdown,
    },
    error::{Errno, KResult},
    sync::mutex::SpinLock as Mutex,
};

pub const CPU_STACK_SIZE: usize = 0x200;
pub const MAX_CPU_NUM: usize = 0x100;

pub static CPU_FREQUENCY: AtomicF64 = AtomicF64::new(0.0f64);

/// How many cores are available after AP initialization.
#[cfg(feature = "multiprocessor")]
pub static AP_UP_NUM: AtomicUsize = AtomicUsize::new(0usize);

/// How many cores in total
#[cfg(feature = "multiprocessor")]
pub static CPU_NUM: spin::Once<usize> = spin::Once::new();

/// The BSP CPU ID.
#[cfg(feature = "multiprocessor")]
pub static BSP_ID: spin::Once<u32> = spin::Once::new();

/// Although this static mutable array is safe as long as each core does not access other's data structure.
#[cfg(feature = "multiprocessor")]
pub static mut CPUS: [spin::Once<AbstractCpu>; MAX_CPU_NUM] = {
    const CPU: spin::Once<AbstractCpu> = spin::Once::new();
    [CPU; MAX_CPU_NUM]
};

/// The Rust-like representation of the header stored in `ap_trampoline.S`.
///
/// This struct serializes the memory bytes into a human-readable struct that is easy for us to work with, and
/// since we need to check if an AP has been correctly initialized, this struct (written by AP trampoline code)
/// can provide us with rich information.
///
/// # The Raw Header in Nasm
/// ```asm
/// .page_table: dq 0
/// .cpu_id: dq 0
/// .ready: dq 0
/// .stack_top: dq 0
/// .stack_bottom: dq 0
/// .trampoline_code: dq 0
/// ```
/// This header can be read at `AP_TRAMPOLINE + core::mem::size_of::<u64>() as u64`. For simplicity, we avoid
/// padding by enforcing all types to be [`u64`].
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ApHeader {
    pub page_table: u64,
    pub cpu_id: u64,
    pub ready: u64,
    pub stack_top: u64,
    pub stack_bottom: u64,
    pub trampoline_code: u64,
}

impl ApHeader {
    /// Checks whether the memory representation is zeros; otherwise, we may access the wrong memory region.
    #[inline(always)]
    pub fn sanity_check(&self) -> bool {
        self.page_table == 0
            && self.cpu_id == 0
            && self.ready == 0
            && self.stack_top == 0
            && self.stack_bottom == 0
            && self.trampoline_code == 0
    }

    /// Make a copy from a raw pointer.
    pub fn from_raw(mut raw: *mut Self) -> Self {
        unsafe {
            let ptr = core::sync::atomic::AtomicPtr::from_mut(&mut raw);
            (*(ptr.load(core::sync::atomic::Ordering::SeqCst))).clone()
        }
    }
}

/// This struct represents an *abstract* CPU core that is easy for us to get around with.
///
/// For each core, it has independent gdt, idt, tss and other kernel components, so it is essential for us
/// to seperate each core and deal with them correctly.
pub struct AbstractCpu {
    /// The local APIC id of the current CPU.
    pub cpu_id: usize,
    /// The global descriptor table (GDT).
    gdt_addr: u64,
    /// The task state segment (TSS) is a structure on x86-based computers which holds information about a task.
    /// It is used by the operating system kernel for task management. Specifically, the following information is
    /// stored in the TSS:
    /// * Processor register state
    /// * I/O port permissions
    /// * Inner-level stack pointers
    /// * Previous TSS link
    tss: &'static TaskStateSegment,
    /// The Inter-Processor Interrupt event queue (callbacks)
    ipi_queue: Mutex<Vec<Box<dyn Fn() + Send + 'static>>>,
    /// In Long Mode, the TSS does not store information on a task's execution state, instead it is used to store the
    /// Interrupt Stack Table.
    ///
    /// In addition to the per thread stacks, there are specialized stacks associated with each CPU.  These stacks
    /// are only used while the kernel is in control on that CPU; when a CPU returns to user space the specialized
    /// stacks contain no useful data.  The main CPU stacks are:
    /// * Interrupt stack.
    /// * Double-fault stack.
    stack_addr: u64,
}

impl AbstractCpu {
    pub fn new(gdt_addr: u64, tss: &'static TaskStateSegment, stack_addr: u64) -> Self {
        Self {
            cpu_id: cpu_id(),
            gdt_addr,
            tss,
            stack_addr,
            ipi_queue: Mutex::new(Vec::new()),
        }
    }

    pub fn current() -> KResult<&'static mut Self> {
        unsafe {
            CPUS.get_mut(cpu_id())
                .ok_or(Errno::EEXIST)?
                .get_mut()
                .ok_or(Errno::EINVAL)
        }
    }

    pub fn push_event(&self, cb: Box<dyn Fn() + Send + 'static>) {
        self.ipi_queue.lock().push(cb);
    }

    pub fn pop_event(&self) {
        let cbs = {
            let mut lock = self.ipi_queue.lock();
            core::mem::replace(lock.as_mut(), Vec::new())
        };
        cbs.iter().for_each(|cb| cb());
    }
}

/// This sets up the current CPU by [`cpu_id()`].
pub fn init_current_cpu(
    gdt_addr: u64,
    tss: &'static TaskStateSegment,
    stack_addr: u64,
) -> KResult<()> {
    unsafe {
        let current = CPUS.get_mut(cpu_id()).ok_or(Errno::EEXIST)?;
        current.call_once(|| AbstractCpu::new(gdt_addr, tss, stack_addr));
    }

    Ok(())
}

pub fn cpuid() -> CpuId {
    CpuId::with_cpuid_fn(|a, c| {
        let result = unsafe { core::arch::x86_64::__cpuid_count(a, c) };
        CpuIdResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    })
}

pub fn cpu_name(level: i64) -> String {
    match level {
        64 => cpuid().get_vendor_info().unwrap().as_str().into(),
        0..14 => format!("i{}86", level),
        _ => String::from("i686"),
    }
}

/// Put CPU into non-responsive state.
///
/// # Purpose of this function
///
/// The function `die()` will put the CPU into an endless loop. This function is invoked
/// typically after an unrecoverable error within the kernel world (e.g., allocation error).
pub fn die() -> ! {
    unsafe {
        core::arch::asm!("cli");
        loop {
            core::arch::asm!("nop");
        }
    }
}

pub fn cpu_id() -> usize {
    cpuid().get_feature_info().unwrap().initial_local_apic_id() as usize
}

pub fn cpu_frequency() -> u16 {
    let freq = match cpuid().get_processor_frequency_info() {
        None => 0,
        Some(f) => f.processor_base_frequency(),
    };

    if freq == 0 {
        warn!("cpu_frequency(): cpuid returns 0. Trying to fetch MSRs. ");
        // Get frequency by MSR?

        CPU_FREQUENCY.load(Ordering::Relaxed) as u16
    } else {
        freq
    }
}

pub fn cpu_feature_info() -> KResult<FeatureInfo> {
    match cpuid().get_feature_info() {
        Some(fi) => Ok(fi),
        None => Err(Errno::EEXIST),
    }
}

pub fn print_cpu_topology() {
    if let Some(info) = cpuid()
        .get_extended_topology_info_v2()
        .or(cpuid().get_extended_topology_info())
    {
        info.for_each(|topo| {
            log::info!("print_cpu_topology(): {:?}", topo);
        });
    }
}

/// Initialize the Advanced Programmable Interrupt Controller.
pub fn init_cpu() -> KResult<()> {
    if !X2Apic::does_cpu_support() {
        log::error!("init_cpu(): CPU does not support x2APIC");
        return Err(Errno::EINVAL);
    }

    let lapic = X2Apic {};
    lapic.init();
    log::info!("init_cpu(): {:#x?}", lapic.get_info());

    unsafe {
        enable_float_processing_unit();
    }

    Ok(())
}

pub fn measure_frequency() {
    // Measure.
    x86_64::instructions::interrupts::without_interrupts(|| {
        // PIT => 10ms.
        unsafe {
            let mut aux = 0u32;
            let begin = core::arch::x86_64::__rdtscp(&mut aux as *mut _);
            countdown(10_000);
            let end = core::arch::x86_64::__rdtscp(&mut aux as *mut _);

            let estimated_frequency = (end - begin) as f64 / 10_000_000f64;
            CPU_FREQUENCY.store(estimated_frequency, Ordering::Relaxed);
            info!("measure_frequency(): estimated frequency is {estimated_frequency} GHz.");
        }
    });
}

unsafe fn enable_float_processing_unit() {
    Cr4::update(|cr4| {
        // enable fxsave/fxrstor
        cr4.insert(Cr4Flags::OSFXSR);
        // sse
        cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    });
    Cr0::update(|cr0| {
        // enable fpu
        cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
        cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    });
}

/// Wrapper function for getting random number in the CPU. Mounted as `/dev/random`.
pub fn rdrand() -> u64 {
    let mut ans = 0;
    unsafe { rdrand64(&mut ans) };
    ans
}

/// Dump the flag register.
pub unsafe fn dump_flags() -> u64 {
    let mut flags: u64;

    core::arch::asm!("pushfq; pop {}", out(reg) flags);
    flags
}
