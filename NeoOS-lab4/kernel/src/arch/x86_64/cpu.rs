//! Rust port of linux/arch/x86/cpu.c

use core::{
    arch::x86_64::{_fxrstor64, _fxsave64},
    sync::atomic::AtomicUsize,
};

use alloc::{boxed::Box, format, string::String, vec::Vec};

use raw_cpuid::{CpuId, CpuIdResult, FeatureInfo};
use spin::Once;
use x86::random::rdrand64;
use x86_64::{
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
    structures::tss::TaskStateSegment,
};

use crate::{
    arch::{
        apic::{init_apic, LOCAL_APIC},
        pit::countdown,
    },
    error::{Errno, KResult},
    sync::mutex::SpinLock as Mutex,
};

pub const CPU_STACK_SIZE: usize = 0x200;
pub const MAX_CPU_NUM: usize = 0x100;

pub static CPU_FREQUENCY: Once<f64> = Once::new();

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

/// The Floating-Point (FP) unit is a specialized hardware component that performs floating-point arithmetic operations,
/// such as addition, subtraction, multiplication, and division, on real numbers. The FP unit is designed to handle
/// operations involving floating-point numbers with higher precision than the regular integer arithmetic units in the
/// processor.
#[derive(Debug, Copy, Clone, Default)]
#[repr(C, align(16))]
pub struct FpState {
    /// x87 FPU Control Word (16 bits). See Figure 8-6 in the Intel® 64 and IA-32 Architectures Software Developer’s Manual
    /// Volume 1, for the layout of the x87 FPU control word.
    pub fcw: u16,
    /// x87 FPU Status Word (16 bits).
    pub fsw: u16,
    /// x87 FPU Tag Word (8 bits) + reserved (8 bits).
    pub ftw: u16,
    /// x87 FPU Opcode (16 bits).
    pub fop: u16,
    /// x87 FPU Instruction Pointer Offset ([31:0]). The contents of this field differ depending on the current addressing
    /// mode (32-bit, 16-bit, or 64-bit) of the processor when the FXSAVE instruction was executed: 32-bit mode — 32-bit IP
    /// offset. 16-bit mode — low 16 bits are IP offset; high 16 bits are reserved. 64-bit mode with REX.W — 64-bit IP
    /// offset. 64-bit mode without REX.W — 32-bit IP offset.
    pub fip: u32,
    /// x87 FPU Instruction Pointer Selector (16 bits) + reserved (16 bits).
    pub fcs: u32,
    /// x87 FPU Instruction Operand (Data) Pointer Offset ([31:0]). The contents of this field differ depending on the
    /// current addressing mode (32-bit, 16-bit, or 64-bit) of the processor when the FXSAVE instruction was executed:
    /// 32-bit mode — 32-bit DP offset. 16-bit mode — low 16 bits are DP offset; high 16 bits are reserved. 64-bit mode
    /// with REX.W — 64-bit DP offset. 64-bit mode without REX.W — 32-bit DP offset.
    pub fdp: u32,
    /// x87 FPU Instruction Operand (Data) Pointer Selector (16 bits) + reserved.
    pub fds: u32,
    /// MXCSR Register State (32 bits).
    pub mxcsr: u32,
    /// This mask can be used to adjust values written to the MXCSR register, ensuring that reserved bits are set to 0. Set
    /// the mask bits and flags in MXCSR to the mode of operation desired for SSE and SSE2 SIMD floating-point instructions.
    pub mxcsr_mask: u32,
    /// x87 FPU or MMX technology registers. Layout: [12 .. 9 | 9 ... 0] LHS = reserved; RHS = mm.
    pub mm: [u128; 8],
    /// XMM registers (128 bits per field).
    pub xmm: [u128; 16],
    /// reserved.
    pub _pad: [u64; 12],
}

impl FpState {
    pub fn new() -> Self {
        assert!(core::mem::size_of::<Self>() == 0x200);

        Self {
            // RESET_VALUE = 0x1f80
            mxcsr: 0x1f80,
            // Initial value for fctrl register.
            mxcsr_mask: 0x037f,
            ..Default::default()
        }
    }

    pub fn fxsave(&mut self) {
        unsafe {
            _fxsave64(self as *mut Self as *mut u8);
        }
    }

    pub fn fxrstor(&self) {
        unsafe {
            _fxrstor64(self as *const Self as *const u8);
        }
    }
}

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
    tss_addr: u64,
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
            tss_addr: tss as *const _ as u64,
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
            core::mem::take::<Vec<_>>(lock.as_mut())
        };
        cbs.iter().for_each(|cb| cb());
    }

    pub fn restore_stack(&self, rsp: u64) {
        assert!(
            !(self.tss_addr as *const u8).is_null(),
            "restore_stack(): internal error due to invalid tss address."
        );

        // A trick that bypasses the Rust borrow checker.
        let tss = unsafe { &mut *(self.tss_addr as *mut TaskStateSegment) };
        // The Privilege Stack Table (PST) is another feature of the x86 architecture that is related to the Interrupt
        // Stack Table (IST). The PST is used to switch between different privilege levels during system calls or
        // interrupts.
        //
        // When a user-level program makes a system call or an interrupt occurs, the processor switches from user mode
        // to kernel mode. This involves changing the privilege level of the processor from user-level privilege (Ring 3)
        // to kernel-level privilege (Ring 0). The PST provides a separate stack for each privilege level, allowing the
        // processor to switch between them as needed.
        tss.privilege_stack_table[0] = virt!(rsp);
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
        *CPU_FREQUENCY.get().unwrap() as _
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
            kinfo!("print_cpu_topology(): {:?}", topo);
        });
    }
}

/// Initialize the Advanced Programmable Interrupt Controller.
pub fn init_cpu() -> KResult<()> {
    init_apic()?;

    kinfo!(
        "init_cpu(): {:#x?}",
        LOCAL_APIC.read().get(&cpu_id()).unwrap().get_info(),
    );

    unsafe {
        enable_float_processing_unit();
    }

    Ok(())
}

/// Measures an approximate CPU frequency by `rdtsc`.
///
/// This operations does not guarantee that the measured frequency matches the real frequency due to reasons like boost.
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
            CPU_FREQUENCY.call_once(|| estimated_frequency);
            kinfo!("measure_frequency(): estimated frequency is {estimated_frequency} GHz.");
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
