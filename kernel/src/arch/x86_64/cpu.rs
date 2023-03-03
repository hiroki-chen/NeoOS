//! Rust port of linux/arch/x86/cpu.c

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::{format, string::String};

use apic::{LocalApic, X2Apic};
use atomic_float::AtomicF64;
use log::{debug, info, warn};
use raw_cpuid::{CpuId, CpuIdResult, FeatureInfo};
use x86::random::rdrand64;
use x86_64::{
    instructions,
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

use crate::{
    arch::{apic::AcpiSupport, pit::countdown},
    error::{Errno, KResult},
};

pub static CPU_FREQUENCY: AtomicF64 = AtomicF64::new(0.0f64);

#[cfg(feature = "multiprocessor")]
/// How many cores are available after AP initialization.
pub static CPU_COUNT: AtomicUsize = AtomicUsize::new(0usize);

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
        64 => String::from(cpuid().get_vendor_info().unwrap().as_str()),
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

    let mut apic = X2Apic {};
    apic.cpu_init();

    log::info!(
        "init_cpu(): xAPIC info:\n version: {:#x?}; id: {:#x?}, icr: {:#x?}",
        apic.version(),
        apic.id(),
        apic.icr()
    );
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

/// Halts the CPU until the next interrupt arrives.
pub fn cpu_halt() {
    instructions::hlt()
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

/// This function initializes all *Application Processors* (AP in short).
///
/// On any system with more than one logical processor we can categorize them as:
///
/// * BSP — bootstrap processor, executes modules that are necessary for booting the system
/// * AP — application processor, any processor other than the bootstrap processor
///
/// Reference: https://wiki.osdev.org/SMP & https://pdos.csail.mit.edu/6.828/2008/readings/ia32/MPspec.pdf
///
/// BSP sends AP an INIT IPI
/// BSP DELAYs (10mSec)
/// If (APIC_VERSION is not an 82489DX) {
///     BSP sends AP a STARTUP IPI
///     BSP DELAYs (200µSEC)
///     BSP sends AP a STARTUP IPI
///     BSP DELAYs (200µSEC)
/// }
/// BSP verifies synchronization with executing AP
pub fn wake_up_aps(apic_id: usize) -> KResult<()> {
    let mut lapic = X2Apic {};
    // Send init IPI.
    let mut icr = /*0x8000 |*/ 0x4000 | 0x500;
    if apic::X2Apic::does_cpu_support() {
        icr |= (apic_id as u64) << 32;
    } else {
        icr |= (apic_id as u64) << 56; // destination apic id
    }

    debug!("wake_up_aps(): sending init IPI: {:#x}", icr);

    lapic.set_icr(icr);

    Ok(())
}
