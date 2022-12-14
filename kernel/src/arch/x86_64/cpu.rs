//! Rust port of linux/arch/x86/cpu.c

use alloc::{format, string::String};

use apic::{LocalApic, XApic};
use raw_cpuid::{CpuId, FeatureInfo};
use x86::random::rdrand64;
use x86_64::{
    instructions,
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

use crate::{
    arch::apic::AcpiSupport,
    error::{Errno, KResult},
    memory::phys_to_virt,
};

pub fn cpu_name(level: i64) -> String {
    match level {
        64 => String::from(CpuId::new().get_vendor_info().unwrap().as_str()),
        0..14 => format!("i{}86", level),
        _ => String::from("i686"),
    }
}

/// Put CPU into non-responsive state.
pub fn die() -> ! {
    loop {
        unsafe {
            core::arch::asm!("nop");
        }
    }
}

pub fn cpu_id() -> usize {
    CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize
}

pub fn cpu_frequency() -> u16 {
    CpuId::new()
        .get_processor_frequency_info()
        .unwrap()
        .processor_base_frequency()
}

pub fn cpu_feature_info() -> KResult<FeatureInfo> {
    match CpuId::new().get_feature_info() {
        Some(fi) => Ok(fi),
        None => Err(Errno::EEXIST),
    }
}

/// Initialize the Advanced Programmable Interrupt Controller.
pub fn init_cpu() -> KResult<()> {
    if !XApic::does_cpu_support() {
        log::error!("init_cpu(): CPU does not support xAPIC");
        return Err(Errno::EINVAL);
    }

    let mut lapic = unsafe { XApic::new(phys_to_virt(0xfee0_0000) as usize) };
    lapic.cpu_init();

    log::info!("init_cpu(): xAPIC info:\n{:#x?}", lapic);
    unsafe {
        enable_float_processing_unit();
    }

    Ok(())
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
