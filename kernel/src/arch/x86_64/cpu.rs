//! Rust port of linux/arch/x86/cpu.c
//!
use crate::error::Errno;

use alloc::{format, string::String};
use log::error;
use raw_cpuid::CpuId;
use x86_64::instructions;

use crate::error::KResult;

pub fn cpu_name(level: i64) -> String {
    match level {
        64 => String::from(CpuId::new().get_vendor_info().unwrap().as_str()),
        0..14 => format!("i{}86", level),
        _ => format!("i686"),
    }
}

pub fn cpu_id() -> usize {
    CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize
}

pub fn validate_cpu() -> KResult<()> {
    let mut err_flags = 0u32;
    let mut cpu_level = 0i64;
    let mut req_level = 0i64;

    check_cpu(&mut cpu_level, &mut req_level, &mut err_flags);

    if cpu_level < req_level {
        error!(
            "validate_cpu(): This kernel requires an {} CPU. ",
            cpu_name(req_level)
        );
        error!("\t\tWe only detected an {} CPU.", cpu_name(cpu_level));
        return Err(Errno::EINVAL);
    }

    // Register APICs
    todo!()
}

/// Halts the CPU until the next interrupt arrives.
pub fn cpu_halt() {
    instructions::hlt()
}

pub fn check_cpu(cpu_level: &mut i64, req_level: &mut i64, err_flags: &mut u32) {
    todo!()
}
