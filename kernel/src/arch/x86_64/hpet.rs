//! HPET, or High Precision Event Timer, is a piece of hardware designed by Intel and Microsoft to replace older
//! PIT and RTC. It consists of (usually 64-bit) main counter (which counts up), as well as from 3 to 32 32-bit or
//! 64-bit wide comparators. HPET is programmed using memory mapped IO, and the base address of HPET can be found
//! using ACPI.

use acpi::HpetInfo;

use crate::{
    error::{Errno, KResult},
    memory::phys_to_virt,
};

const CAPABILITY_OFFSET: u64 = 0x00;
const GENERAL_CONFIG_OFFSET: u64 = 0x10;
const MAIN_COUNTER_OFFSET: u64 = 0xF0;
// Useful constants.
// See https://wiki.osdev.org/HPET
const LEG_RT_CNF: u64 = 2;
const ENABLE_CNF: u64 = 1;

const TN_VAL_SET_CNF: u64 = 0x40;
const TN_TYPE_CNF: u64 = 0x08;
const TN_INT_ENB_CNF: u64 = 0x04;
const T0_CONFIG_CAPABILITY_OFFSET: u64 = 0x100;
const T0_COMPARATOR_OFFSET: u64 = 0x108;

const PER_INT_CAP: u64 = 0x10;
const LEG_RT_CAP: u64 = 0x8000;
#[derive(Debug, Clone)]
pub struct Hpet {
    base: u64,
}

impl Hpet {
    pub fn new(base: u64) -> Self {
        Self {
            base: phys_to_virt(base),
        }
    }

    pub fn read(&self, offset: u64) -> u64 {
        unsafe {
            (self.base as *const u64)
                .add(offset as usize)
                .read_volatile()
        }
    }

    pub fn write(&self, offset: u64, val: u64) {
        unsafe {
            (self.base as *mut u64)
                .add(offset as usize)
                .write_volatile(val);
        }
    }

    pub fn toggle(&self, enable: bool) {
        let mut configurations = self.read(GENERAL_CONFIG_OFFSET);
        configurations &= match enable {
            true => LEG_RT_CNF | ENABLE_CNF,
            false => !(LEG_RT_CNF | ENABLE_CNF),
        };

        self.write(GENERAL_CONFIG_OFFSET, configurations);
    }
}

/// 1. Find HPET base address in 'HPET' ACPI table.
/// 2. Calculate HPET frequency (f = 10^15 / period).
/// 3. Save minimal tick (either from ACPI table or configuration register).
/// 4. Initialize comparators.
/// 5. Set ENABLE_CNF bit.
pub fn init_hpet(hpet_info: &HpetInfo) -> KResult<()> {
    kinfo!("init_hpet(): detected hpet_table!");
    kinfo!("init_hpet(): HPET information:\n{:#x?}", hpet_info);

    let hpet = Hpet::new(hpet_info.base_address as u64);
    // Disable it first.
    hpet.toggle(false);

    let cap = hpet.read(CAPABILITY_OFFSET);
    if cap & LEG_RT_CAP == 0 {
        kwarn!("init_hpet(): missing capability LEG_RT_CAP.");
        return Err(Errno::EINVAL);
    }

    // Main counter tick period in femtoseconds (10^-15 seconds). Must not be zero, must be
    // less or equal to 0x05F5E100, or 100 nanoseconds.
    let counter_clk_period_fs = cap >> 0x20;
    let desired_fs_period: u64 = 2_250_286 * 1_000_000;
    let clk_periods_per_kernel_tick: u64 = desired_fs_period / counter_clk_period_fs;

    let t0_cap = hpet.read(T0_CONFIG_CAPABILITY_OFFSET);
    if t0_cap & PER_INT_CAP == 0 {
        kwarn!("init_hpet(): T0 missing capability PER_INT_CAP {t0_cap}");
        return Err(Errno::EINVAL);
    }

    let counter = hpet.read(MAIN_COUNTER_OFFSET);
    let t0_config_word: u64 = TN_VAL_SET_CNF | TN_TYPE_CNF | TN_INT_ENB_CNF;
    hpet.write(T0_CONFIG_CAPABILITY_OFFSET, t0_config_word);
    hpet.write(T0_COMPARATOR_OFFSET, counter + clk_periods_per_kernel_tick);
    // set interval
    hpet.write(T0_COMPARATOR_OFFSET, clk_periods_per_kernel_tick);

    // Enable.
    hpet.toggle(true);

    kinfo!("init_hpet(): successfully initialized HPET.");
    Ok(())
}
