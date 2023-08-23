//! IOAPIC stands for Input/Output Advanced Programmable Interrupt Controller. It is a hardware component in a computer
//! system that manages interrupt signals from input/output (I/O) devices and distributes them to the appropriate
//! processor cores or threads.
//!
//! The IOAPIC acts as a central hub for interrupt signals and provides more flexibility and better performance compared
//! to traditional interrupt controllers. With an IOAPIC, multiple devices can share the same interrupt signal, reducing
//! the number of interrupts that need to be handled by the system. It also allows the system to assign specific interrupt
//! signals to specific processor cores, which can improve overall system performance by reducing contention for resources.
//!  
//! IOAPICs are commonly found in modern computer systems, particularly in servers, and are usually integrated into the
//! chipset or motherboard. They are typically programmable and can be configured through system software to manage
//! interrupt signals according to the specific requirements of the system.

use bit_field::BitField;

pub const DEFAULT_IOAPIC_ADDR: u64 = 0xfec0_0000;
pub const IOAPICID: u8 = 0x00;
pub const IOAPICVER: u8 = 0x01;
pub const IOAPICARB: u8 = 0x02;

pub const REDIR_NONE: u32 = 0x0000_0000;
pub const REDIR_DISABLED: u32 = 0x0001_0000;

#[inline(always)]
fn ioapic_rediration_table(val: u8) -> u8 {
    // lower-32bits (add +1 for upper 32-bits).
    0x10 + val * 2
}

/// The wrapper for IOAPIC.
pub struct IoApic {
    /// The io-mapped register.
    select_register: u64,
    /// The data register.
    window_register: u64,
}

#[derive(Debug, Clone)]
pub struct IoApicInfo {
    version: u8,
    id: u8,
}

impl IoApic {
    /// Create a new [`IoApic`] given the IO-mapped address `base`.
    ///
    /// # Note
    ///
    /// The caller may need to map the regiter into a valid virtual address.
    pub fn new(base: u64) -> Self {
        Self {
            select_register: base,
            window_register: base + 0x10,
        }
    }

    pub fn get_info(&self) -> IoApicInfo {
        IoApicInfo {
            version: self.read(IOAPICVER).get_bits(0..8) as u8,
            id: self.read(IOAPICID).get_bits(24..28) as u8,
        }
    }

    pub fn write(&self, reg: u8, val: u32) {
        unsafe {
            (self.select_register as *mut u32).write_volatile(reg as _);
            (self.window_register as *mut u32).write_volatile(val);
        }
    }

    pub fn read(&self, reg: u8) -> u32 {
        unsafe {
            (self.select_register as *mut u32).write_volatile(reg as _);
            (self.window_register as *mut u32).read_volatile()
        }
    }

    pub fn get_irq_vector(&self, irq: u8) -> u8 {
        self.read(ioapic_rediration_table(irq).get_bits(0..8)) as _
    }

    pub fn update_irq_vector(&self, irq: u8, irq_vec: u8, target: u8, flags: u32) {
        self.write(ioapic_rediration_table(irq), irq_vec as u32 | flags);
        self.write(ioapic_rediration_table(irq) + 1, (target as u32) << 24);
    }

    /// Different from [`update_irq_vector`], this function *overwrites* the IRQ vector.
    pub fn set_irq_vector(&self, irq: u8, irq_vec: u8) {
        let mut old = self.read(ioapic_rediration_table(irq));
        let old_vec = old.get_bits(0..8);
        if !(0x20..=0xfe).contains(&old_vec) {
            old |= REDIR_DISABLED;
        }

        self.write(
            ioapic_rediration_table(irq),
            *old.set_bits(0..8, irq_vec as u32),
        );
    }

    /// Enable the Interrupt Request characterized by `irq` on CPU `target`.
    pub fn enable_irq(&self, irq: u8, target: u8) {
        let irq_vec = self.get_irq_vector(irq);
        self.update_irq_vector(irq, irq_vec, target, REDIR_NONE);
    }

    /// Disables the IRQ.
    pub fn disable_irq(&self, irq: u8) {
        let irq_vec = self.get_irq_vector(irq);
        self.update_irq_vector(irq, irq_vec, 0, REDIR_DISABLED);
    }
}
