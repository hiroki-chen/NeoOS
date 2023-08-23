//! In computing, Intel's Advanced Programmable Interrupt Controller (APIC) is a family of interrupt controllers.
//! As its name suggests, the APIC is more advanced than Intel's 8259 Programmable Interrupt Controller (PIC),
//! particularly enabling the construction of multiprocessor systems. It is one of several architectural designs
//! intended to solve interrupt routing efficiency issues in multiprocessor computer systems.
//!
//! This module implements all the interfaces used to communicate with the lagacy PIC component. In order to make
//! APIC work correctly, we need to mask the PIC so that IRQs can be properly delivered. If there is a need to use
//! PIC, the module also helps witt this job.

use core::sync::atomic::Ordering;

use lazy_static::lazy_static;
use spin::RwLock;
use x86_64::instructions::port::Port;

use crate::irq::{IrqType, IRQ_TYPE};

lazy_static! {
    pub static ref MASTER_PIC: RwLock<Pic> = RwLock::new(Pic::new(0x20));
    pub static ref SLAVE_PIC: RwLock<Pic> = RwLock::new(Pic::new(0xa0));
}

/// The Programmable Interrupt Controller abstraction.
#[derive(Debug)]
pub struct Pic {
    base: Port<u8>,
    data: Port<u8>,
}

/// Useful when the kernel does not need to use PIC because there is APIC available.
pub fn disable_pic() {
    unsafe {
        MASTER_PIC.write().data.write(0xff);
        SLAVE_PIC.write().data.write(0xff);
    }
}

pub fn init_pic() {
    let mut master = MASTER_PIC.write();
    let mut slave = SLAVE_PIC.write();

    unsafe {
        master.data.write(0x11);
        slave.data.write(0x11);

        master.data.write(0x20);
        slave.data.write(0x28);

        // Cascade mode
        master.data.write(0x4);
        slave.data.write(0x2);

        master.data.write(0x1);
        slave.data.write(0x1);

        // Unmask interrupts
        master.data.write(0x0);
        slave.data.write(0x0);

        // Ack remaining interrupts
        master.ack();
        slave.ack();

        // Tell the atomic data.
        IRQ_TYPE.store(IrqType::Pic, Ordering::Release);
    }
}

impl Pic {
    pub fn new(addr: u64) -> Self {
        Self {
            base: Port::new(addr as u16),
            data: Port::new(addr as u16 + 0x1),
        }
    }

    pub fn ack(&mut self) {
        unsafe {
            self.base.write(0x20);
        }
    }

    pub fn get_isr(&mut self) -> u8 {
        unsafe {
            self.base.write(0x0a);
            self.data.read()
        }
    }

    pub fn set_mask(&mut self, irq: u8) -> bool {
        if irq >= 8 {
            log::warn!("mask(): trying to set IRQ >= 8. This operation will be ignored.");
            false
        } else {
            unsafe {
                let mut mask = self.data.read();
                mask |= 1 << irq;
                self.data.write(mask);
            }

            true
        }
    }

    pub fn unset_mask(&mut self, irq: u8) -> bool {
        if irq >= 8 {
            log::warn!("mask(): trying to set IRQ >= 8. This operation will be ignored.");
            false
        } else {
            unsafe {
                let mut mask = self.data.read();
                mask &= !(1 << irq);
                self.data.write(mask);
            }

            true
        }
    }
}
