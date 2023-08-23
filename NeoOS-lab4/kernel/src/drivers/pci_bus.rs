//! The PCI (Peripheral Component Interconnect) bus was defined to establish a high performance
//! and low cost local bus that would remain through several generations of products.
//!
//! This module probes devices on the BUS and initialize them.

use alloc::format;
use pci::{CSpaceAccessMethod, Location, PCIDevice, PortOps, BAR};
use x86_64::instructions::port::Port;

use crate::{
    drivers::{block::init_ahci, intel_e1000::init_network, PCI_DRIVERS},
    error::KResult,
    function, kdebug, kinfo,
    memory::phys_to_virt,
};

pub const PCI_COMMAND: u16 = 0x04;
pub const PCI_CAP_PTR: u16 = 0x34;
pub const PCI_INTERRUPT_LINE: u16 = 0x3c;
pub const PCI_INTERRUPT_PIN: u16 = 0x3d;

pub const PCI_MSI_CTRL_CAP: u16 = 0x00;
pub const PCI_MSI_ADDR: u16 = 0x04;
pub const PCI_MSI_UPPER_ADDR: u16 = 0x08;
pub const PCI_MSI_DATA_32: u16 = 0x08;
pub const PCI_MSI_DATA_64: u16 = 0x0C;

pub const PCI_CAP_ID_MSI: u8 = 0x05;

struct Ops;

impl PortOps for Ops {
    unsafe fn read16(&self, port: u16) -> u16 {
        Port::new(port).read()
    }

    unsafe fn read32(&self, port: u16) -> u32 {
        Port::new(port).read()
    }

    unsafe fn read8(&self, port: u16) -> u8 {
        Port::new(port).read()
    }

    unsafe fn write16(&self, port: u16, val: u16) {
        Port::new(port).write(val);
    }

    unsafe fn write32(&self, port: u16, val: u32) {
        Port::new(port).write(val);
    }

    unsafe fn write8(&self, port: u16, val: u8) {
        Port::new(port).write(val);
    }
}

pub fn init_pci() -> KResult<()> {
    let devices_connected = unsafe { pci::scan_bus(&Ops, CSpaceAccessMethod::IO) };

    for device in devices_connected.into_iter() {
        kinfo!(
            "init_pci(): {:02x}:{:02x}.{} {:#x} {:#x} ({} {}) irq: {}:{:?}",
            device.loc.bus,
            device.loc.device,
            device.loc.function,
            device.id.vendor_id,
            device.id.device_id,
            device.id.class,
            device.id.subclass,
            device.pic_interrupt_line,
            device.interrupt_pin,
        );

        // Initialize this device.
        init_device(&device)?;
    }

    Ok(())
}

fn init_device(device: &PCIDevice) -> KResult<()> {
    if device.id.class == 0x01 && device.id.subclass == 0x06 {
        // Mass storage class
        // SATA subclass
        if let Some(BAR::Memory(addr, len, _, _)) = device.bars[5] {
            kinfo!("found AHCI dev {:x?} BAR5 {:x?}", device, addr);
            unsafe { enable_irq(device.loc) }.unwrap_or_default();

            let vaddr = phys_to_virt(addr);
            match init_ahci(vaddr as usize, len as usize) {
                Ok(driver) => {
                    PCI_DRIVERS.lock().entry(device.loc).or_insert(driver);
                }
                Err(errno) => return Err(errno),
            }
        }
    }

    if device.id.vendor_id == 0x8086 && [0x100e, 0x10d3, 0x100f].contains(&device.id.device_id) {
        if let Some(BAR::Memory(addr, len, _, _)) = device.bars[0] {
            // Intel ethernet controller.
            kinfo!(
                "found Intel ethernet controller {:x?} BAR0 {:x?}",
                device,
                addr
            );
            let irq = unsafe { enable_irq(device.loc) }.map(|irq| irq as u8);

            let vaddr = phys_to_virt(addr);
            let interface_name = format!("ens{}f{}", device.loc.device, device.loc.function);
            match init_network(irq, vaddr as usize, len as usize, interface_name) {
                Ok(driver) => {
                    PCI_DRIVERS.lock().entry(device.loc).or_insert(driver);
                }
                Err(errno) => return Err(errno),
            }
        }
    }

    Ok(())
}

unsafe fn enable_irq(loc: Location) -> Option<usize> {
    let ops = &Ops;
    let am = CSpaceAccessMethod::IO;

    // 23 and lower are used
    static mut MSI_IRQ: u32 = 23;

    let orig = am.read16(ops, loc, PCI_COMMAND);
    // IO Space | MEM Space | Bus Mastering | Special Cycles | PCI Interrupt Disable
    am.write32(ops, loc, PCI_COMMAND, (orig | 0x40f) as u32);

    // find MSI cap
    let mut msi_found = false;
    let mut cap_ptr = am.read8(ops, loc, PCI_CAP_PTR) as u16;
    let mut assigned_irq = None;
    while cap_ptr > 0 {
        let cap_id = am.read8(ops, loc, cap_ptr);
        if cap_id == PCI_CAP_ID_MSI {
            let orig_ctrl = am.read32(ops, loc, cap_ptr + PCI_MSI_CTRL_CAP);
            // The manual Volume 3 Chapter 10.11 Message Signalled Interrupts
            // 0 is (usually) the apic id of the bsp.
            am.write32(ops, loc, cap_ptr + PCI_MSI_ADDR, 0xfee00000);
            MSI_IRQ += 1;
            let irq = MSI_IRQ;
            assigned_irq = Some(irq as usize);
            // we offset all our irq numbers by 32
            if (orig_ctrl >> 16) & (1 << 7) != 0 {
                // 64bit
                am.write32(ops, loc, cap_ptr + PCI_MSI_DATA_64, irq + 32);
            } else {
                // 32bit
                am.write32(ops, loc, cap_ptr + PCI_MSI_DATA_32, irq + 32);
            }

            // enable MSI interrupt, assuming 64bit for now
            am.write32(ops, loc, cap_ptr + PCI_MSI_CTRL_CAP, orig_ctrl | 0x10000);
            kdebug!(
                " MSI control {:#b}, enabling MSI interrupt {}",
                orig_ctrl >> 16,
                irq
            );
            msi_found = true;
        }
        kinfo!("PCI device has cap id {} at {:#X}", cap_id, cap_ptr);
        cap_ptr = am.read8(ops, loc, cap_ptr + 1) as u16;
    }

    if !msi_found {
        // Use PCI legacy interrupt instead
        // IO Space | MEM Space | Bus Mastering | Special Cycles
        am.write32(ops, loc, PCI_COMMAND, (orig | 0xf) as u32);
        kinfo!("MSI not found, using PCI interrupt");
    }

    kinfo!(" pci device enable done");

    assigned_irq
}
