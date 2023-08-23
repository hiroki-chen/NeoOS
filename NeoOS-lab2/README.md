# A Simple Operating System Kernel for Educational Purposes

This kernel is built with Rust (nightly channel); you must install the corresponding toolchain first. Also, the emulator QEMU must be installed, and KVM support should be enabled (you may also need to add yourself into KVM group and then do `su - $USER`).

## UEFI and Bootloader

This kernel can boot itself by the UEFI crate provided by the `uefi-rs` crate. The UEFI support allows us to conveniently use some basic OS-like tools to do some pre-boot preparations. For example, we can use the simple filesystem to load the kernel image from the disk into the main memory. Also, note that the page table mapping in the UEFI environment is *identical*; that is, the physical address is its virtual address. The NeoOS kernel will remap its component and build a new page table for itself. Then it maps the old virtual address into the kernel range.

Eventually, the kernel flushes the `CR3` register by writing the new page table into it and then performs a jump into the kernel entry `_start` defined in `kernel/src/lib.rs`. The metadata (e.g., ACPI table, memory maps) will be stored in a bootheader and then passed to the kernel.

## Memory Management

Similar to Linux kernel, the NeoOS kernel uses the bit allocator (a.k.a., the buddy system allocator) to manage the kernel-level memory allocation, too. However, the heap allocator (beneath the buddy system allocator) is implemented by an external crate and is enabled as global allocator in `kernel/src/lib.rs` by `#[global_allocator]` configuration. The initial heap is a static mutable array (for the ease of use), so it is `unsafe`.

## Logging and Panic

The kernel implements logging system by redirecting all the relevant macros (i.e., `println!, print!, log::info!`, etc.) to the serial port 0x3f8 whose outputs will be captured by the QEMU emulator. We also support Rust's builtin panic handlers `panic!, unimplemented!(), todo!(), assert*!`. If unrecoverable errors occur, the kernel will print the stack trace to enable debugging with gdb.

## Debugging with GDB

We support debugging with GDB. To do so, make sure you build the kernel by

```sh
$ su - $USER
$ make run DEBUG=1 OS_LOG_LEVEL=DEBUG
Formatting 'disk.img', fmt=qcow2 size=10737418240 cluster_size=65536 lazy_refcounts=off refcount_bits=16
```

One then launches another shell session and attach the kernel to the GDB debugger.

```sh
$ sudo gdb target/x86_64/debug/kernel # Load debug information
>>> GDB outputs

target remote :1234
```

## Some TODOs

* Implement keyboard drivers. (QEMU --> serial --> ? some sort of tty)
* Implement the file system.
* Implement more device drivers.

## Advanced Programmable Interrupt Controller (APIC)

Intel introduced APIC after Pentium P54C CPU to enable more advanced and customable interrupt configurations. APIC consists of two major components: IOAPIC that **dispatches** interrupts, and LAPIC (Local APIC) for each core to handle the interrupt. After the target CPU finishes processing, it sends EOI to the ISR.

The IOAPIC register can be accessed by the physical address 0xffc00000, and one can verify the default address via the ACPI table obtained by the bootloader. You may need to map the address to a virtual address first.

LAPIC, in fact, handles all interrupts including the interrupt issues by the current core, that from IOAPIC, and IPI (Inter-Processor Interrupt) from other LAPICs.
