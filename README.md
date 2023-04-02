# A Simple Operating System Kernel for Educational Purposes

This kernel is built with Rust (nightly channel); you must install the corresponding toolchain first. Also, the emulator QEMU must be installed, and KVM support should be enabled (you may also need to add yourself into KVM group and then do `su - $USER`).

## Build Rust Documentations

You can get the documentation via

```shell
cargo doc --target-dir=doc --no-deps
```

which outputs the doc to `./doc/doc` where you can check the documentation by the crate name. For example, you want to check `kernel`'s doc, you may open `./doc/doc/kernel/index.html`.

## UEFI and Bootloader

This kernel can boot itself by the UEFI provided by the `uefi-rs` crate. The UEFI support allows us to conveniently use some basic OS-like tools to do some pre-boot preparations. For example, we can use the simple filesystem to load the kernel image from the disk into the main memory. Also, note that the page table mapping in the UEFI environment is *identical*; that is, the physical address is its virtual address. The NeoOS kernel will remap its component and build a new page table for itself. Then it maps the old virtual address into the kernel range.

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

* ~~Implement keyboard drivers. (QEMU --> serial --> ? some sort of tty)~~
* Add support for graphic cards.
* Fix multi-core scheduling:
  * Strange page fault address (e.g., 0x0, 0x8).
  * No thread running.
  * Memory corrupted (e.g., B-Tree panics when visiting nodes). Perhaps due to lock problems.
* Implement more device drivers.
* Implement more system calls.
* Reduce memory consumption.
* Refactor the user-space thread management (perhaps using bumpalo-like memory management); the current implementation is mimicked after rCore's implementation.

## Advanced Programmable Interrupt Controller (APIC)

Intel introduced APIC after Pentium P54C CPU to enable more advanced and customable interrupt configurations. APIC consists of two major components: IOAPIC that **dispatches** interrupts, and LAPIC (Local APIC) for each core to handle the interrupt. After the target CPU finishes processing, it sends EOI to the ISR.

The IOAPIC register can be accessed by the physical address 0xffc00000, and one can verify the default address via the ACPI table obtained by the bootloader. You may need to map the address to a virtual address first.

LAPIC, in fact, handles all interrupts including the interrupt issues by the current core, that from IOAPIC, and IPI (Inter-Processor Interrupt) from other LAPICs.

## Apple Filesystem Support for Linux

Additionally, you can install `mkfs.apfs` via this link: <https://github.com/linux-apfs/linux-apfs-rw.git>. This allows one to create an APFS filesystem image on Linux platforms. For example, you can create an image `apfs.img` by

```sh
$ dd if=/dev/zero bs=1M count=400 > apfs.img
400+0 records in
400+0 records out
419430400 bytes (419 MB, 400 MiB) copied, 0.355215 s, 1.2 GB/s
$ mkfs.apfs apfs.img
$ file apfs.img
apfs.img: Apple File System (APFS), blocksize 4096
```

Then you can convert it to QCOW2 file format:

```sh
$ qemu-img convert -f raw apfs.img -O qcow2 apfs.img.qcow2
$ qemu-img resize apfs.img.qcow2 +1G
Image resized.
```

I have checked the correctness of the this tool using my own Rust library for APFS parsing.

## Running NeoOS on macOS

Yes, this kernel can be run on macOS! So one can easily use MacBook to do some tests. The following steps illustrate how to prepare necessary build and execution environment for you Mac. Note however, that compatibility on M1/M2 Macs is not tested.

* Install homwbrew if you do not have it.
* Install qemu on Mac via homwbrew.
* Install musl-gcc-cross for macOS:

```sh
brew install filosottile/musl-cross/musl-cross
```

* Execute the shell script to install musl micro runtime:

```sh
chmod +x ./prepare_darwin.sh
./prepare_darwin.sh
```

* Install `nasm` via homebrew.
* Install rust toolchain if you do not have it. This is done by:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
echo 'source $HOME/.cargo/env' >> ~/.zshrc # or ~/.bashrc
rustup -V
rustup component add rust-src llvm-tools-preview --toolchain `cat rust-toolchain`-x86_64-apple-darwin
```

That's it.
