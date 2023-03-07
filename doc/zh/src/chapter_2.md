# 启动操作系统

千里之行，始于足下。精妙绝伦的操作系统内核没有启动工具，最后也只能成为一些无用之物。在本节我们将介绍基于 UEFI 的 bootloader 是如何对我们的操作系统进行启动的。

## 准备一个极简内核

在本小节，我们为了避免介绍内核的诸多细节给读者造成困扰，我们首先创建一个 `kernel.S` 汇编文件。这个程序简单地执行死循环来进行测试。

```s
.global _start
.text

_start:
__loop:
  jmp __loop
```

其中我们一定需要导出全局符号 `_start`，否则 gcc 会找不到入口。我们随后使用 gcc 对其进行汇编，生成一个裸 ELF 二进制文件：

```shell
gcc kernel.S -o kernel.img -nostdlib
```

## 什么是 UEFI

UEFI是英文“Unified Extensible Firmware Interface”的缩写，翻译成中文是“统一可扩展固件接口”。它是一种计算机固件接口标准，用于取代过时的BIOS（基本输入输出系统），成为新一代计算机固件接口。UEFI具有许多优点，包括更快的启动时间，更大的硬盘驱动器支持，更安全的启动过程和更强大的系统管理功能等。它还支持更多的操作系统，并允许操作系统和硬件之间更紧密的交互。UEFI还具有可扩展性，因此可以轻松添加新功能和支持新硬件。UEFI是由Intel开发的，现在已经成为了业界的标准，大多数现代计算机都采用了UEFI。不过，UEFI和传统BIOS在启动引导过程原理上**没有本质区别**。

UEFI 一个比较重要的特性就是它所有与硬件交互的接口都是**统一**（被称为“协议”，即 Protocol）的，而且所有硬件都被分配了一个全局唯一的标识符（UUID），而且不随着硬件品牌、种类的变化而变化。其次，UEFI 相当于提供了一个**微型的操作系统内核**，在这个内核之中，我们可以访问启动硬盘，进行内存分配，网络访问，进行图形化界面操作等基本行为，然后我们通过这个迷你内核来启动真正的庞大的操作系统内核。

UEFI 引导操作系统内核启动的步骤如下：

1.计算机主板上电之后，现代主板中自带了一个启动管理器（UEFI 的标准之一），它会通过读取存在 NVRAM 中的配置信息选择一个 bootloader 启动。一般而言，UEFI 默认读取的分区盘叫做 EFI 系统分区（EFI System Partition， ESP）。bootloader 的路径一般是 `EFI\BOOT\BOOT<ARCH>.efi`，其中 `<ARCH>` 表示系统架构，例如`\EFI\BOOT\BOOTX64.efi`。

> **提示：** 自己尝试过手动设置 GPT 分区 + UEFI 启动的同学可能会对 ESP 这个特殊系统分区比较熟悉。

2.bootloader 设置好内核启动所需的各种部件，例如获取 ACPI 表，设置页表映射，探测物理内存分布，将操作系统内核加载到主存中，设置操作系统内核栈，然后将这些信息存储在一个特定物理地址后，通过 `exitBootServices` 关闭 UEFI 提供的主要模块。

3.切换页表，跳转到操作系统内核的入口，然后 UEFI 启动正式结束。

## 使用 Rust 开发基于 UEFI 的 Bootloader

### Rust 裸机开发指北

我们开发 bootloader 的主要内容是聚焦在上一小节的第二步，即为操作系统内核的启动作准备工作。使用 C/C++ 的话，我们有 [GNU-EFI](https://wiki.osdev.org/GNU-EFI) 这个开发套件可以用。但是在 Rust 世界中，也有人为 Rust 开发了一套能够进行 UEFI 开发的库，即 [uefi-rs](https://crates.io/uefi-rs)。在此，我们可以使用 Rust 对 UEFI bootloader 进行开发。

我们从一个最简单的目标进行。首先，在某个目录下面创建一个新的 cargo 工程，我们称之为 `bootloader`。

```shell
$ cargo new bootloader
     Created binary (application) `bootloader` package
```

项目的目录分布如下：

```shell
.
├── Cargo.toml
└── src
    └── main.rs
```

要编写操作系统内核，我们*不可以依赖于任何操作系统功能*。 这意味着我们不能使用线程、文件、堆内存、网络、随机数、IO 或任何其他需要操作系统抽象或特定硬件的功能。因为我们正在尝试编写我们自己的操作系统和我们自己的驱动程序。那么，由于没有任何操作系统能够支持我们进行复杂操作， Rust 提供的 `std` 库在这个场景中是不适用的了。所以我们要**禁用它**。不过，需要注意的是，禁用了标准库并不意味着 Rust 的其他功能都不能用了。禁用标准库只是**让依赖于操作系统的功能**不可用了。在我们实现了操作系统的功能之后，我们可以自己写一个标准库出来。

这一步很简单，只需要在 `src/main.rs` 这个文件中加入一句话即可。

```rust
#![no_std]

fn main() {
    println!("Hello World!");
}
```

很明显，这个文件被 cargo 拒绝了编译。

```shell
   Compiling playground v0.0.1 (/playground)
error: cannot find macro `println` in this scope
 --> src/main.rs:4:5
  |
4 |     println!("Hello World!");
  |     ^^^^^^^

error: `#[panic_handler]` function required, but not found

error: language item required, but not found: `eh_personality`
  |
  = note: this can occur when a binary crate with `#![no_std]` is compiled for a target where `eh_personality` is defined in the standard library
  = help: you may be able to compile for a target that doesn't need `eh_personality`, specify a target with `--target` or in `.cargo/config`

error: could not compile `playground` due to 3 previous errors
```

一下子爆出了三个错误，我们仔细分析。

* `error: cannot find macro println in this scope`：这是由于 `println!` 这个宏是标准库导出的符号。我们禁用标准库后自然不存在这个宏。
* `error: #[panic_handler] function required, but not found`：错误处理函数不存在。在 Rust 提供的标准库中，是有一个默认的错误处理函数的，在程序遇到不可恢复的错误的时候，这个函数自动被调用，然后进行一些栈帧的打印，停止程序。禁用标准库后我们需要自己实现一个。实现方案也很简单：

```rust
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

> **提示：** `!` 代表永不返回。很容易理解，程序崩溃后，是不能回退到之前的状态的。而 `PanicIno` 这个类是核心库（core）提供的一个带有错误信息的对象。因为我们没有实现 IO，所以不能用它进行 debug。我们的错误处理就是简单进行死循环。

* `error: language item required, but not found: eh_personality`：Rust 内部实现中存在一种叫做 “language item” 的东西。在编译器实现中，Rust 没有强制将所有的功能都让自己给实现了，它对一些函数、符号的实现可以通过外部库找到。langauge item 就是一种特殊的标记，它能够告诉编译器这个函数实现了某个功能，让编译器采用这个函数提供的实现即可。`eh_personality` 就是其中一个。被它标记的函数意味着实现了 unwinding。

> **提示：** unwinding 相当于是一个垃圾回收器。在程序崩溃后，实现了 unwinding 的函数自动被调用，然后清理栈上未销毁的数据。这确保所有使用的内存被正确释放，并允许父线程捕获崩溃信息，得以继续执行。但是这个步骤很复杂，所以我们不实现。

最后编译器告诉我们入口函数 `_start` 没有找到。熟悉 C/C++ 的同学一定知道，一个 C/C++ 程序的入口点往往是 `main`。但其实在操作系统眼中并非如此。在绝大多数的编程语言中，`main` 函数并不是第一个被调用的。这是由于很多语言都存在运行时（runtime）机制。这个东西需要为主函数的调用进行一些初始化工作，例如栈初始化和寄存器初始化。Rust 也不例外，它通过 C 语言运行时初始化。Rust 的 C 运行时结束初始化后会找到 Rust 程序的入口点（通过 `start` 标记），然后跳转到入口点去执行。而我们的内核当然是没有运行时的，因为运行时依赖于一个可运作的操作系统！因此，我们必须覆盖掉运行时，让我们的内核函数作为真正意义上的第一个被唤醒的函数。在此之前，我们需要额外加入 `#![no_main]`，防止 Rust 强制去链接到 `main`。

现在，我们的源文件是这样的：

```rust
#![no_std]
#![no_main]
#![feature(lang_items)]

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
fn eheh_personality () {

}
```

尝试编译的话就发生了各种符号丢失的错误。这是我们想要看到的，因为我们成功地禁止了 Rust 去链接到主函数！

### 使用 UEFI

很幸运的是，我们不需要花过多精力去定义各种入口函数，然后设置好各种运行环境，因为我们有 UEFI 这个强大的工具。Rust 中我们可以用 uefi 以及 uefi-services 这两个库来进行开发，其中前者提供了 UEFI 的执行环境，后者是一些我们可以使用的数据结构和函数定义。想要将它们添加到项目中，我们只需要：

* 在项目的根目录下执行

```shell
$ cargo add uefi uefi-services
    Updating `ustc` index
      Adding uefi v0.19.1 to dependencies.
             Features:
             + panic-on-logger-errors
             - alloc
             - global_allocator
             - logger
             - unstable
      Adding uefi-services v0.16.0 to dependencies.
             Features:
             + logger
             + panic_handler
             - qemu
             - qemu-exit
```

* 或者将依赖手动添加到 `Cargo.toml` 中：

```toml
[package]
name = "bootloader"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
uefi = "0.19.1"
```

> **注意：** 因为 uefi 这个库帮我们实现了 `panic_handler` 和 `eh_personality`，我们就不需要再源文件中添加自己实现的这两个东西了。

引入 UEFI 之后，我们只需要定义好 EFI bootloader 的入口函数即可。

```rust
#![no_std]
#![no_main]

use uefi::prelude::*;

#[entry]
fn _main(handle: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("Failed to launch the system table!");

    todo!()
}
```

因为我们还未完全实现这个 bootloader，所以我们加入 `todo!()` 这个宏来让编译器通过编译，防止它提示返回值不对。接下来尝试构建一下这个项目吧！

```shell
$ cargo build
error: `#[panic_handler]` function required, but not found

error: language item required, but not found: `eh_personality`
  |
  = note: this can occur when a binary crate with `#![no_std]` is compiled for a target where `eh_personality` is defined in the standard library
  = help: you may be able to compile for a target that doesn't need `eh_personality`, specify a target with `--target` or in `.cargo/config`

error: could not compile `bootloader` due to 2 previous errors
```

这是为什么呢？明明 uefi 提供了这些实现，为什么编译器依旧报错？这是因为我们构建的目标架构不对。我们在 Linux 环境下的默认架构是 `x86_64-unknown-linux-gnu`，而不是为 uefi 环境构建的！所以我们要让编译器交叉编译，生成一个 uefi 环境下的 bootloader。幸运的是 Rust 编译器 `rustc` 支持交叉编译。想要知道支持的架构，可以执行如下命令来查看。

```shell
$ rustc --print target-list
aarch64-apple-darwin
aarch64-apple-ios
aarch64-apple-ios-macabi
aarch64-apple-ios-sim
aarch64-apple-tvos
aarch64-apple-watchos-sim
aarch64-fuchsia
...
```

仔细查看可以发现 `rustc` 支持 uefi。

```shell
$ rustc --print target-list | grep 'uefi'
aarch64-unknown-uefi
i686-unknown-uefi
x86_64-unknown-uefi
```

我们接下来编译的话，只需要手动指定目标架构即可。

```shell
$ rustup target add x86_64-unknown-uefi # 添加交叉编译架构
info: downloading component 'rust-std' for 'x86_64-unknown-uefi'
info: installing component 'rust-std' for 'x86_64-unknown-uefi'

$ cargo build --target x86_64-unknown-uefi # 编译
   Compiling bootloader v0.1.0 (/home/hiroki/bootloader)
    Finished dev [unoptimized + debuginfo] target(s) in 0.23s
```

我们的微型 bootloader 就此诞生了！编译出来的文件可以在 `target/x86_64-unknown-uefi/debug` 中找到：

```shell
$ ls target/x86_64-unknown-uefi/debug/
bootloader.d  bootloader.efi  build  deps  examples  incremental
```
