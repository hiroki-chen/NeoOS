# 准备 QEMU

我们的内核主要是通过 QEMU 这个硬件模拟器来进行的。这是因为 QEMU 容易 debug（如果实体机 debug 需要另一台机器通过串口调试），运行起来的配置也很简单，不需要再实体硬件上面进行复杂的操作。在我们的操作系统的开发过程中，我们将全程使用 `x86_64` 架构的 QEMU 模拟器。QEMU 是一个开源的虚拟机监控器，它可以模拟多种不同的计算机架构（如 x86、ARM、MIPS 等），并且可以运行多种操作系统（如 Linux、Windows、macOS 等）。QEMU 通过模拟硬件环境来运行虚拟机，同时还支持多种虚拟化技术（如 KVM、Xen 等），可以实现更好的性能和隔离度。QEMU 除了可以作为虚拟机监控器来运行虚拟机外，还可以作为模拟器来运行单独的程序。

在 `Makefile` 中，我们定义了 QEMU 的执行命令如下。

```shell
qemu-system-x86_64 -enable-kvm \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:esp \
  -nographic -smp cores=4 -no-reboot -m 4G -rtc clock=vm \
  -drive format=qcow2,file=$(DISK),media=disk,cache=writeback,id=sfsimg,if=none \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=sfsimg,bus=ahci0.0 \
  -cpu host
```

其中 `$(DISK)` 这个变量指定的是 QEMU 运行的虚拟硬盘。

> **提示：** 为了能够使用内核提供的 KVM 虚拟化技术，你必须把自己所在的用户加入到 kvm 用户组。可以用下面的命令实现。执行结束后你需要**重新登陆**以使命令生效。当然，你也可以以 root 权限执行 QEMU，但是并不推荐这么做。

```shell
sudo adduser `id -um` kvm
```

此外，我们还需要一个 ESP 分区以及 UEFI 虚拟器。OVMF (Open Virtual Machine Firmware) 是一个基于 UEFI (Unified Extensible Firmware Interface) 规范的虚拟机固件。它是由 Intel 开发并开源的，旨在为在虚拟化环境下运行的操作系统提供标准的启动和配置环境。ESP 分区可以手动创建。

假设我们还在 `bootloader` 目录下，我们可以手动创建一个文件夹作为 QEMU 的工作区：

```shell
mkdir -p work
```

然后创建一个 ESP 分区，并将编译好的 UEFI bootloader 拷贝过来，重命名为`bootx64.efi`。

```shell
mkdir -p work/esp/efi/boot
cp target/x86_64-unknown-uefi/debug/bootloader.efi work/esp/efi/boot/bootx64.efi
```

随后将 OVMF 的文件拷贝过来。

```shell
cp /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd work
```

最后，创建 QEMU 的虚拟磁盘文件。

```shell
$ qemu-img create -f qcow2 disk.img 10G
Formatting 'disk.img', fmt=qcow2 size=10737418240 cluster_size=65536 lazy_refcounts=off refcount_bits=16
$ mv disk.img work
```

`work` 目录的分布应该长这样：

```shell
work
├── disk.img
├── esp
│   └── efi
│       └── boot
│           └── bootx64.efi
├── OVMF_CODE.fd
└── OVMF_VARS.fd
```

接下来你就可以执行 QEMU 啦！

```shell
$ cd work
$ qemu-system-x86_64 -enable-kvm \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:esp \
  -nographic -smp cores=4 -no-reboot -m 4G -rtc clock=vm \
  -drive format=qcow2,file=disk.img,media=disk,cache=writeback,id=sfsimg,if=none \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=sfsimg,bus=ahci0.0 \
  -cpu host

QEMU output:
[PANIC]: panicked at 'not yet implemented', src/main.rs:10:5
```

可以看到，我们已经成功进入了 bootloader。之所以崩溃，是因为我们加入了 `todo!()` 这个宏，它会让程序崩溃，因为尚未实现功能。退出 QEMU 的方法是 `ctrl+a` 之后按下 `x`。

## 使用 gdb 调试 QEMU

有时候我们会在内核编写中遇到一些 bug，想要调试这些 bug，我们可以使用 gdb 链接到 QEMU 进行。如果想要调试 QEMU 的话，在 QEMU 的运行命令中加入 `-s -S` 即可。随后启动 gdb，你会看到类似如下的信息。

```shell
$ sudo gdb

--------------------------
gdb > target remote :1234
stopped at 0x00000000ff0 ?
gdb > c
```
