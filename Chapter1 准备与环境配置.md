# 环境配置

在准备开发之前，我们需要将你的系统环境设置好，并安装必要的软件包。在此，请**确保**你使用的操作系统是 Linux 系，一般而言下面的发行版都是可以的。

* Ubuntu (20.04, 22.04, etc.) 我们不太推荐使用 18.04，因为可能存在软件包版本过老的问题。
* Debian
* Kali （可以完美兼容 Ubuntu 的所有指令）

如果你在使用 Windows 或者 macOS，请使用虚拟机（VMware、VirtualBox）。

> 注意： Windows 用户请避免使用 WSL2。使用 WSL2 需要在 WSL2 内部使用 qemu 模拟一个虚拟机出来，KVM 的虚拟化可能存在一些问题。**而且，我们需要使用 apfs 驱动，这需要 linux header，但是 wsl2 编译 linux header十分困难，甚至会失败。**
>
## apfs

### APFS

先安装[APFS](https://github.com/linux-apfs/linux-apfs-rw).

首先需要 clone 仓库

```shell
git clone https://github.com/linux-apfs/linux-apfs-rw
```

然后依次执行如下命令：

```shell
sudo apt-get install linux-headers-$(uname -r)
make
modprobe libcrc32c
sudo insmod apfs.ko
```

然后，安装这个：[apfsprogs](https://github.com/linux-apfs/apfsprogs)

先

```sh
git clone https://github.com/linux-apfs/apfsprogs
```

然后在这个项目之中

```sh
cd mkapfs
```

其中，需要把它原来的Makefile替换成如下：

```makefile
SRCS = btree.c dir.c mkapfs.c object.c spaceman.c super.c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

LIBDIR = ../lib
LIBRARY = $(LIBDIR)/libapfs.a

BINDIR = /bin
MANDIR = /share/man/man8

SPARSE_VERSION := $(shell sparse --version 2>/dev/null)

override CFLAGS += -Wall -Wno-address-of-packed-member -fno-strict-aliasing -I$(CURDIR)/../include

mkapfs: $(OBJS) $(LIBRARY)
 @echo '  Linking...'
 @$(CC) $(CFLAGS) $(LDFLAGS) -o mkapfs $(OBJS) $(LIBRARY)
 @echo '  Build complete'

# Build the common libraries
$(LIBRARY): FORCE
 @echo '  Building libraries...'
 @$(MAKE) -C $(LIBDIR) --silent --no-print-directory
 @echo '  Library build complete'
FORCE:

%.o: %.c
 @echo '  Compiling $<...'
 @$(CC) $(CFLAGS) -o $@ -MMD -MP -c $<
ifdef SPARSE_VERSION
 @sparse $(CFLAGS) $<
endif

-include $(DEPS)

clean:
 rm -f $(OBJS) $(DEPS) mkapfs
install:
 install -d $(BINDIR)
 install -t $(BINDIR) mkapfs
 ln -fs -T mkapfs $(BINDIR)/mkfs.apfs
 install -d $(MANDIR)
 install -m 644 -t $(MANDIR) mkapfs.8
 ln -fs -T mkapfs.8 $(MANDIR)/mkfs.apfs.8
```

**注意，由于不同的系统和编辑器的原因，直接复制可能会导致对齐问题，因此在复制后建议手动使用 tab 对齐。**

然后进去执行：

```sh
sudo make
```

和

```sh
sudo make install
```

至此，驱动就装完了。

### NOTICE

注意，如果你采用的是 Vmware 虚拟机，在安装的时候需要进行如下设置：

在 `虚拟机设置`->`处理器`->`虚拟化引擎`之中，勾选`虚拟化 Intel VT-x/EPT 或 AMD-V/RVI`，然后启动虚拟机，**这是必要的工作**。

如果这一步导致了以下问题：
>此平台不支持虚拟化的 Intel VT-x/EPT。 不使用虚拟化的 Intel VT-x/EPT,是否继续？
那么，可行的方式有如下几种：
* 首先需要确认 任务管理器——性能——虚拟化，为已启用。如果没有启用，需要进入BIOS自行启用。
* win10专业版：控制面板——程序——打开或关闭 Windows 功能，取消勾选 Hyper-V，确定禁用Hyper-V服务。之后重启电脑。
* 如果没有 Hyper-V，那么最有效的办法是：打开Windows安全中心>设备安全性>内核隔离，确保“DMA”已关闭，然后重启。

**注意！ WINDOWS 用户必须点击 `重启` 而不是 关机再开机 或其他替代方式！**

## 安装 Rust 工具链

在你的终端执行如下命令：

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

跟着提示安装就好。该命令会默认将 Rust 安装在 `$HOME/.cargo/` 下面。安装完之后，建议你将环境变量设置好，不然可能会出现 `cargo` 找不到的问题。设置环境变量如下：

```shell
echo "source $HOME/.cargo/env" >> ~/.bashrc
source ~/.bashrc
```

如果你使用的终端是 zsh、fish 等其他终端，请把上面的输出路径改成 `~/.zshrc` 等。

## 配置镜像源

由于一些原因，`crates.io` 需要通过 GitHub 来访问，但是我们经常会遇到超时的情况。这个时候请编辑（如果不存在创建一个） `~/.cargo/config`，加入中科大的镜像即可。

```toml
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"
replace-with = 'ustc'

[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"
```

## 安装 nightly Rust

因为我们需要用到一些不稳定的特性，而我们默认安装的 Rust 工具链是 stable channel 的，所以我们需要安装 nightly 版本。这很简单，在你正确安装了 Rust 之后，执行如下命令。

```shell
nightly=$(cat ./rust-toolchain)
rustup component add rust-src llvm-tools-preview --toolchain ${nightly}-x86_64-unknown-linux-gnu
cargo install --git https://github.com/rcore-os/rcore-fs.git --rev 7f5eeac --force rcore-fs-fuse
cargo install cargo-binutils
```

我们的仓库指定了一个 nightly 的版本，请不要随便修改版本，可能会出现一些奇怪的兼容问题。当然我们会尽可能将版本更新到最新的。

## 安装必备的软件包

我们假设你使用的操作系统是 Ubuntu。执行如下命令。

```shell
sudo apt install -y qemu-system qemu-kvm build-essential ovmf git \
     libvirt-daemon-system libvirt-clients bridge-utils musl-tools nasm
```

> 提示：我们的仓库根目录下提供了一个一键安装（Rust 和 软件包）的脚本。用 Python 执行即可。
>
> ```shell
> python3 x.py
> ```

## Build NeoOS

现阶段的 NeoOS 还存在一些小问题，因此 build 的过程如下：

```sh
make run
```

如果看到出现 logo 了，就进入成功了。

最后退出系统：

和退出qemu一样，先按 ctrl + a，然后输入字母 "x"，就能正常退出了。
