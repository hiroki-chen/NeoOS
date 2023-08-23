# 环境配置

在准备开发之前，我们需要将你的系统环境设置好，并安装必要的软件包。在此，请**确保**你使用的操作系统是 Linux 系，一般而言下面的发行版都是可以的。

* Ubuntu (20.04, 22.04, etc.) 我们不太推荐使用 18.04，因为可能存在软件包版本过老的问题。
* Debian
* Kali （可以完美兼容 Ubuntu 的所有指令）

如果你在使用 Windows 或者 macOS，请使用虚拟机（VMware、VirtualBox）。

> 注意： Windows 用户请避免使用 WSL2。使用 WSL2 需要在 WSL2 内部使用 qemu 模拟一个虚拟机出来，KVM 的虚拟化可能存在一些问题。

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
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

我们的仓库指定了一个 nightly 的版本，请不要随便修改版本，可能会出现一些奇怪的兼容问题。当然我们会尽可能将版本更新到最新的。

## 安装必备的软件包

我们假设你使用的操作系统是 Ubuntu。执行如下命令。

```shell
sudo apt install -y qemu-system qemu-kvm build-essential ovmf git libvirt-daemon-system libvirt-clients bridge-utils
```

> 提示：我们的仓库根目录下提供了一个一键安装（Rust 和 软件包）的脚本。用 Python 执行即可。
>
> ```shell
> python x.py
> ```
