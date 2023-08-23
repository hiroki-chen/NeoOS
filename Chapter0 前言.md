# 第 0 章 前言 - 为什么要做这样一个操作系统内核

笔者大二的时候在上 OS 课程的时候，学习了很多理论课知识以及很多关于 OS 的有趣的东西，然后也跟着实验课 coding 了一下，跟着清华大学写的 uCore 内核实现了基本的内核操作，看着 qemu 里面的输出，感到很有趣。然而，笔者对 OS 课程许多设置多多少少感到不满。详细而言可以列举如下。

* 理论课不是太和实践课程匹配。虽然我们采用了 Tanderbaum 教授撰写的现代操作系统一书，里面的知识点还是很丰富的，然而，由于种种原因，包括课程设置和课业压力，我们的东西仅局限于比较前面的部分。这就导致了后期的有关同步、文件系统、权限管理等方面的知识点介绍**特别不足**。但是，实验课中我们却要求实现课程上并没有详细介绍的知识点。于是，这给一部分同学造成了很大的困扰。首先，靠谱的资料比较难找，再者是网上答案满天飞，但是一个能让人比较能够“理解”的教程却寥寥无几。大部分的资料几乎都是在 self-referencing 或者是互相抄袭。再者，很多同学只关注上层建筑，而忽视一些比较细节的东西。但是仅凭借这本操作系统书可不能写出一个可用的内核，这让许多概念变成了死的。
* 实验课的 uCore **太老了**。虽然 uCore 是跟着 MIT 的 JOS 写（抄）的，但是里面的很多东西已经不是很能体现目前的设计了。我们使用的内核竟然只有 32 位的 X86 平台，而不是现在普遍的 64 位操作系统。这让很多 x64 的新特性不能体现。此外，纯粹使用 legacy 的 BIOS 去启动内核**意义也不是很大**。使用 UEFI 写 bootloader 能够让我们更快上手操作系统内核的编写，而不是**沉浸在实模式切换保护模式到长模式，初始页表映射来映射去**这种优先级并非很高的任务之中。最后，在多核系统中，uCore 似乎也没能很好地让我们学会如何启动多核 CPU，并进行一些线程调度、同步的**高阶知识**（e.g., FUTEX 这种东西）。还有类似于 x2APIC, LAPIC Timer, RTC 这些部件都不支持，但这些部件实际上**非常常用**。
* uCore 采用的 C 语言容易给大家带来各种内存问题。因为 C 语言的弱类型特性和没有强制所有权检查，我们在出现 bug 的时候非常难以精准定位。加之 C 语言缺乏好用、易上手的包管理器和强大的高级数据结构支持，我们在实现一些基本的功能的时候（例如想要通过一个哈希表去管理一些线程状态时），我们就很痛苦。甚至我们可能需要一周时间写一个轮子出来，然后再花一周时间去 debug。更为噩梦的是，如果想要跟着 Linux 内核那种写法去写的话，一些 trick 实在过多。笔者认为在这些事情上面倾注大量时间**并无必要**。这是由于我们的目的是**实现一个内核**，而不是参加高级程序语言设计。

事实上，连清华他们自己都在尝试丢弃古早的 uCore 内核转而拥抱新的软硬件生态，写了一个全新的内核叫做 rCore。其中，最值得关注的两个点是：RISC-V 和 Rust。前者是 UCB 提出的精简指令集，因为它并没有 X86 那样的严重历史包袱，它在设计上可谓是一股清流。后者是 2015 年发布 1.0 版本的新的编程语言，目前在区块链、云原生、PL 设计、形式化验证等领域大放异彩。Rust 克服了 C/C++ 的诸多问题，例如内存安全、极为严格的类型检查、所有权检查、不知所云的各种继承，又带来了许多新的特性，例如 `cargo` 包管理器，自由灵活的编译 toolchain，trait 支持、强大的宏系统，各种方便好用的 `std` 容器等。为了体现 Rust 的一些精妙之处，不妨参考如下读取文件并找小写字母的案例。

```rust
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let mut file = File::open("./output.txt").expect("Cannot open the file!");
    // Read the file content into a string.
    let mut content = String::new();
    file.read_to_string(&mut content).expect("read failed!");

    // Print.
    println!(
        "Found characters: {:?}",
        content.chars()
            .filter(|c| ('a'..'z').contains(c))
            .collect::<Vec<_>>());
}
```

依赖于 Rust 提供的 `std` 库，我们只需要几行就可以同时读出文件并进行一些错误处理，并保证了没有内存泄漏。反观 C++：

```c++
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

int main(int argc, const char** argv) {
    // Open the file for reading
    ifstream infile("output.txt");

    // Check if the file was opened successfully
    if (!infile) {
        cout << "Failed to open file." << endl;
        return 1;
    }

        // Read the contents of the file into a string
    string content((istreambuf_iterator<char>(infile)),
                   (istreambuf_iterator<char>()));

    // Find all characters that match the predicate
    auto pred = [](char c) { return std::islower(c); };
    auto it = find_if(content.begin(), content.end(), pred);

    while (it != content.end())
    {
        cout << "Found character: " << *it << endl;
        it = find_if(++it, content.end(), pred);
    }

    // Close the file
    infile.close();

    return 0;
}
```

我们想要模仿 rCore 用 Rust 也来设计一个自己的操作系统内核，何乐而不为？不过，我们暂时使用 x86_64 架构进行开发。一个是我们考虑到 Intel 的兼容性还是很广的，而且市占率也比较可观。根据宫老师所言，

> X86是我们目前能看到的使用最广泛的系统，这东西不能被忽略，如果它的机制我不给你们讲，逼你们去认识，那谁又准备把这部分知识留给谁来给你们讲呢? 所以我反复期酌都没有舍得完全丢弃X86。
> 如果我们能重新做一个教学用OS并且推而广之，不失为一件美事。
> 我也有一些对ucore并不满意的地方，相比JOS，ucore的一些实验设计的略显生硬，格局小了点。

是的，虽然 Rust 这门语言也比较新，不能完全替代 C/C++ 编程，但是它对于认知内核编程而言是能够增加便捷度的。而且，学习 Rust 并非意味着 C 语言完全放弃。实际上，学会 Rust 之后对 C 语言的认知会**更上一层楼**，但代价只是学会它。国内外这门语言的热度一直在不断增加，笔者在系统安全领域也看到了很多相关的项目和工程。例如 Apache 安全云计算的 [Teaclave 项目](https://github.com/apache/incubator-teaclave)，[zkSnark 以太坊工具箱](https://github.com/Zokrates/ZoKrates)，ETHz 做的形式化验证工具 [Prusti](https://github.com/viperproject/prusti-dev)。此外，在系统级编程领域，Rust 的身影也时常可以看见，而且相关的库非常完善了。比如支持 UEFI 的 [uefi-rs](https://github.com/rust-osdev/uefi-rs)，支持x86_64 的[工具箱](https://github.com/rust-osdev/x86_64)。种种思考之后，我们决定还是使用 Rust 作为内核的编程语言。

## 如果你还不会 Rust？

以下为 Rust 新手必读的一些参考资料：

* [The Rust Book](https://doc.rust-lang.org/book/)（Rust 官方文档，首页有各种语言翻译）
* [The Rustonomicon](https://doc.rust-lang.org/nomicon/) （进阶读物，内核级编程必读）

其他可能有用的链接：

* [Rust 社区](https://github.com/rust-lang/rust)
* [官方库](https://crates.io)，你可以在这里找到各种库并且加入到你的项目中。
* [各种文档](https://docs.rs)，发表在 crates.io 上面的库一定在这里可以找到对应的官方文档；包括 `std` 和 `core` 等 Rust 官方自带的库文档。
