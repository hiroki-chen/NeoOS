//! Implements system call interfaces and handling routines.

use alloc::{collections::BTreeMap, sync::Arc};
use lazy_static::lazy_static;
use spin::RwLock;

use crate::{
    arch::interrupt::{SYSCALL, SYSCALL_REGS_NUM},
    error::{error_to_int, Errno, KResult},
    process::thread::{Thread, ThreadContext},
    syscall::fs::{sys_ioctl, sys_writev},
};

mod fs;
mod id;
mod mem;
mod net;
mod others;
mod process;
mod signal;

pub use fs::*;
pub use id::*;
pub use mem::*;
pub use net::*;
pub use others::*;
pub use process::*;
pub use signal::*;

// System call numbers for x86_64.

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_SELECT: u64 = 23;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_MREMAP: u64 = 25;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MINCORE: u64 = 27;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_SHMGET: u64 = 29;
pub const SYS_SHMAT: u64 = 30;
pub const SYS_SHMCTL: u64 = 31;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_PAUSE: u64 = 34;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETITIMER: u64 = 36;
pub const SYS_ALARM: u64 = 37;
pub const SYS_SETITIMER: u64 = 38;
pub const SYS_GETPID: u64 = 39;
pub const SYS_SENDFILE: u64 = 40;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_SEMGET: u64 = 64;
pub const SYS_SEMOP: u64 = 65;
pub const SYS_SEMCTL: u64 = 66;
pub const SYS_SHMDT: u64 = 67;
pub const SYS_MSGGET: u64 = 68;
pub const SYS_MSGSND: u64 = 69;
pub const SYS_MSGRCV: u64 = 70;
pub const SYS_MSGCTL: u64 = 71;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FLOCK: u64 = 73;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETDENTS: u64 = 78;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FCHDIR: u64 = 81;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_GETRLIMIT: u64 = 97;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_TIMES: u64 = 100;
pub const SYS_PTRACE: u64 = 101;
pub const SYS_GETUID: u64 = 102;
pub const SYS_SYSLOG: u64 = 103;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_SETGROUPS: u64 = 116;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETRESGID: u64 = 120;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_SETFSUID: u64 = 122;
pub const SYS_SETFSGID: u64 = 123;
pub const SYS_GETSID: u64 = 124;
pub const SYS_CAPGET: u64 = 125;
pub const SYS_CAPSET: u64 = 126;
pub const SYS_RT_SIGPENDING: u64 = 127;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 128;
pub const SYS_RT_SIGQUEUEINFO: u64 = 129;
pub const SYS_RT_SIGSUSPEND: u64 = 130;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_UTIME: u64 = 132;
pub const SYS_MKNOD: u64 = 133;
pub const SYS_USELIB: u64 = 134;
pub const SYS_PERSONALITY: u64 = 135;
pub const SYS_USTAT: u64 = 136;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_SYSFS: u64 = 139;
pub const SYS_GETPRIORITY: u64 = 140;
pub const SYS_SETPRIORITY: u64 = 141;
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const SYS_MLOCK: u64 = 149;
pub const SYS_MUNLOCK: u64 = 150;
pub const SYS_MLOCKALL: u64 = 151;
pub const SYS_MUNLOCKALL: u64 = 152;
pub const SYS_VHANGUP: u64 = 153;
pub const SYS_MODIFY_LDT: u64 = 154;
pub const SYS_PIVOT_ROOT: u64 = 155;
pub const SYS__SYSCTL: u64 = 156;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_ADJTIMEX: u64 = 159;
pub const SYS_SETRLIMIT: u64 = 160;
pub const SYS_CHROOT: u64 = 161;
pub const SYS_SYNC: u64 = 162;
pub const SYS_ACCT: u64 = 163;
pub const SYS_SETTIMEOFDAY: u64 = 164;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_SWAPON: u64 = 167;
pub const SYS_SWAPOFF: u64 = 168;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_SETHOSTNAME: u64 = 170;
pub const SYS_SETDOMAINNAME: u64 = 171;
pub const SYS_IOPL: u64 = 172;
pub const SYS_IOPERM: u64 = 173;
pub const SYS_CREATE_MODULE: u64 = 174;
pub const SYS_INIT_MODULE: u64 = 175;
pub const SYS_DELETE_MODULE: u64 = 176;
pub const SYS_GET_KERNEL_SYMS: u64 = 177;
pub const SYS_QUERY_MODULE: u64 = 178;
pub const SYS_QUOTACTL: u64 = 179;
pub const SYS_NFSSERVCTL: u64 = 180;
pub const SYS_GETPMSG: u64 = 181;
pub const SYS_PUTPMSG: u64 = 182;
pub const SYS_AFS_SYSCALL: u64 = 183;
pub const SYS_TUXCALL: u64 = 184;
pub const SYS_SECURITY: u64 = 185;
pub const SYS_GETTID: u64 = 186;
pub const SYS_READAHEAD: u64 = 187;
pub const SYS_SETXATTR: u64 = 188;
pub const SYS_LSETXATTR: u64 = 189;
pub const SYS_FSETXATTR: u64 = 190;
pub const SYS_GETXATTR: u64 = 191;
pub const SYS_LGETXATTR: u64 = 192;
pub const SYS_FGETXATTR: u64 = 193;
pub const SYS_LISTXATTR: u64 = 194;
pub const SYS_LLISTXATTR: u64 = 195;
pub const SYS_FLISTXATTR: u64 = 196;
pub const SYS_REMOVEXATTR: u64 = 197;
pub const SYS_LREMOVEXATTR: u64 = 198;
pub const SYS_FREMOVEXATTR: u64 = 199;
pub const SYS_TKILL: u64 = 200;
pub const SYS_TIME: u64 = 201;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_SET_THREAD_AREA: u64 = 205;
pub const SYS_IO_SETUP: u64 = 206;
pub const SYS_IO_DESTROY: u64 = 207;
pub const SYS_IO_GETEVENTS: u64 = 208;
pub const SYS_IO_SUBMIT: u64 = 209;
pub const SYS_IO_CANCEL: u64 = 210;
pub const SYS_GET_THREAD_AREA: u64 = 211;
pub const SYS_LOOKUP_DCOOKIE: u64 = 212;
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_EPOLL_CTL_OLD: u64 = 214;
pub const SYS_EPOLL_WAIT_OLD: u64 = 215;
pub const SYS_REMAP_FILE_PAGES: u64 = 216;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_RESTART_SYSCALL: u64 = 219;
pub const SYS_SEMTIMEDOP: u64 = 220;
pub const SYS_FADVISE64: u64 = 221;
pub const SYS_TIMER_CREATE: u64 = 222;
pub const SYS_TIMER_SETTIME: u64 = 223;
pub const SYS_TIMER_GETTIME: u64 = 224;
pub const SYS_TIMER_GETOVERRUN: u64 = 225;
pub const SYS_TIMER_DELETE: u64 = 226;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_UTIMES: u64 = 235;
pub const SYS_VSERVER: u64 = 236;
pub const SYS_MBIND: u64 = 237;
pub const SYS_SET_MEMPOLICY: u64 = 238;
pub const SYS_GET_MEMPOLICY: u64 = 239;
pub const SYS_MQ_OPEN: u64 = 240;
pub const SYS_MQ_UNLINK: u64 = 241;
pub const SYS_MQ_TIMEDSEND: u64 = 242;
pub const SYS_MQ_TIMEDRECEIVE: u64 = 243;
pub const SYS_MQ_NOTIFY: u64 = 244;
pub const SYS_MQ_GETSETATTR: u64 = 245;
pub const SYS_KEXEC_LOAD: u64 = 246;
pub const SYS_WAITID: u64 = 247;
pub const SYS_ADD_KEY: u64 = 248;
pub const SYS_REQUEST_KEY: u64 = 249;
pub const SYS_KEYCTL: u64 = 250;
pub const SYS_IOPRIO_SET: u64 = 251;
pub const SYS_IOPRIO_GET: u64 = 252;
pub const SYS_INOTIFY_INIT: u64 = 253;
pub const SYS_INOTIFY_ADD_WATCH: u64 = 254;
pub const SYS_INOTIFY_RM_WATCH: u64 = 255;
pub const SYS_MIGRATE_PAGES: u64 = 256;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_MKNODAT: u64 = 259;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_FUTIMESAT: u64 = 261;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_PSELECT6: u64 = 270;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_UNSHARE: u64 = 272;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_SPLICE: u64 = 275;
pub const SYS_TEE: u64 = 276;
pub const SYS_SYNC_FILE_RANGE: u64 = 277;
pub const SYS_VMSPLICE: u64 = 278;
pub const SYS_MOVE_PAGES: u64 = 279;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_SIGNALFD: u64 = 282;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_EVENTFD: u64 = 284;
pub const SYS_FALLOCATE: u64 = 285;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_SIGNALFD4: u64 = 289;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_INOTIFY_INIT1: u64 = 294;
pub const SYS_PREADV: u64 = 295;
pub const SYS_PWRITEV: u64 = 296;
pub const SYS_RT_TGSIGQUEUEINFO: u64 = 297;
pub const SYS_PERF_EVENT_OPEN: u64 = 298;
pub const SYS_RECVMMSG: u64 = 299;
pub const SYS_FANOTIFY_INIT: u64 = 300;
pub const SYS_FANOTIFY_MARK: u64 = 301;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_NAME_TO_HANDLE_AT: u64 = 303;
pub const SYS_OPEN_BY_HANDLE_AT: u64 = 304;
pub const SYS_CLOCK_ADJTIME: u64 = 305;
pub const SYS_SYNCFS: u64 = 306;
pub const SYS_SENDMMSG: u64 = 307;
pub const SYS_SETNS: u64 = 308;
pub const SYS_GETCPU: u64 = 309;
pub const SYS_PROCESS_VM_READV: u64 = 310;
pub const SYS_PROCESS_VM_WRITEV: u64 = 311;
pub const SYS_KCMP: u64 = 312;
pub const SYS_FINIT_MODULE: u64 = 313;
pub const SYS_SCHED_SETATTR: u64 = 314;
pub const SYS_SCHED_GETATTR: u64 = 315;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_SECCOMP: u64 = 317;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_MEMFD_CREATE: u64 = 319;
pub const SYS_KEXEC_FILE_LOAD: u64 = 320;
pub const SYS_BPF: u64 = 321;
pub const SYS_EXECVEAT: u64 = 322;

/// Users can hook this function to do something they want to do (mostly for debugging).
#[linkage = "weak"]
#[no_mangle]
extern "C" fn syscall_hook() {}

lazy_static! {
    /// Records if the process is exited after syscall.
    pub(crate) static ref PROC_EXITED: RwLock<BTreeMap<u64, bool>> = RwLock::new(BTreeMap::new());
}

/// Handles the system calls issued by the thread upon the kernel's capture of the running context. Because syscalls can
/// be interrupted, we do it asynchronously.
///
/// Returns `true` if the system call is correctly handled.
pub async fn handle_syscall(thread: &Arc<Thread>, ctx: &mut ThreadContext) -> bool {
    {
        // If `handle_syscall` is invoked, we can ensure that this thread must be active.
        PROC_EXITED.write().insert(thread.id, false);
    }
    // First, we perform a sanity check.
    assert_eq!(
        ctx.get_trapno(),
        SYSCALL,
        "cannot call this function with a unmatched trap number!"
    );

    let syscall_number = ctx.get_user_context().get_syscall_number();
    let syscall_registers = ctx.get_user_context().get_syscall_params();

    // Check if we are handling syscall?
    assert_eq!(
        syscall_registers.len(),
        SYSCALL_REGS_NUM,
        "the number of parameters is wrong: should be {:#x}, got {:#x}",
        SYSCALL_REGS_NUM,
        syscall_registers.len()
    );

    ktrace!(
        "handling {:#x} with registers {:#x?}",
        syscall_number,
        syscall_registers
    );

    let ret = match do_handle_syscall(thread, ctx, syscall_number, syscall_registers).await {
        Ok(ret) => ret,
        error => -error_to_int(&error) as usize,
    };
    ctx.get_user_context().regs.rax = ret as _;

    // If not found, we asusme this process is corrupted and should be exited.
    let mut map = PROC_EXITED.write();
    let exited = match map.get(&thread.id).copied().unwrap_or(true) {
        false => false,
        true => {
            // remove this thread.
            map.remove(&thread.id);
            true
        }
    };

    exited
}

async fn do_handle_syscall(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_number: u64,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    syscall_hook();

    match syscall_number {
        SYS_PREAD64 => sys_pread(thread, ctx, syscall_registers).await,
        SYS_PWRITE64 => sys_pwrite(thread, ctx, syscall_registers),
        SYS_READ => sys_read(thread, ctx, syscall_registers).await,
        SYS_WRITE => sys_write(thread, ctx, syscall_registers),
        SYS_OPEN => sys_open(thread, ctx, syscall_registers),
        SYS_CLOSE => sys_close(thread, ctx, syscall_registers),
        SYS_POLL => sys_poll(thread, ctx, syscall_registers).await,
        SYS_READV => sys_readv(thread, ctx, syscall_registers).await,
        SYS_WRITEV => sys_writev(thread, ctx, syscall_registers),
        SYS_LSEEK => sys_lseek(thread, ctx, syscall_registers),
        SYS_CHDIR => sys_chdir(thread, ctx, syscall_registers),
        SYS_READLINK => sys_readlink(thread, ctx, syscall_registers),
        SYS_READLINKAT => sys_readlinkat(thread, ctx, syscall_registers),
        SYS_SENDFILE => sys_sendfile(thread, ctx, syscall_registers).await,
        SYS_DUP => sys_dup(thread, ctx, syscall_registers),
        SYS_DUP2 => sys_dup2(thread, ctx, syscall_registers),
        SYS_DUP3 => sys_dup3(thread, ctx, syscall_registers),
        SYS_IOCTL => sys_ioctl(thread, ctx, syscall_registers),
        SYS_CHMOD => sys_chmod(thread, ctx, syscall_registers),
        SYS_LCHOWN => sys_lchown(thread, ctx, syscall_registers),
        SYS_FCHOWN => sys_fchown(thread, ctx, syscall_registers),
        SYS_FCHMOD => sys_fchmod(thread, ctx, syscall_registers),
        SYS_CHOWN => sys_chown(thread, ctx, syscall_registers),
        SYS_MKDIR => sys_mkdir(thread, ctx, syscall_registers),
        SYS_MKDIRAT => sys_mkdirat(thread, ctx, syscall_registers),
        SYS_FCNTL => sys_fnctl(thread, ctx, syscall_registers),
        SYS_FSTAT => sys_fstat(thread, ctx, syscall_registers),
        SYS_LSTAT => sys_lstat(thread, ctx, syscall_registers),
        SYS_STAT => sys_stat(thread, ctx, syscall_registers),
        SYS_GETDENTS64 => sys_getdents64(thread, ctx, syscall_registers),
        SYS_SYMLINK => sys_symlink(thread, ctx, syscall_registers),
        SYS_SYMLINKAT => sys_symlinkat(thread, ctx, syscall_registers),
        SYS_EPOLL_CREATE => sys_epoll_create(thread, ctx, syscall_registers),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(thread, ctx, syscall_registers),
        SYS_EPOLL_CTL => sys_epoll_ctl(thread, ctx, syscall_registers),
        SYS_EPOLL_PWAIT => sys_epoll_pwait(thread, ctx, syscall_registers),
        SYS_EVENTFD => sys_eventfd(thread, ctx, syscall_registers),
        SYS_EVENTFD2 => sys_eventfd2(thread, ctx, syscall_registers),
        SYS_NEWFSTATAT => sys_newfstatat(thread, ctx, syscall_registers),
        SYS_GETCWD => sys_getcwd(thread, ctx, syscall_registers),

        SYS_MMAP => sys_mmap(thread, ctx, syscall_registers),
        SYS_MUNMAP => sys_munmap(thread, ctx, syscall_registers),
        SYS_MPROTECT => sys_mprotect(thread, ctx, syscall_registers),
        SYS_BRK => sys_brk(thread, ctx, syscall_registers),
        SYS_MADVISE => sys_madvice(thread, ctx, syscall_registers),

        SYS_KILL => sys_kill(thread, ctx, syscall_registers),
        SYS_TKILL => sys_tkill(thread, ctx, syscall_registers),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(thread, ctx, syscall_registers),
        SYS_RT_SIGACTION => sys_rt_sigaction(thread, ctx, syscall_registers),
        SYS_RT_SIGRETURN => sys_rt_sigreturn(thread, ctx, syscall_registers),

        SYS_GETEUID => sys_geteuid(thread, ctx, syscall_registers),
        SYS_GETUID => sys_getuid(thread, ctx, syscall_registers),
        SYS_GETEGID => sys_getegid(thread, ctx, syscall_registers),
        SYS_GETGID => sys_getgid(thread, ctx, syscall_registers),

        SYS_GETPPID => sys_getppid(thread, ctx, syscall_registers),
        SYS_GETPGID => sys_getpgid(thread, ctx, syscall_registers),
        SYS_SETPGID => sys_setpgid(thread, ctx, syscall_registers),
        SYS_GETTID => sys_gettid(thread, ctx, syscall_registers),
        SYS_GETPID => sys_getpid(thread, ctx, syscall_registers),
        SYS_EXECVE => sys_execve(thread, ctx, syscall_registers),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(thread, ctx, syscall_registers),
        SYS_EXIT => sys_exit(thread, ctx, syscall_registers),
        SYS_FORK | SYS_VFORK => sys_fork(thread, ctx, syscall_registers),
        SYS_WAIT4 => sys_wait4(thread, ctx, syscall_registers).await,
        SYS_EXIT_GROUP => sys_exit_group(thread, ctx, syscall_registers),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(thread, ctx, syscall_registers),
        SYS_SCHED_YIELD => sys_sched_yield(thread, ctx, syscall_registers),

        SYS_ARCH_PRCTL => sys_arch_prctl(thread, ctx, syscall_registers),
        SYS_GETTIMEOFDAY => sys_gettimeofday(thread, ctx, syscall_registers),
        SYS_TIME => sys_time(thread, ctx, syscall_registers),
        SYS_GETGROUPS => sys_getgroups(thread, ctx, syscall_registers),
        SYS_UNAME => sys_uname(thread, ctx, syscall_registers),
        SYS_CLOCK_GETTIME => sys_clock_gettime(thread, ctx, syscall_registers),
        SYS_PRLIMIT64 => sys_prlimit64(thread, ctx, syscall_registers),

        SYS_SOCKET => sys_socket(thread, ctx, syscall_registers),
        SYS_ACCEPT => sys_accept(thread, ctx, syscall_registers),
        SYS_ACCEPT4 => sys_accept4(thread, ctx, syscall_registers),
        SYS_CONNECT => sys_connect(thread, ctx, syscall_registers),
        SYS_BIND => sys_bind(thread, ctx, syscall_registers),
        SYS_LISTEN => sys_listen(thread, ctx, syscall_registers),
        SYS_GETSOCKNAME => sys_getsockname(thread, ctx, syscall_registers),
        SYS_GETPEERNAME => sys_getpeername(thread, ctx, syscall_registers),
        SYS_SETSOCKOPT => sys_setsockopt(thread, ctx, syscall_registers),
        SYS_GETSOCKOPT => sys_getsockopt(thread, ctx, syscall_registers),
        SYS_SENDTO => sys_sendto(thread, ctx, syscall_registers),
        SYS_SENDMMSG => sys_sendmsg(thread, ctx, syscall_registers),
        SYS_RECVFROM => sys_recvfrom(thread, ctx, syscall_registers),
        SYS_SOCKETPAIR => sys_socketpair(thread, ctx, syscall_registers),
        SYS_SHUTDOWN => sys_shutdown(thread, ctx, syscall_registers),

        _ => {
            kerror!("unrecognized syscall number {:#x}", syscall_number);
            Err(Errno::EINVAL)
        }
    }
}

/// Declares a dummy syscall that does nothing and returns a default result [`KResult<T>`]. This is used typically when
/// a syscall is temporarily too complex or too bothersome to be implemented.
///
/// # Examples
///
/// ```
/// // Oops, this returns fault!
/// dummy_impl!(sys_my_cool_syscall, Err(Errno::EFAULT));
/// // OK!
/// dummy_impl!(sys_another_cool_syscall, Ok(0));
/// ```
#[allow(unused)]
#[macro_export]
macro_rules! dummy_impl {
    ($name:ident, $ret:expr) => {
        pub fn $name(
            thread: &alloc::sync::Arc<$crate::process::thread::Thread>,
            ctx: &mut $crate::process::thread::ThreadContext,
            syscall_registers: [u64; $crate::arch::interrupt::SYSCALL_REGS_NUM],
        ) -> $crate::error::KResult<usize> {
            $ret
        }
    };
}
