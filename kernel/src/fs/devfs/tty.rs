//! Teletypewriter. TTY is a virtual terminal that provides a text-based interface for interacting with the system.

use core::{
    any::Any,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use bitflags::bitflags;
use lazy_static::lazy_static;
use rcore_fs::vfs::{make_rdev, FileType, FsError, INode, Metadata, PollStatus, Timespec};
use spin::RwLock;

use crate::{
    function, kerror, print,
    process::{
        event::{Event, EventBus},
        search_by_group_id,
    },
    signal::{send_signal, SigInfo, Signal},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

lazy_static! {
    pub static ref TTY: Arc<TtyInode> = Arc::new(TtyInode::new());
    static ref WINSIZE: RwLock<Winsize> = RwLock::new(Winsize::default());
}

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;

// c_lflag flag constants.

bitflags! {
    /// <https://elixir.bootlin.com/linux/v6.2/source/include/uapi/asm-generic/termbits.h#L166>
    #[derive(Default)]
    pub struct LocalModes: u32 {
        const ISIG = 0000001;
        const ICANON = 0000002;
        const XCASE = 0000004;
        const ECHO = 0000010;
        const ECHOE = 0000020;
        const ECHOK = 0000040;
        const ECHONL = 0000100;
        const NOFLSH = 0000200;
        const TOSTOP = 0000400;
        const ECHOCTL = 0001000;
        const ECHOPRT = 0002000;
        const ECHOKE = 0004000;
        const FLUSHO = 0010000;
        const PENDIN = 0040000;
        const IEXTEN = 0100000;
        const EXTPROC = 0200000;
    }

    /// <https://elixir.bootlin.com/linux/v6.2/source/include/uapi/asm-generic/termbits.h#L64>
    #[derive(Default)]
    pub struct InputModes: u32 {
        const IGNBRK = 0x001; /* Ignore break condition */
        const BRKINT = 0x002; /* Signal interrupt on break */
        const IGNPAR = 0x004; /* Ignore characters with parity errors */
        const PARMRK = 0x008; /* Mark parity and framing errors */
        const INPCK = 0x010; /* Enable input parity check */
        const ISTRIP = 0x020; /* Strip 8th bit off characters */
        const INLCR = 0x040; /* Map NL to CR on input */
        const IGNCR = 0x080; /* Ignore CR */
        const ICRNL = 0x100; /* Map CR to NL on input */
        const IXANY = 0x800; /* Any character will restart after stop */
        const IUCLC = 0x0200;
        const IXON = 0x0400;
        const IXOFF = 0x1000;
        const IMAXBEL = 0x2000;
        const IUTF8 = 0x4000;
    }

    /// <https://elixir.bootlin.com/linux/v6.2/source/include/uapi/asm-generic/termbits-common.h#L21>
    #[derive(Default)]
    pub struct OutputModes: u32 {
        const OPOST = 0x01; /* Perform output processing */
        const OCRNL = 0x08;
        const ONOCR = 0x10;
        const ONLRET = 0x20;
        const OFILL = 0x40;
        const OFDEL = 0x80;
        const OLCUC = 0x00002;
        const ONLCR = 0x00004;
        const NLDLY = 0x00100;
        const NL0 = 0x00000;
        const NL1 = 0x00100;
        const CRDLY = 0x00600;
        const CR0 = 0x00000;
        const CR1 = 0x00200;
        const CR2 = 0x00400;
        const CR3 = 0x00600;
        const TABDLY = 0x01800;
        const TAB0 = 0x00000;
        const TAB1 = 0x00800;
        const TAB2 = 0x01000;
        const TAB3 = 0x01800;
        const XTABS = 0x01800;
        const BSDLY = 0x02000;
        const BS0 = 0x00000;
        const BS1 = 0x02000;
        const VTDLY = 0x04000;
        const VT0 = 0x00000;
        const VT1 = 0x04000;
        const FFDLY = 0x08000;
        const FF0 = 0x00000;
        const FF1 = 0x08000;
    }

    #[derive(Default)]
    pub struct ControlModes: u32 {
        const CBAUD = 0x0000100f;
        const CSIZE = 0x00000030;
        const CS5 = 0x00000000;
        const CS6 = 0x00000010;
        const CS7 = 0x00000020;
        const CS8 = 0x00000030;
        const CSTOPB = 0x00000040;
        const CREAD = 0x00000080;
        const PARENB = 0x00000100;
        const PARODD = 0x00000200;
        const HUPCL = 0x00000400;
        const CLOCAL = 0x00000800;
        const CBAUDEX = 0x00001000;
        const BOTHER = 0x00001000;
        const B57600= 0x00001001;
        const B115200 = 0x00001002;
        const B230400 = 0x00001003;
        const B460800 = 0x00001004;
        const B500000 = 0x00001005;
        const B576000 = 0x00001006;
        const B921600 = 0x00001007;
        const B1000000 = 0x00001008;
        const B1152000 = 0x00001009;
        const B1500000 = 0x0000100a;
        const B2000000 = 0x0000100b;
        const B2500000 = 0x0000100c;
        const B3000000 = 0x0000100d;
        const B3500000 = 0x0000100e;
        const B4000000 = 0x0000100f;
        const CIBAUD = 0x100f0000; /* input baud rate */
    }
}

const CONTROL_BYTES: &[u8; 4] = &[0o3, 0o31, 0o32, 0o34];

struct Serial<'ctx> {
    inner: &'ctx TtyInode,
}

impl<'ctx> Future for Serial<'ctx> {
    type Output = rcore_fs::vfs::Result<PollStatus>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner.buf_available() {
            true => Poll::Ready(self.inner.poll()),
            false => {
                let waker = cx.waker().clone();
                self.inner.eventbus.lock().subscribe(Box::new(move |_| {
                    waker.wake_by_ref();
                    true
                }));

                Poll::Pending
            }
        }
    }
}

/// The TTY inode located under `/dev`. It should be lazily initialized after the filesystem is up.
/// The file /dev/tty is a character file with major number 5 and minor number 0, usually of mode 0666 and
/// owner.group root.tty. It is a synonym for the controlling terminal of a process, if any.
pub struct TtyInode {
    /// The process pid thatcurrently occupies the tty.
    fg_pid: RwLock<usize>,
    buffer: Mutex<VecDeque<u8>>,
    eventbus: Mutex<EventBus>,
    termios: RwLock<Termios>,
}

impl TtyInode {
    pub fn new() -> Self {
        Self {
            fg_pid: RwLock::new(0),
            buffer: Mutex::new(VecDeque::new()),
            eventbus: Mutex::new(EventBus::default()),
            termios: RwLock::new(Termios::new()),
        }
    }

    pub fn get_fd_pid(&self) -> usize {
        *self.fg_pid.read()
    }

    pub fn buf_available(&self) -> bool {
        !self.buffer.lock().is_empty()
    }

    pub fn read_byte(&self) -> u8 {
        let mut buf = self.buffer.lock();
        let byte = buf.pop_front().unwrap();

        if buf.is_empty() {
            self.eventbus.lock().clear(Event::READABLE);
        }
        byte
    }

    pub fn write_byte(&self, byte: u8) {
        // Resort to ioctl?
        let local_modes = LocalModes::from_bits_truncate(self.termios.read().c_lflag);
        if local_modes.contains(LocalModes::ISIG) && CONTROL_BYTES.contains(&byte) {
            // Send signal to foreground process!
            let foreground_processes = search_by_group_id(self.get_fd_pid() as _);
            foreground_processes.into_iter().for_each(|proc| {
                send_signal(
                    proc,
                    -1,
                    SigInfo {
                        signo: Signal::SIGINT as _,
                        code: 128,
                        errno: 0,
                        sifields: Default::default(),
                    },
                );
            });
        } else {
            self.buffer.lock().push_back(byte);
            self.eventbus.lock().set(Event::READABLE);
        }
    }
}

impl INode for TtyInode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        match self.buf_available() {
            true => {
                if buf.is_empty() {
                    kerror!("cannot input an empty buffer.");
                    return Err(FsError::InvalidParam);
                }

                buf[0] = self.read_byte();
                Ok(1)
            }
            false => Err(FsError::Again),
        }
    }

    fn io_control(&self, cmd: u32, data: usize) -> rcore_fs::vfs::Result<usize> {
        match cmd {
            TIOCGWINSZ => {
                let ptr = data as *mut Winsize;
                unsafe {
                    ptr.write(WINSIZE.read().clone());
                }

                Ok(0)
            }

            TCGETS => {
                let ptr = data as *mut Termios;
                unsafe {
                    ptr.write(self.termios.read().clone());
                }

                Ok(0)
            }

            TCSETS => {
                let termios = unsafe { (data as *const Termios).read() };
                *self.termios.write() = termios;

                Ok(0)
            }

            TIOCSPGRP => {
                let pid = unsafe { (data as *const i32).read() };
                *self.fg_pid.write() = pid as _;

                Ok(0)
            }

            TIOCGPGRP => {
                let ptr = data as *mut i32;
                unsafe {
                    ptr.write(*self.fg_pid.read() as i32);
                }

                Ok(0)
            }
            _ => Err(FsError::IOCTLError), // No such command.
        }
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        let utf_str = unsafe { core::str::from_utf8_unchecked(buf) };
        print!("{}", utf_str);
        Ok(buf.len())
    }

    fn poll(&self) -> rcore_fs::vfs::Result<PollStatus> {
        Ok(PollStatus {
            read: self.buf_available(),
            write: true,
            error: false,
        })
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn metadata(&self) -> rcore_fs::vfs::Result<Metadata> {
        Ok(Metadata {
            dev: 1,
            inode: 13,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::CharDevice,
            mode: 0o666,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: make_rdev(5, 0),
        })
    }

    fn set_metadata(&self, _metadata: &Metadata) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }

    /// Polls something
    fn async_poll<'ctx>(
        &'ctx self,
    ) -> Pin<Box<dyn Future<Output = rcore_fs::vfs::Result<PollStatus>> + Send + Sync + 'ctx>> {
        Box::pin(Serial { inner: self })
    }
}

/// termios is a Unix API for terminal I/O that describes a general terminal interface provided to control asynchronous
/// communication ports. It contains a number of line-control functions that allow more fine-grained control over the
/// serial line in certain special situations. The anatomy of a program performing serial I/O with the help of termios
/// is as follows: Configure communication parameters and other interface properties (line discipline, etc.) with the
/// help of specific termios functions and data structures.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,   /* input modes */
    pub c_oflag: u32,   /* output modes */
    pub c_cflag: u32,   /* control modes */
    pub c_lflag: u32,   /* local modes */
    pub c_line: u8,     /* line discipline */
    pub c_cc: [u8; 19], /* special characters */
    pub c_ispeed: u32,  /* input speed */
    pub c_ospeed: u32,  /* output speed */
}

#[derive(Clone, Debug, Copy)]
#[repr(C)]
struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl Default for Winsize {
    fn default() -> Self {
        Self {
            ws_row: 400,
            ws_col: 200,
            ws_xpixel: 100,
            ws_ypixel: 100,
        }
    }
}

impl Termios {
    pub fn new() -> Self {
        Self {
            c_iflag: (InputModes::IMAXBEL
                | InputModes::IUCLC
                | InputModes::IUTF8
                | InputModes::BRKINT
                | InputModes::ICRNL
                | InputModes::IXON)
                .bits(),
            c_oflag: (OutputModes::OPOST | OutputModes::ONLCR).bits(),
            c_cflag: (ControlModes::HUPCL | ControlModes::CREAD | ControlModes::CSIZE).bits()
                | 0x0000000f,
            c_lflag: (LocalModes::IEXTEN
                | LocalModes::ECHOCTL
                | LocalModes::ECHOKE
                | LocalModes::ECHOE
                | LocalModes::ECHOK
                | LocalModes::ISIG
                | LocalModes::ICANON)
                .bits(),
            c_line: 0,
            // #define INIT_C_CC {
            //      [VINTR] = 'C'-0x40,
            //      [VQUIT] = '\\'-0x40,
            //      [VERASE] = '\177',
            //      [VKILL] = 'U'-0x40,
            //      [VEOF] = 'D'-0x40,
            //      [VSTART] = 'Q'-0x40,
            //      [VSTOP] = 'S'-0x40,
            //      [VSUSP] = 'Z'-0x40,
            //      [VREPRINT] = 'R'-0x40,
            //      [VDISCARD] = 'O'-0x40,
            //      [VWERASE] = 'W'-0x40,
            //      [VLNEXT] = 'V'-0x40,
            //      INIT_C_CC_VDSUSP_EXTRA
            //      [VMIN] = 1 }
            c_cc: [
                3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 255, 18, 15, 23, 22, 255, 0, 0,
            ],
            // baud speed: 38400.
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }
}

impl Default for Termios {
    fn default() -> Self {
        Self::new()
    }
}
