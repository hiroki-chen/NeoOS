//! Teletypewriter. TTY is a virtual terminal that provides a text-based interface for interacting with the system.

use core::any::Any;

use alloc::{collections::VecDeque, sync::Arc};
use lazy_static::lazy_static;
use rcore_fs::vfs::{make_rdev, FileType, FsError, INode, Metadata, PollStatus, Timespec};
use spin::RwLock;

use crate::{
    function, kerror, print,
    process::event::{Event, EventBus},
    sync::mutex::SpinLock as Mutex,
};

lazy_static! {
    pub static ref TTY: Arc<TtyInode> = Arc::new(TtyInode::new());
}

/// The TTY inode located under `/dev`. It should be lazily initialized after the filesystem is up.
/// The file /dev/tty is a character file with major number 5 and minor number 0, usually of mode 0666 and
/// owner.group root.tty. It is a synonym for the controlling terminal of a process, if any.
pub struct TtyInode {
    /// The process pid thatcurrently occupies the tty.
    fg_pid: RwLock<usize>,
    buffer: Mutex<VecDeque<u8>>,
    eventbus: Mutex<EventBus>,
}

impl TtyInode {
    pub fn new() -> Self {
        Self {
            fg_pid: RwLock::new(usize::MAX),
            buffer: Mutex::new(VecDeque::new()),
            eventbus: Mutex::new(EventBus::default()),
        }
    }

    pub fn get_fd_pid(&self) -> usize {
        self.fg_pid.read().clone()
    }

    pub fn buf_available(&self) -> bool {
        !self.buffer.lock().is_empty()
    }

    pub fn read_byte(&self) -> u8 {
        let mut buf = self.buffer.lock();
        let byte = buf.pop_front().unwrap();

        if buf.is_empty() {
            self.eventbus.lock().set(Event::READABLE);
        }
        byte
    }

    pub fn write_byte(&self, byte: u8) {
        // Resort to ioctl?
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
}
