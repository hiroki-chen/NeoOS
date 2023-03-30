//! The network stacks including socket.

use alloc::{collections::BTreeSet, vec::Vec};
use lazy_static::lazy_static;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    wire::{IpAddress, Ipv4Address},
};

use core::{
    any::Any,
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::{arch::cpu::rdrand, error::KResult, sync::mutex::SpinLock as Mutex};

// mod raw;
pub mod tcp;
pub mod udp;

pub use tcp::*;
pub use udp::*;

lazy_static! {
    /// A static managed socket sets which store alive and available socket fds for us.
    pub static ref SOCKET_SET: Mutex<SocketSet<'static>> = Mutex::new(SocketSet::new(Vec::new()));
    /// A port record map.
    pub static ref PORT_IN_USE: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
}

pub const RECVBUF_LEN: usize = 4096;
pub const SENDBUF_LEN: usize = 4096;

/// Allocates a port between 49152 and 65535 as requied by smoltcp.
pub fn get_free_port() -> u16 {
    loop {
        let port = (rdrand() % (u16::MAX - 49152 + 1) as u64) as u16 + 49152;

        let mut lock = PORT_IN_USE.lock();
        if !lock.contains(&port) {
            lock.insert(port);

            return port;
        }
    }
}

/// Converts [`SocketAddrV4`] into [`IpAddress`].
#[inline]
pub fn convert_addr(src: &SocketAddrV4) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::from_bytes(&src.ip().octets()))
}

/// Possible values which can be passed to the [`TcpStream::shutdown`] method.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Shutdown {
    /// The reading portion of the [`TcpStream`] should be shut down.
    ///
    /// All currently blocked and future [reads] will return <code>[Ok]\(0)</code>.
    ///
    /// [reads]: crate::io::Read "io::Read"
    Read,
    /// The writing portion of the [`TcpStream`] should be shut down.
    ///
    /// All currently blocked and future [writes] will return an error.
    ///
    /// [writes]: crate::io::Write "io::Write"
    Write,
    /// Both the reading and the writing portions of the [`TcpStream`] should be shut down.
    ///
    /// See [`Shutdown::Read`] and [`Shutdown::Write`] for more information.
    Both,
}

/// The handle to the socket itself which serves as a reference count to any alive connections.
#[derive(Debug, Clone)]
pub struct SocketWrapper(SocketHandle);

/// Defines a set of socket-like behaviors for tcp, udp, quic, etc. protocols.
pub trait Socket: Send + Sync {
    /// Reads from this socket.
    fn read(&self, buf: &mut [u8]) -> KResult<usize>;

    /// Writes to this socket.
    fn write(&mut self, buf: &[u8]) -> KResult<usize>;

    /// Binds to a given address.
    fn bind(&mut self, addr: SocketAddr) -> KResult<()>;

    /// Listens to a given address.
    fn listen(&mut self) -> KResult<()>;

    /// Connects to a given address.
    fn connect(&mut self, addr: SocketAddr) -> KResult<()>;

    /// Sets the socket options.
    fn setsocketopt(&mut self) -> KResult<()>;

    /// Reads the timeout field.
    fn timeout(&self) -> Option<Duration>;

    /// Gets the peer address.
    fn peer_addr(&self) -> Option<SocketAddr>;

    /// Gets the address of this socket.
    fn addr(&self) -> Option<SocketAddr>;

    /// Sets the timeout.
    fn set_timeout(&mut self, timeout: Duration);

    /// Shutdowns this socket.
    fn shutdown(&mut self, how: Shutdown) -> KResult<()>;

    /// Gets the raw file descriptor of this socket.
    fn as_raw_fd(&self) -> u64;

    /// Set the nonblocking bit.
    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()>;

    /// Cast between trait objects as reference.
    fn as_any_ref(&self) -> &dyn Any;

    /// Cast between trait objects as reference.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
