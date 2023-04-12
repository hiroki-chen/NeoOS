//! The network stacks including socket.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec,
    vec::Vec,
};
use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use rcore_fs::vfs::PollStatus;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::tcp::SocketBuffer,
    wire::{IpAddress, Ipv4Address},
};
use spin::RwLock;

use core::{
    any::Any,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::{
    arch::cpu::rdrand,
    error::{Errno, KResult},
    sync::mutex::SpinLock as Mutex,
    sys::SocketOptions,
};

#[cfg(feature = "raw_socket")]
mod raw;

pub mod tcp;
pub mod udp;

#[cfg(feature = "raw_socket")]
pub use raw::*;

pub use tcp::*;
pub use udp::*;

lazy_static! {
    /// A static managed socket sets which store alive and available socket fds for us.
    pub static ref SOCKET_SET: Mutex<SocketSet<'static>> = Mutex::new(SocketSet::new(Vec::new()));
    /// A port record map.
    pub static ref PORT_IN_USE: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    /// A table used to track which socket handle is listening because listening socket is no longer valid for other usage.
    pub static ref LISTEN_TABLE: RwLock<ListenTable> = RwLock::new(ListenTable::new());
}

pub const RECVBUF_LEN: usize = 4096;
pub const SENDBUF_LEN: usize = 4096;
pub const IPV4_HDR_LEN: usize = 20;
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

/// Socket types.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SocketType {
    /// A UDP socket.
    Udp,
    /// A TCP socket.
    Tcp,
    /// A raw socket working on the transmission layer.
    Raw,
}

/// Possible values which can be passed to the [`TcpStream::shutdown`] method.
#[derive(Copy, Clone, PartialEq, Eq, Debug, TryFromPrimitive)]
#[repr(u64)]
pub enum Shutdown {
    /// The reading portion of the [`TcpStream`] should be shut down.
    ///
    /// All currently blocked and future [reads] will return <code>[Ok]\(0)</code>.
    ///
    /// [reads]: crate::io::Read "io::Read"
    Read = 0,
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

/// A listening table wrapper.
pub struct ListenTable(BTreeMap<u16, ListenTableEntry>);
pub struct ListenTableEntry(VecDeque<SocketHandle>);

impl ListenTable {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// If a new connection arrives, the main thread polls the driver which adds this connection into the listen table.
    pub fn add_incoming_connection(&mut self, src: SocketAddr, dst: SocketAddr) -> KResult<()> {
        if let Some(entry) = self.0.get_mut(&dst.port()) {
            if entry.0.len() >= 64 {
                return Err(Errno::ENOMEM);
            }

            let mut socket = smoltcp::socket::tcp::Socket::new(
                SocketBuffer::new(vec![0u8; RECVBUF_LEN]),
                SocketBuffer::new(vec![0u8; SENDBUF_LEN]),
            );
            if socket.listen(dst.port()).is_ok() {
                let socket_handle = SOCKET_SET.lock().add(socket);
                entry.0.push_back(socket_handle);
            }
        }

        Ok(())
    }

    /// Checks whether a port can be used to listen.
    #[inline]
    pub fn is_free(&self, port: u16) -> bool {
        !self.0.contains_key(&port)
    }

    /// Listens to a port.
    pub fn listen(&mut self, port: u16) -> KResult<()> {
        if !self.is_free(port) {
            Err(Errno::EEXIST)
        } else {
            // Occupy this entry, but does not add socket handles.
            self.0.insert(port, ListenTableEntry::new());
            Ok(())
        }
    }

    #[inline]
    /// Removes a port from listening.
    pub fn remove(&mut self, port: u16) -> KResult<()> {
        if self.0.contains_key(&port) {
            self.0.remove(&port);
        }

        Ok(())
    }

    /// Accepts incoming tcp connections from the other side.
    pub fn accept(&mut self, port: u16, peek: bool) -> KResult<(SocketHandle, SocketAddr)> {
        if let Some(entry) = self.0.get_mut(&port) {
            if let Some(&first) = entry.0.front() {
                let socket_set = SOCKET_SET.lock();
                let socket = socket_set.get::<smoltcp::socket::tcp::Socket>(first.clone());

                let state = socket.state();
                if matches!(
                    state,
                    smoltcp::socket::tcp::State::Listen
                        | smoltcp::socket::tcp::State::SynReceived
                        | smoltcp::socket::tcp::State::Established,
                ) {
                    if !peek {
                        entry.0.pop_front();
                    }

                    let remote_endpoint = socket.remote_endpoint().ok_or(Errno::EINVAL)?;
                    let remote_endpoint = remote_endpoint.addr.as_bytes();
                    let socket_addr = SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(
                            remote_endpoint[0],
                            remote_endpoint[1],
                            remote_endpoint[2],
                            remote_endpoint[3],
                        ),
                        port,
                    ));

                    return Ok((first, socket_addr));
                }

                Err(Errno::EAGAIN)
            } else {
                // No incoming.
                return Err(Errno::EAGAIN);
            }
        } else {
            // No such port.
            Err(Errno::EACCES)
        }
    }
}

impl ListenTableEntry {
    pub fn new() -> Self {
        Self(VecDeque::new())
    }
}

impl Drop for ListenTableEntry {
    fn drop(&mut self) {
        let mut socket_set = SOCKET_SET.lock();
        while let Some(socket_handle) = self.0.pop_front() {
            socket_set.remove(socket_handle);
        }
    }
}

/// Defines a set of socket-like behaviors for tcp, udp, quic, etc. protocols.
pub trait Socket: Send + Sync {
    fn clone_as_box(&self) -> Box<dyn Socket>;

    /// Polls this socket.
    fn poll(&self) -> KResult<PollStatus> {
        Err(Errno::EINVAL)
    }

    /// Reads from this socket.
    fn read(&self, buf: &mut [u8]) -> KResult<(usize, Option<SocketAddr>)>;

    /// Writes to this socket.
    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> KResult<usize>;

    /// Binds to a given address.
    fn bind(&mut self, addr: SocketAddr) -> KResult<()>;

    /// Assigns this socket with a fd.
    fn set_fd(&mut self, fd: u64);

    /// Listens to a given address.
    fn listen(&mut self) -> KResult<()>;

    /// Connects to a given address.
    fn connect(&mut self, addr: SocketAddr) -> KResult<()>;

    /// Sets the socket options.
    fn setsockopt(&mut self, key: SocketOptions, value: Vec<u8>) -> KResult<()>;

    /// Gets the socket options.
    fn getsockopt(&self, key: SocketOptions) -> KResult<Vec<u8>>;

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
    fn as_raw_fd(&self) -> KResult<u64>;

    /// Set the nonblocking bit.
    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()>;

    /// Cast between trait objects as reference.
    fn as_any_ref(&self) -> &dyn Any;

    /// Cast between trait objects as reference.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Gets the type of this socket.
    fn ty(&self) -> SocketType;
}

impl Clone for Box<dyn Socket> {
    fn clone(&self) -> Self {
        self.clone_as_box()
    }
}
