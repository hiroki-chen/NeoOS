//! A socket for sending and receiving raw packets.

use core::{net::SocketAddr, time::Duration};

use alloc::{vec, vec::Vec};
use smoltcp::{
    socket::raw::{PacketBuffer, PacketMetadata, Socket},
    wire::{IpProtocol, IpVersion},
};

use crate::{
    error::{Errno, KResult},
    sys::SocketOptions,
};

use super::{
    Shutdown, Socket as SocketTrait, SocketType, SocketWrapper, RECVBUF_LEN, SENDBUF_LEN,
    SOCKET_SET,
};

pub struct RawSocket {
    socket: SocketWrapper,
}

impl RawSocket {
    pub fn new(protocol_type: IpProtocol) -> Self {
        // Prepare a raw socket.
        let socket = Socket::new(
            IpVersion::Ipv4,
            protocol_type,
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 1024], vec![0u8; RECVBUF_LEN]),
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 1024], vec![0u8; SENDBUF_LEN]),
        );

        Self {
            socket: SocketWrapper(SOCKET_SET.lock().add(socket)),
        }
    }
}

impl SocketTrait for RawSocket {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        todo!()
    }

    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> Result<usize, Errno> {
        todo!()
    }

    fn bind(&mut self, addr: SocketAddr) -> KResult<()> {
        todo!()
    }

    fn listen(&mut self) -> KResult<()> {
        todo!()
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        Err(Errno::EINVAL)
    }

    fn setsocketopt(&mut self, key: SocketOptions, value: Vec<u8>) -> KResult<()> {
        todo!()
    }

    fn timeout(&self) -> Option<Duration> {
        todo!()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        todo!()
    }

    fn addr(&self) -> Option<SocketAddr> {
        todo!()
    }

    fn set_timeout(&mut self, timeout: Duration) {
        todo!()
    }

    fn shutdown(&mut self, shutdown: Shutdown) -> KResult<()> {
        todo!()
    }

    fn as_raw_fd(&self) -> KResult<u64> {
        todo!()
    }

    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()> {
        Err(Errno::EINVAL)
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }

    fn ty(&self) -> SocketType {
        SocketType::Raw
    }

    fn set_fd(&mut self, fd: u64) {
        todo!()
    }
}
