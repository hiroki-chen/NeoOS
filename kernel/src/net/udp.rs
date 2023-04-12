use alloc::{boxed::Box, vec, vec::Vec};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket};

use core::{any::Any, net::SocketAddr, time::Duration};

use crate::{error::KResult, sys::SocketOptions};

use super::{
    Shutdown, Socket as SocketTrait, SocketType, SocketWrapper, RECVBUF_LEN, SENDBUF_LEN,
    SOCKET_SET,
};

pub const UDP_META_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct UdpStream {
    socket: SocketWrapper,
    addr: Option<SocketAddr>,
}

impl UdpStream {
    pub fn new() -> Self {
        let udp_socket_inner = Socket::new(
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; UDP_META_LEN],
                vec![0u8; RECVBUF_LEN],
            ),
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; UDP_META_LEN],
                vec![0u8; SENDBUF_LEN],
            ),
        );

        let socket = SocketWrapper(SOCKET_SET.lock().add(udp_socket_inner));
        Self { socket, addr: None }
    }
}

unsafe impl Send for UdpStream {}
unsafe impl Sync for UdpStream {}

impl SocketTrait for UdpStream {
    fn read(&self, buf: &mut [u8]) -> KResult<(usize, Option<SocketAddr>)> {
        todo!()
    }

    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> KResult<usize> {
        todo!()
    }

    fn bind(&mut self, addr: SocketAddr) -> KResult<()> {
        todo!()
    }

    fn listen(&mut self) -> KResult<()> {
        todo!()
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        todo!()
    }

    fn setsockopt(&mut self, key: SocketOptions, value: Vec<u8>) -> KResult<()> {
        todo!()
    }

    fn getsockopt(&self, key: SocketOptions) -> KResult<Vec<u8>> {
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

    fn shutdown(&mut self, how: Shutdown) -> KResult<()> {
        todo!()
    }

    fn as_raw_fd(&self) -> KResult<u64> {
        todo!()
    }

    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()> {
        todo!()
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn ty(&self) -> SocketType {
        SocketType::Udp
    }

    fn set_fd(&mut self, fd: u64) {
        todo!()
    }

    fn clone_as_box(&self) -> Box<dyn SocketTrait> {
        Box::new(self.clone())
    }
}
