use alloc::{boxed::Box, vec};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket};

use core::{net::SocketAddr, time::Duration};

use crate::error::{Errno, KResult};

use super::{Shutdown, Socket as SocketTrait, SocketWrapper, RECVBUF_LEN, SENDBUF_LEN, SOCKET_SET};

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
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        todo!()
    }

    fn write(&mut self, buf: &[u8]) -> KResult<usize> {
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

    fn setsocketopt(&mut self) -> KResult<()> {
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

    fn as_raw_fd(&self) -> u64 {
        todo!()
    }

    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn SocketTrait> {
        todo!()
    }

    fn accept(&mut self) -> KResult<(Box<dyn SocketTrait>, SocketAddr)> {
        Err(Errno::EINVAL)
    }
}
