use alloc::{boxed::Box, vec, vec::Vec};
use smoltcp::{
    socket::udp::{PacketBuffer, PacketMetadata, RecvError, SendError, Socket},
    wire::IpEndpoint,
};

use core::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use crate::{
    error::{Errno, KResult},
    sys::SocketOptions,
};

use super::{
    convert_addr, Shutdown, Socket as SocketTrait, SocketType, SocketWrapper, RECVBUF_LEN,
    SENDBUF_LEN, SOCKET_SET,
};

pub const UDP_META_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct UdpStream {
    socket: SocketWrapper,
    addr: Option<SocketAddr>,
    fd: Option<u64>,
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
        Self {
            socket,
            addr: None,
            fd: None,
        }
    }
}

unsafe impl Send for UdpStream {}
unsafe impl Sync for UdpStream {}

impl SocketTrait for UdpStream {
    fn read(&self, buf: &mut [u8]) -> KResult<(usize, Option<SocketAddr>)> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        if !socket.is_open() {
            return Err(Errno::ENOMEDIUM);
        }

        match socket.recv_slice(buf) {
            Ok((len, addr)) => {
                let ip = addr.addr.as_bytes();
                let port = addr.port;
                let socket_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port);
                Ok((len, Some(socket_addr)))
            }
            Err(RecvError::Exhausted) => Ok((0, None)),
        }
    }

    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> KResult<usize> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        // if !socket.is_open() {
        //     return Err(Errno::ENOMEDIUM);
        // }
        if let Some(SocketAddr::V4(socket_addr)) = dst {
            let ip = convert_addr(&socket_addr);
            let remote_endpoint = IpEndpoint {
                addr: ip,
                port: socket_addr.port(),
            };

            socket
                .send_slice(buf, remote_endpoint)
                .map_err(|err| match err {
                    SendError::Unaddressable => Errno::EADDRNOTAVAIL,
                    SendError::BufferFull => Errno::ENOMEM,
                })
                .map(|_| buf.len())
        } else {
            Err(Errno::ESOCKTNOSUPPORT)
        }
    }

    fn bind(&mut self, addr: SocketAddr) -> KResult<()> {
        match self.addr {
            Some(addr) => Err(Errno::EALREADY),
            None => {
                self.addr.replace(addr);
                Ok(())
            }
        }
    }

    fn listen(&mut self) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn setsockopt(&mut self, key: SocketOptions, value: Vec<u8>) -> KResult<()> {
        todo!()
    }

    fn getsockopt(&self, key: SocketOptions) -> KResult<Vec<u8>> {
        todo!()
    }

    fn timeout(&self) -> Option<Duration> {
        None
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    fn addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    fn set_timeout(&mut self, timeout: Duration) {}

    fn shutdown(&mut self, how: Shutdown) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn as_raw_fd(&self) -> KResult<u64> {
        self.fd.ok_or(Errno::ENOMEDIUM)
    }

    fn set_nonblocking(&mut self, non_blocking: bool) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
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
        self.fd.replace(fd);
    }

    fn clone_as_box(&self) -> Box<dyn SocketTrait> {
        Box::new(self.clone())
    }
}
