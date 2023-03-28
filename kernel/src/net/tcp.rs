use alloc::{boxed::Box, vec};
use smoltcp::{
    socket::tcp::{Socket, SocketBuffer},
    wire::{IpAddress, IpListenEndpoint, Ipv4Address},
};

use core::{net::SocketAddr, time::Duration};

use crate::{
    drivers::NETWORK_DRIVERS,
    error::{Errno, KResult},
    function, kerror,
    net::{RECVBUF_LEN, SENDBUF_LEN, SOCKET_SET}, kinfo,
};

use super::{Shutdown, Socket as SocketTrait, SocketWrapper};

/// This enum represents the state of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// A tcp is not initialized. This means the corresponding socket is created.
    Uninit,
    /// The tcp is waiting for the peer.
    Listening,
    /// The tcp is working.
    Alive,
    /// The tcp is closing with a [`Shutdown`] option, denoting whether read/write can still be handled.
    Closing(Shutdown),
    /// The tcp is completely closed and needs to be cleaned.
    Dead,
}

/// A TCP stream between a local and a remote socket.
///
/// After creating a `TcpStream` by either [`connect`]ing to a remote host or
/// [`accept`]ing a connection on a [`TcpListener`], data can be transmitted
/// by [reading] and [writing] to it.
///
/// The connection will be closed when the value is dropped. The reading and writing
/// portions of the connection can also be shut down individually with the [`shutdown`]
/// method.
///
/// The Transmission Control Protocol is specified in [IETF RFC 793].
///
/// [`accept`]: TcpListener::accept
/// [`connect`]: TcpStream::connect
/// [IETF RFC 793]: https://tools.ietf.org/html/rfc793
/// [reading]: Read
/// [`shutdown`]: TcpStream::shutdown
/// [writing]: Write
///
/// # Notes
///
/// In kernel, there is no difference between a listener and a stream, so we treat them as `TcpStream`.
#[derive(Debug, Clone)]
pub struct TcpStream {
    /// The inner socket instance.
    socket: SocketWrapper,
    /// The socket's address.
    addr: Option<SocketAddr>,
    /// Is this socket still alive?
    state: TcpState,
}

impl TcpStream {
    pub fn new() -> Self {
        let tcp_socket_inner = Socket::new(
            SocketBuffer::new(vec![0u8; RECVBUF_LEN]),
            SocketBuffer::new(vec![0u8; SENDBUF_LEN]),
        );
        let socket = SocketWrapper(SOCKET_SET.lock().add(tcp_socket_inner));
        Self {
            socket,
            addr: None,
            state: TcpState::Uninit,
        }
    }

    #[inline]
    pub fn state(&self) -> TcpState {
        self.state
    }
}

impl SocketTrait for TcpStream {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        todo!()
    }

    fn write(&mut self, buf: &[u8]) -> KResult<usize> {
        todo!()
    }

    fn bind(&mut self, addr: SocketAddr) -> KResult<()> {
        if let SocketAddr::V4(addr) = addr {
            if addr.port() == 0 {
                kerror!("no port provided.");
                return Err(Errno::EINVAL);
            }

            self.addr.replace(SocketAddr::V4(addr));
            self.state = TcpState::Uninit;

            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }

    fn listen(&mut self) -> KResult<()> {
        match self.state {
            TcpState::Dead | TcpState::Closing(_) => {
                kerror!("invalid socket state.");
                Err(Errno::EINVAL)
            }

            TcpState::Alive | TcpState::Listening => Ok(()),
            TcpState::Uninit => {
                if let Some(SocketAddr::V4(addr)) = self.addr {
                    // Listen.
                    let mut socket_set = SOCKET_SET.lock();
                    let socket = socket_set.get_mut::<smoltcp::socket::tcp::Socket>(self.socket.0);
                    let local_endpoint = IpListenEndpoint {
                        addr: Some(IpAddress::Ipv4(Ipv4Address::from_bytes(
                            &addr.ip().octets(),
                        ))),
                        port: addr.port(),
                    };

                    kinfo!("listening to {:?}", addr);
                    socket.listen(local_endpoint).map_err(|_| Errno::EINVAL)
                } else {
                    kerror!("no address provided.");
                    Err(Errno::EINVAL)
                }
            }
        }
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        let lock = NETWORK_DRIVERS.read();
        let driver = lock.first().ok_or(Errno::ENODEV)?;

        kinfo!("connecting to {:?}", addr);

        driver.connect(addr, self.socket.0)?;
        self.state = TcpState::Alive;
        Ok(())
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
}

// Of course fd can be sent across threads safely.
unsafe impl Send for TcpStream {}
unsafe impl Sync for TcpStream {}
