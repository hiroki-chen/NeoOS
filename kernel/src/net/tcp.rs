use alloc::{boxed::Box, vec};
use smoltcp::{
    socket::tcp::{Socket, SocketBuffer},
    wire::IpListenEndpoint,
};

use core::{
    any::Any,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::{
    drivers::NETWORK_DRIVERS,
    error::{Errno, KResult},
    function, kerror, kinfo,
    net::{RECVBUF_LEN, SENDBUF_LEN, SOCKET_SET},
};

use super::{convert_addr, Shutdown, Socket as SocketTrait, SocketWrapper};

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
    /// Peer's address.
    peer: Option<SocketAddr>,
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
            peer: None,
            state: TcpState::Uninit,
        }
    }

    #[inline]
    pub fn state(&self) -> TcpState {
        self.state
    }

    #[inline]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub async fn accept(&mut self) -> KResult<(Box<dyn SocketTrait>, SocketAddr)> {
        let local_endpoint = self.addr.ok_or(Errno::EINVAL)?;
        if let SocketAddr::V4(local_endpoint) = local_endpoint {
            let local_endpoint = IpListenEndpoint {
                addr: Some(convert_addr(&local_endpoint)),
                port: local_endpoint.port(),
            };

            // Block the current thread.
            loop {
                let mut socket_set = SOCKET_SET.lock();
                let socket = socket_set.get_mut::<smoltcp::socket::tcp::Socket>(self.socket.0);

                // Check the state.
                if self.state == TcpState::Listening && socket.is_active() {
                    if let Some(remote_endpoint) = socket.remote_endpoint() {
                        // May have security issues: syn flood.
                        let rx_buffer = SocketBuffer::new(vec![0; RECVBUF_LEN]);
                        let tx_buffer = SocketBuffer::new(vec![0; SENDBUF_LEN]);

                        let mut socket = Socket::new(rx_buffer, tx_buffer);
                        // TODO: Timeout? ==> return EWOULDBLOCK.
                        socket
                            .listen(local_endpoint)
                            .map_err(|_| Errno::ECONNREFUSED)?;
                        let old = core::mem::replace(&mut self.socket.0, socket_set.add(socket));

                        let boxed_socket = Box::new(TcpStream {
                            socket: SocketWrapper(old),
                            addr: self.addr,
                            peer: None, // The old one should be destroyed.
                            state: TcpState::Dead,
                        });

                        let ip_bytes = remote_endpoint.addr.as_bytes();
                        let socket_addr = SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]),
                            remote_endpoint.port,
                        ));
                        return Ok((boxed_socket, socket_addr));
                    }
                } else {
                    drop(socket);
                    drop(socket_set);
                    NETWORK_DRIVERS.read().iter().for_each(|driver| {
                        driver.poll();
                    });
                }
            }
        } else {
            Err(Errno::EINVAL)
        }
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

                    // Ignore.
                    if socket.is_listening() {
                        return Ok(());
                    }

                    let local_endpoint = IpListenEndpoint {
                        addr: Some(convert_addr(&addr)),
                        port: addr.port(),
                    };
                    socket.listen(local_endpoint).map_err(|_| Errno::EINVAL)?;
                    self.state = TcpState::Listening;

                    Ok(())
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

        driver.connect(addr, self.socket.0)?;
        self.state = TcpState::Alive;
        kinfo!("connecting to {:?}", addr);
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

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// Of course fd can be sent across threads safely.
unsafe impl Send for TcpStream {}
unsafe impl Sync for TcpStream {}
