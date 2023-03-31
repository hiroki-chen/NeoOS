use alloc::{boxed::Box, vec};
use smoltcp::{
    socket::tcp::{Socket, SocketBuffer},
    wire::IpListenEndpoint,
};

use core::{any::Any, net::SocketAddr, time::Duration};

use crate::{
    drivers::NETWORK_DRIVERS,
    error::{Errno, KResult},
    function, kerror, kinfo,
    net::{LISTEN_TABLE, RECVBUF_LEN, SENDBUF_LEN, SOCKET_SET},
};

use super::{convert_addr, Shutdown, Socket as SocketTrait, SocketType, SocketWrapper};

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
    socket: Option<SocketWrapper>,
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
            socket: Some(socket),
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

    pub fn accept(&mut self) -> KResult<Box<dyn SocketTrait>> {
        if self.state != TcpState::Listening {
            kerror!("This socket is not listening.");
            return Err(Errno::EINVAL);
        }

        let local_endpoint = self.addr.ok_or(Errno::EINVAL)?;
        if let SocketAddr::V4(local_endpoint) = local_endpoint {
            let local_endpoint = IpListenEndpoint {
                addr: Some(convert_addr(&local_endpoint)),
                port: local_endpoint.port(),
            };

            loop {
                // Polls each driver.
                NETWORK_DRIVERS.read().iter().for_each(|driver| {
                    driver.poll();
                });

                match LISTEN_TABLE.write().accept(local_endpoint.port) {
                    Ok((socket_handle, remove_address)) => {
                        return Ok(Box::new(Self {
                            socket: Some(SocketWrapper(socket_handle)),
                            addr: Some(self.addr.unwrap()),
                            peer: Some(remove_address),
                            state: TcpState::Alive,
                        }));
                    }

                    Err(Errno::EAGAIN) => continue,
                    Err(errno) => {
                        kerror!("cannot accept incoming connection.");
                        return Err(errno);
                    }
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
                    if self.socket.is_none() {
                        return Ok(());
                    }

                    LISTEN_TABLE.write().listen(addr.port())?;
                    kinfo!("socket is listening on port {}", addr.port());
                    // Moves this socket handle.
                    let handle = self.socket.take();
                    SOCKET_SET.lock().remove(handle.unwrap().0);
                    self.state = TcpState::Listening;

                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
        }
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        let lock = NETWORK_DRIVERS.read();
        let driver = lock.first().ok_or(Errno::ENODEV)?;

        driver.connect(addr, self.socket.as_ref().unwrap().0)?;
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
        self.peer.clone()
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

    fn ty(&self) -> SocketType {
        SocketType::Tcp
    }
}

// Of course fd can be sent across threads safely.
unsafe impl Send for TcpStream {}
unsafe impl Sync for TcpStream {}
