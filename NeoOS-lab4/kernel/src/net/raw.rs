//! A socket for sending and receiving raw packets.

use core::{
    any::Any,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use alloc::{collections::BTreeMap, vec, vec::Vec};
use smoltcp::{
    socket::raw::{PacketBuffer, PacketMetadata, Socket},
    wire::{IpProtocol, IpVersion, Ipv4Address, Ipv4Packet},
};

#[allow(unused_imports)]
use crate::{
    drivers::intel_e1000::{IP_CIDR_HOST, IP_CIDR_TAP},
    error::{Errno, KResult},
    sys::SocketOptions,
};

use super::{
    Shutdown, Socket as SocketTrait, SocketType, SocketWrapper, IPV4_HDR_LEN, RECVBUF_LEN,
    SENDBUF_LEN, SOCKET_SET,
};

/// Represents a L3-layer raw socket that can be used to examine the IP header and construct the corresponding network
/// protocols like ICMP, ARP, etc.
pub struct RawSocket {
    socket: SocketWrapper,
    raw_fd: Option<u64>,
    /// The address this socket binds to.
    addr: Option<SocketAddr>,
    /// Socket options.
    socket_options: BTreeMap<SocketOptions, Vec<u8>>,
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
            raw_fd: None,
            addr: None,
            socket_options: BTreeMap::new(),
        }
    }
}

impl SocketTrait for RawSocket {
    fn read(&self, buf: &mut [u8]) -> KResult<(usize, Option<SocketAddr>)> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        if socket.can_recv() {
            let read_len = socket.recv_slice(buf).map_err(|_| Errno::ENOTCONN)?;

            // Construct the remote socket address.
            let packet = Ipv4Packet::new_checked(buf.to_vec()).map_err(|_| Errno::EINVAL)?;
            let ip_addr = packet.src_addr().as_bytes().to_vec();
            let ip_addr = Ipv4Addr::new(ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
            let addr = SocketAddr::V4(SocketAddrV4::new(ip_addr, 0));

            Ok((read_len, Some(addr)))
        } else {
            Err(Errno::ENOMEDIUM)
        }
    }

    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> KResult<usize> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        if !socket.can_recv() {
            return Err(Errno::ENOMEDIUM);
        }

        // By default, there would be no header for the raw socket.
        let has_header = self
            .socket_options
            .get(&SocketOptions::IpHdrincl)
            .unwrap_or(&vec![0u8])
            .first()
            .copied()
            .unwrap()
            != 0;
        if has_header {
            if socket.can_send() {
                match socket.send_slice(buf) {
                    Ok(_) => Ok(buf.len()),
                    Err(_) => Err(Errno::ENOMEM),
                }
            } else {
                Err(Errno::EAGAIN)
            }
        } else {
            // Assemble an IP header and send to the socket.
            match dst {
                Some(SocketAddr::V4(addr)) => {
                    if let Some(SocketAddr::V4(src_addr)) = self.addr {
                        // Determine the destination IP address from the function's parameter.
                        let ip_address = Ipv4Address::from_bytes(&addr.ip().octets());
                        let buffer = vec![0u8; IPV4_HDR_LEN + buf.len()];

                        // Assemble the header.
                        let mut packet = Ipv4Packet::new_unchecked(buffer);
                        packet.set_dst_addr(ip_address);
                        packet.set_src_addr(Ipv4Address::from_bytes(&src_addr.ip().octets()));
                        packet.set_header_len(20);
                        packet.set_version(4);
                        packet.payload_mut().copy_from_slice(&buf);
                        packet.fill_checksum();

                        // Send the packet.
                        socket
                            .send_slice(packet.as_ref())
                            .map_err(|_| Errno::ENOTCONN)
                            .map(|_| buf.len() + IPV4_HDR_LEN)
                    } else {
                        Err(Errno::ENOMEDIUM)
                    }
                }
                Some(_) | None => Err(Errno::ENOMEDIUM),
            }
        }
    }

    fn bind(&mut self, addr: SocketAddr) -> KResult<()> {
        if self.addr.is_some() {
            return Err(Errno::EALREADY);
        }

        self.addr.replace(addr);
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        Ok(())
    }

    fn listen(&mut self) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn connect(&mut self, addr: SocketAddr) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn setsockopt(&mut self, key: SocketOptions, value: Vec<u8>) -> KResult<()> {
        self.socket_options
            .entry(key)
            .and_modify(|entry| {
                *entry = value;
            })
            .or_default();
        Ok(())
    }

    fn getsockopt(&self, key: SocketOptions) -> KResult<Vec<u8>> {
        self.socket_options.get(&key).cloned().ok_or(Errno::ENOENT)
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

    fn set_timeout(&mut self, timeout: Duration) {
        unimplemented!()
    }

    fn shutdown(&mut self, shutdown: Shutdown) -> KResult<()> {
        Err(Errno::ESOCKTNOSUPPORT)
    }

    fn as_raw_fd(&self) -> KResult<u64> {
        self.raw_fd.ok_or(Errno::EINVAL)
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
        SocketType::Raw
    }

    fn set_fd(&mut self, fd: u64) {
        self.raw_fd.replace(fd);
    }
}
