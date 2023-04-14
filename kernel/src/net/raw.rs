//! A socket for sending and receiving raw packets.

use core::{
    any::Any,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use smoltcp::{
    socket::raw::{PacketBuffer, PacketMetadata, Socket},
    wire::{IpProtocol, IpVersion, Ipv4Address, Ipv4Packet},
};

use crate::drivers::NETWORK_DRIVERS;
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
#[derive(Clone)]
pub struct RawSocket {
    socket: SocketWrapper,
    /// Raw file descriptor.
    raw_fd: Option<u64>,
    /// The address this socket binds to.
    addr: Option<SocketAddr>,
    /// Socket options.
    socket_options: BTreeMap<SocketOptions, Vec<u8>>,
    /// protocol type.
    protocol: IpProtocol,
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
            protocol: protocol_type,
        }
    }

    /// Constructs a packet according to `protocol`.
    fn make_packet(&self, src: Ipv4Address, dst: Ipv4Address, data: &[u8]) -> KResult<Vec<u8>> {
        let mut buf = vec![0u8; IPV4_HDR_LEN + data.len()];
        buf[9] = self.protocol.into();
        let mut packet = Ipv4Packet::new_unchecked(buf);

        // Set up the packet.
        packet.set_src_addr(src);
        packet.set_dst_addr(dst);
        packet.set_version(4);
        packet.set_header_len(IPV4_HDR_LEN as _);
        packet.set_total_len((IPV4_HDR_LEN + data.len()) as _);
        packet.payload_mut().copy_from_slice(data);
        packet.fill_checksum();

        Ok(packet.into_inner())
    }
}

impl SocketTrait for RawSocket {
    fn read(&self, buf: &mut [u8]) -> KResult<(usize, Option<SocketAddr>)> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

        NETWORK_DRIVERS.read().iter().for_each(|driver| {
            driver.poll();
        });

        if let Ok(read_len) = socket.recv_slice(buf) {
            // Construct the remote socket address.
            let packet = Ipv4Packet::new_checked(buf.to_vec()).map_err(|_| Errno::EINVAL)?;
            let ip_addr = packet.src_addr().as_bytes().to_vec();
            let ip_addr = Ipv4Addr::new(ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
            let addr = SocketAddr::V4(SocketAddrV4::new(ip_addr, 0));

            Ok((read_len, Some(addr)))
        } else {
            Ok((0, None))
        }
    }

    fn write(&self, buf: &[u8], dst: Option<SocketAddr>) -> KResult<usize> {
        let mut socket_set = SOCKET_SET.lock();
        let socket = socket_set.get_mut::<Socket>(self.socket.0);

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
                    let src_addr = match self.addr {
                        Some(SocketAddr::V4(src_addr)) => src_addr.ip().octets(),
                        Some(_) => return Err(Errno::ESOCKTNOSUPPORT),
                        None => {
                            // Get from the network driver.
                            match NETWORK_DRIVERS.read().first().unwrap().ipv4_addr() {
                                Some(addr) => addr.0,
                                None => return Err(Errno::ENOMEDIUM),
                            }
                        }
                    };

                    // Determine the destination IP address from the function's parameter.
                    let dst_addr = Ipv4Address::from_bytes(&addr.ip().octets());
                    let src_addr = Ipv4Address::from_bytes(&src_addr);
                    let packet = self.make_packet(src_addr, dst_addr, buf)?;
                    // Send the packet.
                    socket
                        .send_slice(packet.as_slice())
                        .map_err(|_| Errno::ENOTCONN)?;

                    Ok(buf.len())
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

    fn clone_as_box(&self) -> Box<dyn SocketTrait> {
        Box::new(self.clone())
    }
}
