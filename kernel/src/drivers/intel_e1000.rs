//! The driver for the network card on the PCI bus. On Qemu, this is 0x8086, 0x100e, a.k.a.:
//! Intel Corporation 82545EM Gigabit Ethernet Controller.

use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::DerefMut,
};

use alloc::{collections::VecDeque, string::String, sync::Arc, vec, vec::Vec};
use smoltcp::{
    iface::{Config, Interface, SocketHandle},
    phy::{DeviceCapabilities, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, State},
    time::Instant,
    wire::{
        EthernetAddress as MacAddress, EthernetFrame, HardwareAddress, IpAddress, IpCidr,
        IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
    },
};

use crate::{
    arch::{interrupt::timer::tick_microsecond, PAGE_SIZE},
    error::{Errno, KResult},
    function, kerror, kinfo, kwarn,
    memory::{allocate_frame_contiguous, deallocate_frame, phys_to_virt, virt_to_phys},
    net::{get_free_port, LISTEN_TABLE, SOCKET_SET},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::{
    isomorphic_drivers::{
        net::ethernet::{intel::e1000::E1000, structs::EthernetAddress},
        provider::Provider,
    },
    Driver, Type, DRIVERS, IRQ_MANAGER, NETWORK_DRIVERS, NETWORK_UUID,
};

/// A dummy mac address.
const MAC_ADDRESS: &[u8] = &[0x52, 0x54, 0x0, 0x12, 0x34, 0x57];
/// Linux setups for tap0.
pub const IP_CIDR_TAP: IpAddress = IpAddress::v4(192, 168, 179, 233);
// macOS vmnet-host default address.
pub const IP_CIDR_HOST: IpAddress = IpAddress::v4(172, 16, 253, 233);
/// Default gateway address.
const DEFAULT_GATEWAY: Ipv4Address = Ipv4Address([0, 0, 0, 0]);
/// Default gateway address for macOS.
const IP_GATEWAY: Ipv4Address = Ipv4Address([172, 16, 253, 1]);
/// Default tap0 gateway address for Linux.
const IP_GATEWAY_TAP: Ipv4Address = Ipv4Address([192, 168, 179, 1]);

#[derive(Clone)]
pub struct RxTokenIntel(Vec<u8>);
pub struct TxTokenIntel(Arc<Mutex<E1000<NetProvider>>>);

pub trait NetworkDriver: Driver {
    /// Returns the MAC address of the physical netowrk card.
    fn mac_addr(&self) -> Vec<u8>;

    /// Returns the IPV4 address.
    fn ipv4_addr(&self) -> Option<Ipv4Address>;

    /// Returns the interface name.
    fn name(&self) -> &str;

    /// Sends a buffer via this interface.
    fn send(&self, buf: &[u8]) -> KResult<usize>;

    /// Polls this interface.
    fn poll(&self);

    /// Connects to the tcp socket.
    fn connect(&self, addr: SocketAddr, socket_handle: SocketHandle) -> KResult<()>;

    /// Gets the ip address of the interface.
    fn ip_addrs(&self) -> Vec<IpCidr>;
}

pub struct NetProvider;

impl Provider for NetProvider {
    const PAGE_SIZE: usize = PAGE_SIZE;

    fn alloc_dma(size: usize) -> (usize, usize) {
        let page_num = size / Self::PAGE_SIZE;
        let phys_addr = match allocate_frame_contiguous(page_num, 0) {
            Ok(addr) => addr,
            Err(errno) => panic!("cannot allocate dma. Errno: {:?}", errno),
        }
        .as_u64();

        (phys_to_virt(phys_addr) as usize, phys_addr as usize)
    }

    fn dealloc_dma(vaddr: usize, size: usize) {
        let phys_addr = virt_to_phys(vaddr as u64);
        let page_num = size / Self::PAGE_SIZE;

        for i in 0..page_num {
            if let Err(errno) = deallocate_frame(phys_addr + (i * Self::PAGE_SIZE) as u64) {
                panic!(
                    "failed to deallocate memory at {:#x}. Errno: {:?}",
                    vaddr, errno
                );
            }
        }
    }
}

/// A wrapper for the driver. We need this because `Interface` accepts the trait object.
#[derive(Clone)]
pub struct IntelEthernetDriverWrapper {
    pub inner: Arc<Mutex<E1000<NetProvider>>>,
    pub receive_queue: VecDeque<RxTokenIntel>,
}

impl IntelEthernetDriverWrapper {
    pub fn new(header: usize, size: usize, mac: EthernetAddress) -> Self {
        Self {
            inner: Arc::new(Mutex::new(E1000::new(header, size, mac))),
            receive_queue: VecDeque::new(),
        }
    }

    pub fn receive(&mut self) -> Option<RxTokenIntel> {
        self.receive_queue.pop_front()
    }

    fn poll(&mut self) {
        let mut inner = self.inner.lock();
        while let Some(data) = inner.receive() {
            self.receive_queue.push_back(RxTokenIntel(data));
        }
    }
}

impl RxToken for RxTokenIntel {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Preprocess something if there is any incoming TCP connections.
        let mut ethernet_frame = EthernetFrame::new_unchecked(self.0.clone());
        if let Ok(mut ip_frame) = Ipv4Packet::new_checked(ethernet_frame.payload_mut()) {
            if ip_frame.next_header() == IpProtocol::Tcp {
                let ip_src = ip_frame.src_addr().as_bytes().to_vec();
                let ip_dst = ip_frame.dst_addr().as_bytes().to_vec();
                if let Ok(tcp_packet) = TcpPacket::new_checked(ip_frame.payload_mut()) {
                    if tcp_packet.syn() && !tcp_packet.ack() {
                        let src_addr = SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(ip_src[0], ip_src[1], ip_src[2], ip_src[3]),
                            tcp_packet.src_port(),
                        ));
                        let dst_addr = SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]),
                            tcp_packet.dst_port(),
                        ));
                        LISTEN_TABLE
                            .write()
                            .add_incoming_connection(src_addr, dst_addr)
                            .unwrap();
                    }
                }
            }
        }

        f(&mut self.0)
    }
}

impl TxToken for TxTokenIntel {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; 1536];
        // Construct a valid packet for sending.
        let res = f(&mut buf[..len]);

        // kinfo!("sending packet {:02x?}", &buf[..len]);
        self.0.lock().send(&buf[..len]);

        res
    }
}

impl smoltcp::phy::Device for IntelEthernetDriverWrapper {
    type RxToken<'a> = RxTokenIntel;
    type TxToken<'a> = TxTokenIntel;

    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.receive()
            .map(|data| (data, TxTokenIntel(self.inner.clone())))
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        match self.inner.lock().can_send() {
            true => Some(TxTokenIntel(self.inner.clone())),
            false => None,
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_burst_size = Some(64);
        cap.max_transmission_unit = 1520;
        cap
    }
}

pub struct IntelEthernetController {
    /// The driver implementation.
    driver: Mutex<IntelEthernetDriverWrapper>,
    /// The ethernet interface for networking.
    interface: Mutex<Interface>,
    /// Interrupt request.
    irq: Option<u8>,
    /// The interface name. E.g., ens1f0.
    name: String,
}

impl IntelEthernetController {
    pub fn new(irq: Option<u8>, header: usize, size: usize, name: String) -> Self {
        let mut config = Config::new();
        config.random_seed = 0xdeadbeef;
        config
            .hardware_addr
            .replace(HardwareAddress::Ethernet(MacAddress::from_bytes(
                MAC_ADDRESS,
            )));
        let mut driver =
            IntelEthernetDriverWrapper::new(header, size, EthernetAddress::from_bytes(MAC_ADDRESS));
        let mut interface = Interface::new(config, &mut driver);

        // Update the route table.
        #[cfg(feature = "linux_gateway")]
        {
            interface.update_ip_addrs(|ip| {
                let cidr = [IpCidr::new(IP_CIDR_TAP, 24)];
                ip.extend_from_slice(&cidr).unwrap();
                kinfo!("ip address set for {:?}", cidr);
            });

            interface
                .routes_mut()
                .add_default_ipv4_route(IP_GATEWAY_TAP)
                .unwrap();
        }

        #[cfg(not(feature = "linux_gateway"))]
        {
            interface.update_ip_addrs(|ip| {
                let cidr = [IpCidr::new(IP_CIDR_HOST, 24)];
                ip.extend_from_slice(&cidr).unwrap();
                kinfo!("ip address set for {:?}", cidr);
            });

            interface
                .routes_mut()
                .add_default_ipv4_route(IP_GATEWAY)
                .unwrap();
        }

        Self {
            driver: Mutex::new(driver),
            interface: Mutex::new(interface),
            irq,
            name,
        }
    }
}

impl Driver for IntelEthernetController {
    fn dispatch(&self, irq: Option<u64>) -> bool {
        // By default we check by matching the irq.
        if irq.map(|irq| irq as u8).unwrap_or(u8::MIN) == self.irq.unwrap_or(u8::MAX) {
            self.driver.lock().inner.lock().handle_interrupt();
            self.poll();
            true
        } else {
            false
        }
    }

    fn ty(&self) -> Type {
        Type::Net
    }

    fn uuid(&self) -> &'static str {
        NETWORK_UUID
    }
}

impl NetworkDriver for IntelEthernetController {
    fn mac_addr(&self) -> Vec<u8> {
        self.interface.lock().hardware_addr().as_bytes().to_vec()
    }

    fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.interface.lock().ipv4_addr()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn send(&self, buf: &[u8]) -> KResult<usize> {
        TxTokenIntel(self.driver.lock().inner.clone()).consume(buf.len(), |data| {
            data.copy_from_slice(buf);
            Ok(data.len())
        })
    }

    fn poll(&self) {
        let mut driver = self.driver.lock();
        driver.poll();

        let timestamp = Instant::from_micros(tick_microsecond().as_micros() as i64);
        let mut interface = self.interface.lock();
        let mut socket_set = SOCKET_SET.lock();
        interface.poll(timestamp, driver.deref_mut(), &mut socket_set);
    }

    fn connect(&self, addr: SocketAddr, socket_handle: SocketHandle) -> KResult<()> {
        if let SocketAddr::V4(addr) = addr {
            let mut interface = self.interface.lock();
            let mut socket_set = SOCKET_SET.lock();
            let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
            // Currently, we only support ipv4.
            let temporary_port = get_free_port();
            let remote_endpoint = IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.ip().octets())),
                addr.port(),
            );

            match socket.connect(interface.context(), remote_endpoint, temporary_port) {
                Ok(_) => {
                    drop(socket_set);
                    drop(interface);
                    // do something.

                    loop {
                        self.poll();

                        // Is connected?
                        let mut socket_set = SOCKET_SET.lock();
                        let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                        match socket.state() {
                            State::SynSent => continue,
                            State::Established => break,
                            _ => return Err(Errno::ECONNREFUSED),
                        }
                    }

                    Ok(())
                }
                Err(err) => {
                    kerror!("connection refused due to {:?}", err);
                    Err(Errno::ECONNREFUSED)
                }
            }
        } else {
            Err(Errno::EINVAL)
        }
    }

    fn ip_addrs(&self) -> Vec<IpCidr> {
        self.interface.lock().ip_addrs().to_vec()
    }
}

pub fn init_network(
    irq: Option<u8>,
    header: usize,
    size: usize,
    name: String,
) -> KResult<Arc<IntelEthernetController>> {
    let driver = Arc::new(IntelEthernetController::new(irq, header, size, name));
    NETWORK_DRIVERS.write().push(driver.clone());
    DRIVERS.write().push(driver.clone());

    if let Some(irq) = irq {
        IRQ_MANAGER
            .write()
            .register_irq(irq as _, driver.clone(), false);
        kinfo!("irq {:#x} registerd for e1000", irq);
    } else {
        kwarn!("There is no MSI assigned for this network card");
        kwarn!("If you are using qemu, make sure networking is configured correctly");
    }
    Ok(driver)
}
