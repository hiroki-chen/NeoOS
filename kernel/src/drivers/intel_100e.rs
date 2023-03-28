//! The driver for the network card on the PCI bus. On Qemu, this is 0x8086, 0x100e, a.k.a.:
//! Intel Corporation 82545EM Gigabit Ethernet Controller.

use core::net::SocketAddr;

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use smoltcp::{
    iface::{Config, Interface, SocketHandle},
    phy::{DeviceCapabilities, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, State},
    wire::{
        EthernetAddress as MacAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address,
    },
};

use crate::{
    arch::PAGE_SIZE,
    error::{Errno, KResult},
    function, kerror, kinfo,
    memory::{allocate_frame_contiguous, deallocate_frame, phys_to_virt, virt_to_phys},
    net::{get_free_port, SOCKET_SET},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::{
    isomorphic_drivers::{
        net::ethernet::{intel::e1000::E1000, structs::EthernetAddress},
        provider::Provider,
    },
    Driver, Type, DRIVERS, IRQ_MANAGER, NETWORK_DRIVERS, NETWORK_UUID, SOCKET_CONDVAR,
};

/// A dummy mac address.
const MAC_ADDRESS: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

pub struct RxTokenIntel(Vec<u8>);
pub struct TxTokenIntel(IntelEthernetDriverWrapper);

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
}

impl IntelEthernetDriverWrapper {
    pub fn new(header: usize, size: usize, mac: EthernetAddress) -> Self {
        Self {
            inner: Arc::new(Mutex::new(E1000::new(header, size, mac))),
        }
    }
}

impl RxToken for RxTokenIntel {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl TxToken for TxTokenIntel {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; PAGE_SIZE];
        // Construct a valid packet for sending.
        let res = f(&mut buf[..len]);

        let mut driver = self.0.inner.lock();
        driver.send(&buf);

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
        self.inner
            .lock()
            .receive()
            .map(|data| (RxTokenIntel(data), TxTokenIntel(self.clone())))
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        match self.inner.lock().can_send() {
            true => Some(TxTokenIntel(self.clone())),
            false => None,
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_burst_size = Some(64);
        cap.max_transmission_unit = 1500;
        cap
    }
}

pub struct IntelEthernetController {
    /// The driver implementation.
    driver: IntelEthernetDriverWrapper,
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

        // Set the default netowrk gateway.
        let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, 1, 2), 24)];
        interface.update_ip_addrs(|ip| {
            ip.extend_from_slice(&ip_addrs).unwrap();
        });

        kinfo!("gateway set for 10.0.1.2/24");

        Self {
            driver,
            interface: Mutex::new(interface),
            irq,
            name,
        }
    }
}

impl Driver for IntelEthernetController {
    fn dispatch(&self, irq: Option<u64>) -> bool {
        true
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
        TxTokenIntel(self.driver.clone()).consume(buf.len(), |data| {
            data.copy_from_slice(buf);
            Ok(data.len())
        })
    }

    fn poll(&self) {
        // todo.
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
                            State::SynSent => {
                                drop(socket);
                                SOCKET_CONDVAR.wait(socket_set);
                            }
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
    }
    Ok(driver)
}
