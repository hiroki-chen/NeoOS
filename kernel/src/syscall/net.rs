//! Networking syscall interfaces.

use core::net::SocketAddr;

use alloc::{boxed::Box, sync::Arc};

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::{Errno, KResult},
    fs::file::FileObject,
    net::{Socket, TcpStream, UdpStream},
    process::thread::{Thread, ThreadContext},
    sys::{IpProto, SockAddr, SocketType, AF_INET, AF_UNIX},
    utils::ptr::Ptr,
};

/// `socket()` creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
/// The file descriptor returned by a successful call will be the lowest-numbered file descriptor not currently
/// open for the process.
pub fn sys_socket(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // The domain argument specifies a communication domain; this
    // selects the protocol family which will be used for communication.
    let domain = syscall_registers[0];
    // The socket has the indicated type, which specifies the
    // communication semantics.
    let ty = syscall_registers[1];
    // The protocol specifies a particular protocol to be used with the
    // socket.
    let protocol = syscall_registers[2];

    // FIXME: We assume they are valid for the time being.
    let socket_type = unsafe { core::mem::transmute::<u8, SocketType>((ty & 0xff) as u8) };
    let ipproto_type = unsafe { core::mem::transmute::<u8, IpProto>((protocol & 0xff) as u8) };

    let socket: Box<dyn Socket> = match domain {
        AF_INET | AF_UNIX => match socket_type {
            SocketType::SockStream => Box::new(TcpStream::new()),
            SocketType::SockDgram => Box::new(UdpStream::new()),
            SocketType::SockRaw => {
                todo!()
            }
        },

        _ => return Err(Errno::EINVAL), // unsupported.
    };

    let socket_fd = thread.parent.lock().add_file(FileObject::Socket(socket))?;
    Ok(socket_fd as _)
}

/// The `connect()` system call connects the socket referred to by the file descriptor sockfd to the address specified by addr.
/// The `addrlen` argument specifies the size of addr. The format of the address in addr is determined by the address space
/// of the socket sockfd.
pub fn sys_connect(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let socket_fd = syscall_registers[0];
    let sockaddr = syscall_registers[1];
    let addrlen = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(socket_fd)?;

    if let FileObject::Socket(socket) = socket {
        // Parse the sockaddr and addrlen.
        let sockaddr_ptr = Ptr::new(sockaddr as *mut SockAddr);
        // FIXME: check_read is always wrong.
        // thread.vm.lock().check_read_array(&sockaddr_ptr, 1).unwrap();
        let addr = unsafe { sockaddr_ptr.read() }?;

        let ipv4_addr = match addr.sa_family as u64 {
            AF_INET => addr.to_core_sockaddr(),
            _ => return Err(Errno::EINVAL),
        };

        socket.connect(ipv4_addr).map(|_| 0)
    } else {
        Err(Errno::EBADF)
    }
}

/// Binds a name to a socket
pub fn sys_bind(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let sockaddr = syscall_registers[1];
    let addrlen = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let sockaddr_ptr = Ptr::new(sockaddr as *mut SockAddr);
        let addr = unsafe { sockaddr_ptr.read() }?;

        let ipv4_addr = match addr.sa_family as u64 {
            AF_INET => addr.to_core_sockaddr(),
            _ => return Err(Errno::EINVAL),
        };

        socket.bind(ipv4_addr).map(|_| 0)
    } else {
        Err(Errno::EBADF)
    }
}

/// `listen()` marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept
/// incoming connection requests using accept(2).
pub fn sys_listen(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    // Not used. always 0.
    let _backlog = syscall_registers[1];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        socket.listen().map(|_| 0)
    } else {
        Err(Errno::EBADF)
    }
}

/// The accept() system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET). It extracts the firs
/// connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket
/// and returns a new file descriptor referring to that socket.  The newly created socket is not in the listening state.
/// The original socket sockfd is unaffected by this call.
pub async fn sys_accept(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let sockaddr = syscall_registers[1];
    let socklen = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let socket = socket
            .as_any_mut()
            .downcast_mut::<TcpStream>()
            .ok_or(Errno::EINVAL)?;
        let (accepted, addr) = socket.accept().await?;
        if let SocketAddr::V4(addr) = addr {
            // Write back to user space.
            proc.add_file(FileObject::Socket(accepted))?;
            let ptr = Ptr::new(sockaddr as *mut SockAddr);

            unsafe {
                ptr.write(SockAddr {
                    // Mark as fixed.
                    sa_family: AF_INET as _,
                    sa_data_min: {
                        let mut buf = [0u8; 14];
                        buf[..2].copy_from_slice(&addr.port().to_be_bytes());
                        buf[2..].copy_from_slice(&addr.ip().octets());
                        buf
                    },
                })?;
            }
            Ok(0)
        } else {
            Err(Errno::EINVAL)
        }
    } else {
        Err(Errno::EBADF)
    }
}
