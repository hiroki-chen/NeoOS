//! Networking syscall interfaces.

use core::net::{IpAddr, SocketAddr};

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use smoltcp::wire::IpProtocol;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, io::IoVec},
    dummy_impl,
    error::{Errno, KResult},
    fs::file::FileObject,
    net::{RawSocket, Shutdown, Socket, TcpStream, UdpStream},
    process::thread::{Thread, ThreadContext},
    sys::{IpProto, MsgHdr, SockAddr, SocketOptions, SocketType, AF_INET, AF_UNIX},
};

fn get_socket_name<T>(
    thread: &Arc<Thread>,
    socket: &mut Box<dyn Socket>,
    sockaddr: u64,
    len: usize,
    is_self: bool,
) -> KResult<usize> {
    let addr = if is_self {
        match socket.addr() {
            Some(SocketAddr::V4(addr)) => addr,
            Some(_) | None => return Ok(0), // Nothing is changed.
        }
    } else {
        match socket.peer_addr() {
            Some(SocketAddr::V4(addr)) => addr,
            Some(_) | None => return Ok(0), // Nothing is changed.
        }
    };

    let ptr = thread.vm.lock().get_mut_ptr(sockaddr)?;
    if ptr.is_null() {
        return Err(Errno::EFAULT);
    }

    unsafe {
        ptr.write(SockAddr {
            // Mark as fixed.
            sa_family: AF_INET as _,
            sa_data_min: {
                let mut buf = [0u8; 14];
                buf[..2].copy_from_slice(&addr.port().to_be_bytes());
                buf[2..6].copy_from_slice(&addr.ip().octets());
                buf
            },
        })?;
    }

    Ok(0)
}

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
    let socket_type = SocketType::from((ty & 0xff) as u8);
    let ipproto_type = IpProto::from((protocol & 0xff) as u8);

    let socket: Box<dyn Socket> = match domain {
        AF_INET | AF_UNIX => match socket_type {
            SocketType::SockStream => Box::new(TcpStream::new()),
            SocketType::SockDgram => Box::new(UdpStream::new()),
            SocketType::SockRaw => Box::new(RawSocket::new(IpProtocol::from(ipproto_type as u8))),
            SocketType::Unknown => return Err(Errno::EINVAL),
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
        let sockaddr_ptr = thread.vm.lock().get_ptr::<SockAddr>(sockaddr)?;
        let addr = unsafe { sockaddr_ptr.read() }?;

        let ipv4_addr = match addr.sa_family as u64 {
            AF_INET => addr.to_core_sockaddr(),
            _ => return Err(Errno::EINVAL),
        };

        socket.connect(ipv4_addr).map(|_| 0)
    } else {
        Err(Errno::ENOTSOCK)
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
        let sockaddr_ptr = thread.vm.lock().get_ptr::<SockAddr>(sockaddr)?;
        let addr = unsafe { sockaddr_ptr.read() }?;

        let ipv4_addr = match addr.sa_family as u64 {
            AF_INET => addr.to_core_sockaddr(),
            _ => return Err(Errno::EINVAL),
        };

        socket.bind(ipv4_addr).map(|_| 0)
    } else {
        Err(Errno::ENOTSOCK)
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

/// If flags is 0, then accept4() is the same as accept().
pub fn sys_accept4(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let sockaddr = syscall_registers[1];
    let socklen = syscall_registers[2];
    let flags = syscall_registers[3];

    do_accept(thread, sockfd, sockaddr, socklen, flags)
}

/// The accept() system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET). It extracts the firs
/// connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket
/// and returns a new file descriptor referring to that socket.  The newly created socket is not in the listening state.
/// The original socket sockfd is unaffected by this call.
pub fn sys_accept(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let sockaddr = syscall_registers[1];
    let socklen = syscall_registers[2];

    do_accept(thread, sockfd, sockaddr, socklen, 0)
}

/// The shutdown() call causes all or part of a full-duplex connection on the socket associated with sockfd to be shut down.
pub fn sys_shutdown(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let how = syscall_registers[1];

    let mut proc = thread.parent.lock();
    if let Ok(FileObject::Socket(socket)) = proc.get_fd(sockfd) {
        socket
            .shutdown(Shutdown::try_from(how).map_err(|_| Errno::EINVAL)?)
            .map(|_| 0)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

///The setsockopt() function shall set the option specified by the option_name argument, at the protocol level specified by
/// the level argument, to the value pointed to by the option_value argument for the socket associated with the file
/// descriptor specified by the socket argument.
pub fn sys_setsockopt(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let level = syscall_registers[1];
    let option_name = syscall_registers[2];
    let option_value = syscall_registers[3];
    let option_len = syscall_registers[4];

    let option_name = SocketOptions::from(option_name);
    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        // TODO: Check pointer.
        let value =
            unsafe { core::slice::from_raw_parts(option_value as *const u8, option_len as _) }
                .to_vec();
        socket.setsockopt(option_name, value).map(|_| 0)
    } else {
        Err(Errno::EBADF)
    }
}

/// getsockopt() and setsockopt() manipulate options for the socket referred to by the file descriptor sockfd.
pub fn sys_getsockopt(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let level = syscall_registers[1];
    let optname = syscall_registers[2];
    let optval = syscall_registers[3];
    let optlen = syscall_registers[4];

    let vm = thread.vm.lock();
    let opt_ptr = vm.get_ptr(optname)?;
    let len_ptr = vm.get_ptr::<u64>(optlen)?;
    if opt_ptr.is_null() || len_ptr.is_null() {
        return Err(Errno::EFAULT);
    }

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let optname = SocketOptions::from(optname);
        match socket.getsockopt(optname) {
            Ok(val) => unsafe {
                opt_ptr.write_slice(&val);
                len_ptr.write(val.len() as _).map(|_| val.len())
            },
            Err(_) => Ok(0),
        }
    } else {
        Err(Errno::ENOTSOCK)
    }
}

/// getpeername() returns the address of the peer connected to the socket sockfd, in the buffer pointed to by addr.
/// The addrlen argument should be initialized to indicate the amount of space pointed to by addr.
pub fn sys_getpeername(
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
        get_socket_name::<SockAddr>(thread, socket, sockaddr, socklen as _, false)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

/// The system calls send(), sendto(), and sendmsg() are used to transmit a message to another socket.
///
/// # Note
///
/// There is no `send()` syscall because `send()` is converted to `sendto()`.
pub fn sys_sendto(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let buf = syscall_registers[1];
    let len = syscall_registers[2];
    let flags = syscall_registers[3];
    let dst_addr = syscall_registers[4];
    let addr_len = syscall_registers[5];

    let mut proc = thread.parent.lock();
    let vm = thread.vm.lock();
    let socket = proc.get_fd(sockfd)?;
    if let FileObject::Socket(socket) = socket {
        // Check if there is dst_addr.
        let dst_addr = vm.get_ptr::<SockAddr>(dst_addr)?;
        let dst_addr = match dst_addr.is_null() {
            true => None,
            false => {
                let socket_address = unsafe { dst_addr.read() }?.to_core_sockaddr();
                Some(socket_address)
            }
        };

        let buf = vm.get_slice(buf, len as _)?;
        let len = socket.write(buf, dst_addr)?;
        Ok(len)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

pub fn sys_sendmsg(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let msghdr = syscall_registers[1];
    let flags = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let vm = thread.vm.lock();

        let msg_ptr = vm.get_ptr::<MsgHdr>(msghdr)?;
        let msg = unsafe { msg_ptr.read() }?;
        // Read messages from iovec.
        let iovec = msg.msg_iov;
        let iovec_len = msg.msg_iovlen;
        let iovec = IoVec::get_all_iovecs(thread, iovec, iovec_len as _)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // Get destination address.
        let dst = match unsafe { vm.get_ptr::<SockAddr>(msg.msg_name as _)?.read() } {
            Ok(addr) => Some(addr.to_core_sockaddr()),
            Err(_) => None,
        };

        socket.write(&iovec, dst)
    } else {
        Err(Errno::ENOTSOCK)
    }
}
/// The recv(), recvfrom(), and recvmsg() calls are used to receive messages from a socket. They may be used to receive data
/// on both connectionless and connection-oriented sockets. This page first describes common features of all three system
/// calls, and then describes the differences between the calls.
pub fn sys_recvfrom(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let buf = syscall_registers[1];
    let len = syscall_registers[2];
    let flags = syscall_registers[3];
    let src_addr = syscall_registers[4];
    let addr_len = syscall_registers[5];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;
    if let FileObject::Socket(socket) = socket {
        let vm = thread.vm.lock();
        let buf = vm.get_mut_slice(buf, len as _)?;
        let (len, addr) = socket.read(buf)?;

        kinfo!("trying to get mutable pointer @ {src_addr:#x}");
        let ptr = vm.get_mut_ptr(src_addr).unwrap_or_default();
        if let (false, Some(SocketAddr::V4(addr))) = (ptr.is_null(), addr) {
            // We need to write to the `src_addr` (e.g., for UDP connections).
            unsafe {
                ptr.write(SockAddr {
                    // Mark as fixed.
                    sa_family: AF_INET as _,
                    sa_data_min: {
                        let mut buf = [0u8; 14];
                        buf[..2].copy_from_slice(&addr.port().to_be_bytes());
                        buf[2..6].copy_from_slice(&addr.ip().octets());
                        buf
                    },
                })?;
            }
        }

        Ok(len)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

pub fn sys_recvmsg(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let sockfd = syscall_registers[0];
    let msghdr = syscall_registers[1];
    let flags = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let vm = thread.vm.lock();
        let mgs_ptr = vm.get_mut_ptr::<MsgHdr>(msghdr)?;
        let msg = unsafe { mgs_ptr.read() }?;
        let iovec = msg.msg_iov;
        let iovec_len = msg.msg_iovlen;

        let mut buf = [0u8; 4096];
        let (len, addr) = socket.read(&mut buf)?;
        drop(vm);
        let len = IoVec::write_all_iovecs(thread, iovec, iovec_len as _, &buf[..len])?;

        Ok(len)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

/// getsockname() returns the current address to which the socket sockfd is bound, in the buffer pointed to by addr. The
/// addrlen argument should be initialized to indicate the amount of space (in bytes) pointed to by addr. On return it
/// contains the actual size of the socket address.
pub fn sys_getsockname(
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
        get_socket_name::<SockAddr>(thread, socket, sockaddr, socklen as _, true)
    } else {
        Err(Errno::ENOTSOCK)
    }
}

fn do_accept(
    thread: &Arc<Thread>,
    sockfd: u64,
    sockaddr: u64,
    addrlen: u64,
    flags: u64,
) -> KResult<usize> {
    // TODO: Flag is unused here. Add at least the non-blocking flag.
    let mut proc = thread.parent.lock();
    let socket = proc.get_fd(sockfd)?;

    if let FileObject::Socket(socket) = socket {
        let socket = socket
            .as_any_mut()
            .downcast_mut::<TcpStream>()
            .ok_or(Errno::EINVAL)?;
        let accepted = socket.accept()?;
        let peer = accepted.peer_addr().unwrap();

        if let IpAddr::V4(addr) = peer.ip() {
            // Write back to user space.
            let fd = proc.add_file(FileObject::Socket(accepted))?;
            let ptr = thread.vm.lock().get_mut_ptr(sockaddr)?;

            unsafe {
                ptr.write(SockAddr {
                    // Mark as fixed.
                    sa_family: AF_INET as _,
                    sa_data_min: {
                        let mut buf = [0u8; 14];
                        buf[..2].copy_from_slice(&peer.port().to_be_bytes());
                        buf[2..6].copy_from_slice(&addr.octets());
                        buf
                    },
                })?;
            }
            Ok(fd as _)
        } else {
            Err(Errno::EINVAL)
        }
    } else {
        Err(Errno::ENOTSOCK)
    }
}

dummy_impl!(sys_socketpair, Err(Errno::EACCES));
