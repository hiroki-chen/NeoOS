use std::{
    io::{Read, Write},
    net::TcpStream,
};

fn main() {
    let mut socket = TcpStream::connect("172.16.253.233:80").unwrap();

    loop {
        let mut input = String::new();
        println!("[+] Input string:");
        std::io::stdin().read_line(&mut input).unwrap();
        println!("");
        socket.write(input.as_bytes()).unwrap();

        let mut buf = vec![0u8; 4096];
        let len = socket.read(&mut buf).unwrap();
        println!("[+] Read {:02x?}", &buf[..len]);
    }
}
