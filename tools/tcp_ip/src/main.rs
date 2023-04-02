use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage: ./tcp_ip [addr] [port]");
        return;
    }

    let addr = format!("{}:{}", args[1], args[2]);
    let mut socket = TcpStream::connect(&addr).unwrap();

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
