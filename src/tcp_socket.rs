use std::net::TcpStream;

pub struct Tcp_socket{
    message_received: Vec<String>
}

impl Tcp_socket {
    pub fn new() -> Tcp_socket {
        println!("creating Tcp_socket");
        Tcp_socket{
            message_received: vec![]
        }
    }
}