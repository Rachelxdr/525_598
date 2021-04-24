use std::thread;
use std::io::{self, ErrorKind, Read, Write};
use crate::node::Node;
use crate::tcp_socket::Tcp_socket;
mod node;
mod tcp_socket;
use std::sync::mpsc::{self, TryRecvError};
pub use rand::rngs::ThreadRng;
use rand::rngs::OsRng;
mod key;
mod prelude;
mod sig;
mod trace;



fn main() {
    // Create Communication channel between threads  
    let(tx, rx) = mpsc::channel();
    
    // Create new party
    let mut test_node = Node::new(rx);

    // Create Server thread to receive message
    let server_thread = thread::spawn(move || {
        node::server_thread_create(tx);
    });


    // Getting node's role from input
    println!("Please enter a role: H (honest) / B (Byzantine)");
    let mut buff = String::new();
    loop {
        io::stdin().read_line(&mut buff).expect("reading from stdin failed");
        println!("buff: [{}]", buff);
        if buff == "H\n".to_string(){
            //Starting a honest party
            test_node.start_honest();
            break;
        } else if buff == "B\n".to_string(){
            // Starting Byzantine party. This party will send different TRS to different parties
            test_node.start_diff();
            break;
        } else {
            buff.clear();
            println!("H (honest) / B (Byzantine)");
            continue;
        }
    }
   
    let server_res = server_thread.join();

}

