use std::collections::HashMap;
use std::net;
use std::env;
use std::str;
use std::ptr;
use std::net::TcpStream;
use dns_lookup::{get_hostname, lookup_host};
use std::net::IpAddr;
use crate::tcp_socket::Tcp_socket;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, TryRecvError};
use std::{thread, time};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
// use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};
use rand::rngs::OsRng;
use rand_core::{RngCore, Error, impls};
use x25519_dalek::{EphemeralSecret, PublicKey};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
// use fujisaki_ringsig::{gen_keypair, sign, verify, Tag};
use std::fmt;
use sha2::Sha512;

// use trace;

// Traceable ring github
// mod key;
// mod prelude;
// mod sig;

use crate::{
    key::{gen_keypair, PrivateKey, PublicKey as Trace_key},
    prelude::*,
    sig::{compute_sigma, Signature, Tag, sign},
};

// use crate::{
//     traceable_ring_nemocracy::key::{gen_keypair, PrivateKey, PublicKey},
//     traceable_ring_nemocracy::prelude::*,
//     traceable_ring_nemocracy::sig::Tag,
// };
// use crate::{
//     key::PublicKey,
//     prelude::*,
//     traceable_ring_nemocracy::sig::{compute_sigma, Signature, Tag},
// };

// Traceable ring github


//To install rust and cargo on vms:
//1. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//2. source $HOME/.cargo/env
const MSG_SIZE:usize = 256;
const INTRODUCER_IP: &str = "192.168.31.154"; // 192.168.31.154 for local test, 172.22.94.218 for vm test, "10.193.227.18"
const PORT: &str = ":6000";
const CLIENT_PORT: &str = ":6001";
pub struct Node {
    id: String, // also used a public key
    hb:i32, 
    local_clock:i32,
    membership_list: Vec<String>,
    parties_status: HashMap<String, (Trace_key, u8)>, // Ip_addr -> (public_key, flag) flag = 0(honest), flag = 1(byzantine)
    status: u8, // INACTIVE = 0, ACTIVE = 1
    tcp_util: Tcp_socket,
    ssk: x25519_dalek::EphemeralSecret,
    spk: x25519_dalek::PublicKey,
    // secret_key: fujisaki_ringsig::PrivateKey,
    // public_key: fujisaki_ringsig::PublicKey,

    secret_key: PrivateKey,
    public_key: Trace_key,

    // ssk: RSAPrivateKey,
    // spk: RSAPublicKey,
    // trs: fujisaki_ringsig::Signature,
    // channel: (std::sync::mpsc::Sender<String>, std::sync::mpsc::Receiver<String>)
    // server_channel: std::sync::mpsc::Sender<String>, 
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    // client_sender: std::sync::mpsc::Sender<String>,
    // client_receiver: std::sync::mpsc::Receiver<String>


}

impl Node {
    // pub fn new(rx: std::sync::mpsc::Receiver<String>) -> Node{
    pub fn new(rx: std::sync::mpsc::Receiver<Vec<u8>> ) -> Node{
        println!("creating new node");
        let mut rng = OsRng;
        let mut rng1 = OsRng;
        println!("rng: {:?} \n rng1{:?}", rng, rng1);
        let bits = 2048;
        // let rsa_secret= RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        // let rsa_public = RSAPublicKey::from(&rsa_secret);
        // let (sk, pk) = fujisaki_ringsig::gen_keypair(rng);
        let (s_sk, s_pk) = gen_keypair(rng1);
        println!("original pk to compare: {:?}", s_pk);
        let sk = EphemeralSecret::new(rng1);
        let pk = PublicKey::from(&sk);
        println!(" public key equal: {:?}",  pk.as_bytes());
        // println!("shadow secret key: {:?}, shadow public key: {:?}", s_sk, s_pk);
        let my_channel = std::sync::mpsc::channel::<Vec<u8>>();
        println!("sender: {:?}, receiver: {:?}", my_channel.0, my_channel.1);
        let trs_msg = "intializing trs";
        Node {
            id: Node::create_id(),
            hb: 0,
            local_clock: 0,
            status: 0,
            tcp_util: Tcp_socket::new(),
            membership_list: 
                vec!["172.22.94.218".to_string(), // vm1
                     "172.22.156.221".to_string(), // vm2
                     "172.22.94.219".to_string(), // vm3
                     "172.22.156.222".to_string(), // vm4
                     "172.22.94.220".to_string(), // vm5
                     "172.22.156.223".to_string(), // vm6
                     "172.22.94.221".to_string()], // vm7
            parties_status: HashMap::new(),
            ssk: sk,
            spk: pk,
            secret_key: s_sk,
            public_key: s_pk,
            // trs: fujisaki_ringsig::Signature {
            //     aa1: RistrettoPoint::hash_from_bytes::<Sha512>(trs_msg.as_bytes()),
            //     cs: vec![],
            //     zs: vec![],
            // },
            // server_channel: my_channel.0, 
            rx: rx, 
            // client_sender: my_channel.0,
            // client_receiver: my_channel.1
        }
        // println!("sender: {:?}, receiver: {:?}", channel.0, channel.1);

    }

    // fn calculate_hash<T: Hash>(t: &T) -> u64 {
    //     let mut s = DefaultHasher::new();
    //     t.hash(&mut s);
    //     s.finish();
    // }
    
    fn process_message(&mut self, msg:Vec<u8>) {

        println!("message vec received: {:?}", msg);
        let msg_type: u8 = msg[0];
        // let msg_len: u8 = msg[1];
        // let is_anonymous: u8 = msg[2];
        // let msg_end: usize = (msg_len + 3).into();
        // let msg_vec: Vec<u8> = (&msg[3..msg_end]).to_vec();
        // let mut src_addr:String = "".to_string();
        // if (is_anonymous == 0) {
        //     let addr_vec: Vec<u8> = (&msg[msg_end..]).to_vec();
        //     src_addr = src_addr.replace("", &String::from_utf8(addr_vec).unwrap());
        //     println!("src_addr parsed: {:?}", src_addr);
        // }

        // println!("msg_vec received: {:?}", msg_vec);

        if (msg_type == 0) {
            let msg_len: u8 = msg[1];
            let is_anonymous: u8 = msg[2];
            let msg_end: usize = (msg_len + 3).into();
            let msg_vec: Vec<u8> = (&msg[3..msg_end]).to_vec();
            let mut src_addr:String = "".to_string();
            if (is_anonymous == 0) {
                let addr_vec: Vec<u8> = (&msg[msg_end..]).to_vec();
                src_addr = src_addr.replace("", &String::from_utf8(addr_vec).unwrap());
                println!("src_addr parsed: {:?}", src_addr);
            }
            match Trace_key::from_bytes(&msg_vec) {
                Some(incoming_pk) => {
                    let received_pk: Trace_key = incoming_pk;
                    // println!("incoming key decoded successfully: {:?}", received_pk);
                    // assert_eq!(received_pk, self.public_key);
                    // println!("assert passed again");
                    if (src_addr != "") {
                        match self.parties_status.get(&src_addr) {
                            Some(_) => (), 
                            None => {
                                let new_party: (Trace_key, u8) = (received_pk, 0);
                                self.parties_status.insert(src_addr.clone(), new_party);
                                println!("inserted new party: {:?}", src_addr.clone());
                            }
                        }
                    } else {
                        println!("error src_addr");
                    }
                    
    
                }, 
                None => {
                    println!("incoming key error");
                } 
            }
        }

       
        // let received_pk: fujisaki_ringsig::PublicKey = fujisaki_ringsig::PublicKey::from_bytes(&msg).unwrap();

        // let msg_ind = msg.as_str();
        // if (msg_ind.chars().nth(1).unwrap() == '0') {
        //     println!("message type is 0, msg:{:?}", msg);
        //     let mut split_ret = msg.split("::");
        //     split_ret.next();
        //     let msg_content = split_ret.next().unwrap().clone();
        //     println!("msg_content: {}", msg_content);
        //     let whole_msg_byte = msg.clone().into_bytes();
        //     println!("whole_msg_byte: {:?}", whole_msg_byte);
        //     let mut split_content = msg_content.split("==");
        //     let incoming_pk = split_content.next().unwrap().clone();
        //     let src_addr = split_content.next().unwrap().clone();
            
        //     println!("incoming pk: {}, src_addr: {}", incoming_pk, src_addr);
        //     let pk_byte = String::from(incoming_pk);
        //     // let pk_byte_as = String::from(incoming_pk);
        //     let mut pk_vec: Vec<u8> = vec![0; 32];
        //     // let mut pk_vec_as: Vec<u8> = vec![0; 32];
        //     pk_vec = pk_byte.into_bytes();
        //     // let pk_vec_as = pk_byte_as.as_bytes().to_vec();
        //     println!("incoming pk into bytes: {:?}", pk_vec);
        //     // println!("incoming pk as bytes: {:?}", pk_vec_as);
        //     let pk_str_sec = String::from_utf8_lossy(&pk_vec);
        //     println!("pk_str_sec:  {:?}", pk_str_sec);

        //     let pk_vec_sec = pk_str_sec.unwrap().clone().into_bytes();
        //     println!("pk_vec_sec: {:?}", pk_vec_sec);



        //     match self.parties_status.get(src_addr) {
        //         Some(_) => (),
        //         None => {
        //             println!(" adding incoming pk: {}, src_addr: {}", incoming_pk, src_addr);
        //             // let received_key: 
        //             let new_party: (String, u8) = (incoming_pk.to_string(), 0);
        //             self.parties_status.insert(src_addr.to_string(), new_party);
        //             println!("added new pk");
        //         }
        //     }
            
        // }
    }

    fn process_received(&mut self) {
        println!("rx address in process: {:p}", &self.rx);
        // let mut msg_received: Vec<String> = vec![];
        loop {
            // println!("loop");
            match self.rx.try_recv() {
                Ok(msg) => {
                    println!("received from channel");
                    // TODO process message here
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    if (self.parties_status.len() == 7) {
                        println!("party status len is 1");
                        break;
                    }
                    // println!("No more msgs");
                
                },
                Err(TryRecvError::Disconnected) => {
                    println!("disconnected");
                    break;
                },
                Err(e) => {
                    println!("other error : {:?}", e);
                    break;
                }
            }
        }

        
    }

    // fn client_process(&self) {
    //     let mut msg_received: Vec<String> = vec![];
    //     loop {
    //         match self.client_receiver.try_recv() {
    //             Ok(msg) => {
    //                 println!("received from channel");
    //                 msg_received.push(msg);
    //             },
    //             Err(TryRecvError::Empty) => {
    //                 println!("No more msgs");
    //                 // break;
    //             },
    //             Err(TryRecvError::Disconnected) => {
    //                 println!("disconnected");
    //                 break;
    //             }
    //         }
    //     }

    //     for m in msg_received.iter() {
    //         println!("client received message {:?}", m);
    //     }
    // }

    pub fn create_trs(&mut self) -> Signature{
        println!("creating trs");
        let issue = b"anonymous pke".to_vec();
        let mut pubkeys: Vec<Trace_key> = vec![];

        for (ip, pk) in self.parties_status.iter() {
            println!("adding pk: {:?}", ip);
            let pk_vec: Vec<u8> = pk.0.as_bytes().to_vec();
            match Trace_key::from_bytes(&pk_vec) {
                Some(pk_trs) => {

                    pubkeys.push(pk_trs);
                    println!("add pk to tag for trs");
                }
                None => {
                    println!("trs create pk error");
                }
            }
        }
        let tag = Tag { 
            issue, 
            pubkeys,
        };

        let msg_to_sign = self.spk.as_bytes();
        let mut rng = rand::thread_rng();
        sign(&mut rng, &*msg_to_sign, &tag, &self.secret_key)
    }

    pub fn start_honest(mut self) {
        // Hardcode membership list for now
        
            println!("starting honest node");
            &self.client_start();
            println!("starting thread");
            let client_thread = thread::spawn(move || loop {
                // if (self.status == 0) {

                //     &self.client_start();
                //     self.status = 1;
                // }
                // println!("client thread");
                thread::sleep(time::Duration::from_millis(2000));
                &self.process_received();
                println!("received done, len: {:?}", self.parties_status.len());
                // if (self.parties_status.len() != self.membership_list.len()) {
                if (self.parties_status.len() < 7) {
                    continue;
                }
                for (key, val) in self.parties_status.iter() {
                    println!("src: {:?} flag: {:?}", key, val.1);
                }
                let trs: Signature = self.create_trs();
                println!("created trs: {:?}", trs);
                // break;
                println!("trs.aa1: {:?}", trs.aa1);
                println!("trs.cs: {:?}", trs.cs);
                println!("trs.zs: {:?}", trs.zs);
                let mut trs_vec: Vec<u8> = Vec::new();
                let mut trs_aa1_vec: Vec<u8> = trs.aa1.compress().as_bytes().to_vec();
                trs_vec.append(&mut trs_aa1_vec);
                for cs_each in trs.cs.iter() {
                    trs_vec.append(&mut cs_each.to_bytes().to_vec());
                }
                for zs_each in trs.zs.iter() {
                    trs_vec.append(&mut zs_each.to_bytes().to_vec());
                }

                println!("trs_vec: {:?}", trs_vec);
                // [msg_type, spki_len, aa1_len, cs_len, zs_len, is_anonymous]


                // let trs_cs_vec: Vec<u8> = trs.cs.to_bytes();
                // let trs_zs_vec: Vec<u8> = trs.zs.to_bytes();
                // println!("trs_aa1_vec: {:?}", trs_aa1_vec);
                // println!("trs_cs_vec: {:?}", trs_cs_vec);
                // println!("trs_zs_vec: {:?}", trs_zs_vec);
                break;
                // trs_vec = trs.as_bytes();
                // println!("trs_vec: {:?}". trs_vec);
                // TODO: 3/29 test trs on vms
            });

            // &self.process_received();
            let client_res = client_thread.join();
            // let server_thread = thread::spawn(move || {
            //     server_thread_create(&self);
            //     // &test_node.server_thread_create();
            // });
            // 1. join the system by sending public_key to the introducer

            // 3. create traceable ring signature (Trs = <ski, L, m>, L = tag(issue, {pki}N), m = spki
            //     {pki}N is the set of all public keys
            // let mut all_public_keys = vec!["node0".to_string(), "node1".to_string(), "node2".to_string(), "node3".to_string(), "node4".to_string(), "node5".to_string(), "node6".to_string(), "node7".to_string(), "node8".to_string(), "node9".to_string()];
            // let mut msg: String = String::new();
            // msg.push_str("[0]::");
            // let mut public_key_vec = self.public_key.as_bytes();
            // println!("public_key_vec: {:?}", public_key_vec);

            // let public_str = String::from_utf8_lossy(public_key_vec);
            // msg.push_str(&public_str);
            // // msg.push_str(self.public_key.as_bytes().to_owned());
            // println!("sending to {}, msg: {}", INTRODUCER_IP.to_string(), msg);
            // self.send_message(INTRODUCER_IP.to_string(), msg);

            // TODO 03/24 continue sending other messages


            // 4. send (spki, trsi) to all (sign using ski)
            //     each party also receive from others, by the end it gets a set 
            //     sspksi = {(spki, trsi)} (i = 0-n) (Signed Shadowed public key set at i)
            // 5. Send sspksi to all others (dolev strong)
            // 6. take the union of all received sets (sspksu)(Signed Shadowed public key set union)
            // 7. run va = ver(spka, trsa) (using pka to verify the authenticity) for all pair and remove parties (spka, trsa) whose va != 1
            // 8. t_ab = trace(L, (spka, trsa), (spkb, trsb)) for all pairs in the union and remove sspka and sspkb for those t_ab != "indep" and spka != spkb.
            //     After this step we get a master signed shadow public key set msspks
            // 9. output anonymout PKI{spki | (spki, trsi) is party of msspks} 

            
            // let server_res = server_thread.join();

            // Get a `Trace` object representing the relationship between the two provided signatures and
            // messages.
            //
            // Example:
            //
            // ```
            // # fn main() {
            // use fujisaki_ringsig::{gen_keypair, sign, trace, Tag, Trace};
            // # let mut rng = rand::thread_rng();
            //
            // let msg1 = b"cooking MCs like a pound of bacon";
            // let msg2 = msg1;
            // let issue = b"testcase 54321".to_vec();
            //
            // let (my_privkey, pubkey1) = gen_keypair(&mut rng);
            // let (_, pubkey2) = gen_keypair(&mut rng);
            // let (_, pubkey3) = gen_keypair(&mut rng);
            //
            // let pubkeys = vec![pubkey1, pubkey2, pubkey3];
            // let tag = Tag {
            //     issue,
            //     pubkeys,
            // };
            //
            // let sig1 = sign(&mut rng, &*msg1, &tag, &my_privkey);
            // let sig2 = sign(&mut rng, &*msg2, &tag, &my_privkey);
            //
            // assert_eq!(trace(&*msg1, &sig1, &*msg2, &sig2, &tag), Trace::Linked);



    }

    pub fn create_msg(&self, mut msg_vec: Vec<u8>, mut msg_type: u8, mut is_anonymous: u8) -> Vec<u8>{
        let msg_len: u8 = msg_vec.len() as u8;
        let mut result_vec: Vec<u8> = vec![msg_type, msg_len, is_anonymous];
        result_vec.append(&mut msg_vec);
        result_vec

    }

    pub fn client_start(&self){
        let mut msg: String = String::new();
        msg.push_str("[0]::");
        // println!("pk before send: {:?}", self.public_key);
        let mut public_key_vec: Vec<u8> = self.public_key.as_bytes();
        let mut my_vec: Vec<u8> = vec![1];
        // my_vec.append(& mut public_key_vec.clone());
        // println!("my_vec: {:?}", my_vec);
        println!("public_key_vec: {:?}", public_key_vec);
        
        let received_pk: Trace_key;
        let msg_to_send: Vec<u8> = self.create_msg(public_key_vec.clone(), 0, 0);
        let ref_vec: &[u8] = &msg_to_send[3..];
        println!("msg_to_send: {:?}", msg_to_send);
        match Trace_key::from_bytes(ref_vec) {
            Some(incoming_pk) => {
                received_pk = incoming_pk;
                // println!("incoming key decoded before send: {:?}", received_pk);
                assert_eq!(received_pk, self.public_key);
                println!("assert passed");
            }, 
            None => {
                println!("incoming key error");
            } 
        }
        
        // create_msg(public_key_vec.clone(), 0);
        // let public_str = String::from_utf8_lossy(&public_key_vec);
        // let public_str = String::from_utf8_lossy(&public_key_vec);
        // println!("public_str:{:?}", public_str);
        // match &public_str.unwrap() {
        //     Ok(pub_str) => {
        //         msg.push_str(pub_str);
        //     },
        //     Err(e) => {
        //         println!("err utf8:{:?}", e);
        //     }
        
        // msg.push_str(&public_str);
        // msg.push_str(self.public_key.as_bytes().to_owned());
        // println!("sending to {}, msg: {}", INTRODUCER_IP.to_string(), msg);
        for party in self.membership_list.iter() {
            self.send_message(party.to_string(), msg_to_send.clone());
        }
        // self.send_message(INTRODUCER_IP.to_string(), msg_to_send);
    }

    // pub fn send_message_bytes(&self, target: String, msg: Vec<u8>) {

    // }


    pub fn send_message(&self, target: String, msg: Vec<u8>) {
        thread::sleep(time::Duration::from_millis(2000));
        // println!("client send message");
        let host_name = dns_lookup::get_hostname().unwrap();
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        let mut bind_param = ip_addr[0].to_string();
        bind_param.push_str(CLIENT_PORT);

        let local_param = "192.168.31.154:6001".to_string();

        let socket = net::UdpSocket::bind(bind_param).expect("client failed to bind");

        let mut connect_param = target.clone();
        connect_param.push_str(PORT);
        // let socket = net::UdpSocket::bind(connect_param.clone()).expect("client failed to bind");

        println!("target: {}, msg: {:?}", connect_param.clone(), msg);
        // let mut target = net::UdpSocket::bind(connect_param).expect("client Stream failed to connect");
        // target.set_nonblocking(true).expect("client failed to initialize non-blocking");
        // let mut buff = vec![0; MSG_SIZE];

        // let mut msg_string: String = String::new();
        // msg_string.push_str("hello world");


        // let buff = msg.clone().into_bytes();
        println!("msg_vec: {:?}", msg);
        match socket.send_to(&msg, connect_param){
            Ok(number_of_bytes) => println!("{:?}", number_of_bytes),
            Err(fail) => println!("failed sending {:?}", fail),
        }
        // target.write_all(&buff).expect("client writing to socket failed");

        println!("msg sent!");


        // let(tx_client, rx_client) = mpsc::channel::<String>();

        // thread::spawn(move || loop{
        //     let mut buff = vec![0; MSG_SIZE];
        //     // match target.read_exact(&mut buff) {
        //     //     Ok(_) => {
        //     //         // println!("read exact buf: {:?}", buff);
        //     //         let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
        //     //         println!("message recv {:?}", msg);
        //     //     }, 
        //     //     Err (ref err) if err.kind() == ErrorKind::WouldBlock => (),
        //     //     Err(_) => {
        //     //         println!("connection with server was severed");
        //     //         break;
        //     //     }
        //     // }
        //     // TODO process received message
        //     match rx_client.try_recv() {
        //         Ok(msg_string)=> {
        //             let mut buff = msg_string.clone().into_bytes();
        //             buff.resize(MSG_SIZE, 0);
        //             target.write_all(&buff).expect("client writing to socket failed");
        //             println!("message to process  {:?}", msg_string);
        //         }, 
        //         Err(TryRecvError::Empty) => (),
        //         Err(TryRecvError::Disconnected) => break
        //     }
        //     thread::sleep(time::Duration::from_millis(1000));

        // });

        // println!("Sending message...:{}", msg);
        // // tx.send(msg);
        // // tx.send("1111111111".to_string());
        // loop {
        //     // tx.send("1111111111".to_string());
        //     tx_client.send(msg.clone());
        //     thread::sleep(time::Duration::from_millis(2000));
        // }
    }

    pub fn honest() {
        
    }


    fn create_id() -> String {
        let host_name = dns_lookup::get_hostname().unwrap();
        println!("hostname: {:?}", host_name);
        
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        println!("ip_addr: {:?}", ip_addr);

        ip_addr[0].to_string()
    }

    
}

pub fn server_thread_create(tx: std::sync::mpsc::Sender<Vec<u8>> ) {
    println!("tx address in thread: {:p}", &tx);
    // tx.send("hello from tx".to_string());
    println!("server_thread_create");
    // let tx = *tx_addr;
    let host_name = dns_lookup::get_hostname().unwrap();
    let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
    let mut bind_param = ip_addr[0].to_string();
    bind_param.push_str(":6000");
    println!("full address: {}", bind_param);

    let local_param = "192.168.31.154:6000".to_string();

    let server = net::UdpSocket::bind(bind_param).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    // let mut clients = vec![]; // vector os connected clients

    // let (tx, rx) = mpsc::channel::<String>();
    let sleep_period = time::Duration::from_millis(1000);
    loop {
        // println!("server receive loop");

        // let mut buff = vec![0, MSG_SIZE];

        let mut buf: [u8; MSG_SIZE] = [0; MSG_SIZE];
        let number_of_bytes: usize = 0;
        let mut result: Vec<u8> = Vec::new();

        match server.recv_from(&mut buf) {
            Ok((number_of_bytes, src_addr)) => {
                // let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                result = Vec::from(&buf[0..number_of_bytes]);
                let mut addr_vec: Vec<u8> = vec![];
                addr_vec = src_addr.to_string().into_bytes();
                result.append(&mut addr_vec);
                // let msg = String::from_utf8(result).expect("Invalid utf8 message");
        
                // println!("server receive, src_addr: {:?}, msg: {:?}", src_addr, msg);
                // //TODO 03/25 figure out why the channel doesn't send everytime
                // let mut msg_to_process = String::from(msg);
                // msg_to_process.push_str("==");
                // msg_to_process.push_str(&src_addr.to_string());
                // tx.send(msg_to_process.to_string()).expect("failed to send msg to rx");


                tx.send(result).expect("failed to send msg to rx");
                println!("pushed received message to the channel");
            }, 
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            Err(fail) => println!("failed listening {:?}", fail)
            // Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            // Err(e) => {
            //     println!("closing connection with :{}, Err:{:?}", msg, e);
            //     break;
            // }
        }
    


        // for stream in server.incoming() {

        
        //     if let Ok((mut socket, addr)) = server.accept() {
        //         println!("Client {} connected", addr);

        //         // let tx = tx.clone();

        //         clients.push(socket.try_clone().expect("failed to clone client"));

        //         // thread::spawn(move || loop {
        //         loop{
        //             let mut buff = vec![0; MSG_SIZE]; // MSG_SIZE 0s
        //             // let mut buff = vec![];
        //             match socket.read_exact(&mut buff) {
        //                 Ok(_) => {
        //                     let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
        //                     let msg = String::from_utf8(msg).expect("Invalid utf8 message");

        //                     println!("server receive {}, {:?}", addr, msg);
        //                     //TODO 03/25 figure out why the channel doesn't send everytime
        //                     tx.send(addr.to_string()).expect("failed to send msg to rx");
        //                     println!("pushed received message to the channel");
        //                 },

        //                 Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
        //                 Err(e) => {
        //                     println!("closing connection with :{}, Err:{:?}", addr, e);
        //                     break;
        //                 }
        //             }

        //             std::thread::sleep(sleep_period);
        //         }
        //         // });
        //     }
        // }
        // if let Ok(msg) = rx.try_recv() {
        //     clients = clients.into_iter().filter_map(|mut client| {
        //         let mut buff = msg.clone().into_bytes();
        //         buff.resize(MSG_SIZE, 0);

        //         client.write_all(&buff).map(|_| client).ok()
        //     }).collect::<Vec<_>>();
        // }
        std::thread::sleep(sleep_period);
    }
}
