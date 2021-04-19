use std::collections::{HashMap, HashSet};
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
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar,
    traits::Identity,
};
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
const NUM_PARTIES: usize = 7;
const TRS_VEC_SIZE: usize = 32;
const MSG_SIZE:usize = 2048;
const INTRODUCER_IP: &str = "192.168.31.154"; // 192.168.31.154 for local test, 172.22.94.218 for vm test, "10.193.227.18"
const PORT: &str = ":6000";
const CLIENT_PORT: &str = ":6001";
pub struct Node {
    id: String, // Node's ipaddress
    hb:i32, 
    local_clock:i32,
    membership_list: Vec<String>,
    parties_status: HashMap<String, (Trace_key, u8)>, // Ip_addr -> (public_key, flag) flag = 0(honest), flag = 1(byzantine)
    status: u8, // INACTIVE = 0, ACTIVE = 1
    tcp_util: Tcp_socket,
    ssk: x25519_dalek::EphemeralSecret, //Anonymous secret key
    spk: x25519_dalek::PublicKey, // Anonymous public key
    // secret_key: fujisaki_ringsig::PrivateKey,
    // public_key: fujisaki_ringsig::PublicKey,
    signature_byte_set: HashSet<Vec<u8>>, // TRS message vector set to get the union of all TRS
    signatures_set: HashMap<x25519_dalek::PublicKey, Signature>, // Map anonymous public key to TRS
    secret_key: PrivateKey, // Unanonyous secret key
    public_key: Trace_key, // Unanonymous public key
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    trs_tag: Tag,


}

impl Node {
    // Function to create a new party in the system
    pub fn new(rx: std::sync::mpsc::Receiver<Vec<u8>> ) -> Node{
        println!("creating new node");
        // Parameters to create keys
        let mut rng = OsRng;
        let mut rng1 = OsRng;
        let bits = 2048;
        
        // Create unanonymous public key and private key
        let (s_sk, s_pk) = gen_keypair(rng1);

        // Create Anonymous public key and private key
        let sk = EphemeralSecret::new(rng1);
        let pk = PublicKey::from(&sk);

        // Initialize "empty" tag 
        let issue = b"tag init".to_vec();
        let mut pubkeys: Vec<Trace_key> = vec![];

        let init_tag = Tag { 
            issue, 
            pubkeys,
        };
        
        Node {
            id: Node::create_id(),
            hb: 0,
            local_clock: 0,
            status: 0,
            tcp_util: Tcp_socket::new(),
            // Information of other nodes (TODO: Add to configuration file)
            membership_list: 
                vec!["172.22.94.218".to_string(), // vm1
                     "172.22.156.221".to_string(), // vm2
                     "172.22.94.219".to_string(), // vm3
                     "172.22.156.222".to_string(), // vm4
                     "172.22.94.220".to_string(), // vm5
                     "172.22.156.223".to_string(), // vm6
                     "172.22.94.221".to_string()], // vm7
            // Map to keep track of status of other members
            parties_status: HashMap::new(),
            signatures_set: HashMap::new(),
            signature_byte_set: HashSet::new(),
            ssk: sk, // Anonymous secret key
            spk: pk, // Anonymous public key
            secret_key: s_sk, // Unanonymous secret key
            public_key: s_pk, // Unanonymous public key
            rx: rx, // Communication channel for client
            trs_tag: init_tag,
        }

    }

    // Function to send all received TRS byte to other parties
    fn multicast_trs_set(&mut self) {
        for sig_byte in self.signature_byte_set.iter() {
            for party in self.membership_list.iter() {
                self.send_message(party.to_string(), sig_byte.clone());
            }
        }
    }


    // Function to process messages received from other parties
    fn process_message(&mut self, mut msg:Vec<u8>) {

       // Parse message
        let msg_type: u8 = msg[0];
        // let msg_len: u8 = msg[1];
        // let is_anonymous: u8 = msg[2];

        // Slice off the mesage content
        // let msg_end: usize = (msg_len + 3).into();
        // let msg_vec: Vec<u8> = (&msg[3..msg_end]).to_vec();
        // let mut src_addr:String = "".to_string();
        // if (is_anonymous == 0) {
        //     let addr_vec: Vec<u8> = (&msg[msg_end..]).to_vec();
        // Get the source address of unanonymous message
        //     src_addr = src_addr.replace("", &String::from_utf8(addr_vec).unwrap());
        //     println!("src_addr parsed: {:?}", src_addr);
        // }


        // Parse message based on message type
        if (msg_type == 0) { // public key of another party
            // Get msg starting index
            let msg_len: u8 = msg[1];
            let is_anonymous: u8 = msg[2];
            // Slice off the mesage content
            let msg_end: usize = (msg_len + 3).into();
            let msg_vec: Vec<u8> = (&msg[3..msg_end]).to_vec();
            let mut src_addr:String = "".to_string();


            if (is_anonymous == 0) {
                let addr_vec: Vec<u8> = (&msg[msg_end..]).to_vec();
                // Get the source address of unanonymous message
                src_addr = src_addr.replace("", &String::from_utf8(addr_vec).unwrap());
                println!("src_addr parsed: {:?}", src_addr);
            }
            // Recreate publick key using bytes received
            match Trace_key::from_bytes(&msg_vec) {
                Some(incoming_pk) => {
                    let received_pk: Trace_key = incoming_pk;

                    if (src_addr != "") {
                         // Add the party to the parties status list if it is a new party
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
        } else if (msg_type == 1) { // Other party's TRS information

            // Change message type
            msg[0] = 2;

            // Check if msg is already received 
            if (!self.signature_byte_set.contains(&msg)) {

                // Insert message to the received TRS set
                self.signature_byte_set.insert(msg.clone());
            }

            println!("inserted new signature vec to byte set");

            println!("decodeing signatures");
            // [msg_type, spki_len, aa1_len, cs_len, num_cs, zs_len, num_zs, is_anonymous, pki_vec, aa1_vec, cs_vec, zs_vec]
            // Decode trs msg vector

            // Convert length information from u8 to usize for slicing purpose
            let spk_len: usize = msg[1].into();
            let aa1_len: usize = msg[2].into();
            let cs_len: usize = msg[3].into();
            let num_cs: usize = msg[4].into();
            let zs_len: usize = msg[5].into();
            let num_zs: usize = msg[6].into();
            let is_anonymous: usize = msg[7].into();

            // Calculate the size of each cs/zs vector
            let num_vec: usize = cs_len / NUM_PARTIES; // change num parties

            // Set up the indices of each components of the received TRS for deserialization 
            let spk_index: usize = 8;
            let spk_index_end: usize = 8 + spk_len;
            let aa1_index: usize = spk_index_end;
            let aa1_index_end: usize = aa1_index + aa1_len;
            let cs_index: usize = aa1_index_end;
            let cs_index_end: usize = cs_index+ cs_len;
            let zs_index: usize = cs_index_end;
            let zs_index_end: usize = zs_index + zs_len;

            // For debugging
            println!("spk_len: {:?}, spk_index : {:?}, spk_index_end: {:?}", spk_len, spk_index, spk_index_end);
            println!("aa1_len: {:?}, aa1_index : {:?}, aa1_index_end: {:?}", aa1_len, aa1_index, aa1_index_end);
            println!("cs_len: {:?}, num_cs: {:?}, cs_index : {:?}, cs_index_end: {:?}",cs_len, num_cs, cs_index, cs_index_end);
            println!("zs_len: {:?}, num_zs: {:?}, zs_index : {:?}, zs_index_end: {:?}", zs_len, num_zs, zs_index, zs_index_end);

            // Create incoming party's anonymous public key vector
            let spk_vec: Vec<u8> = (&msg[spk_index..spk_index_end]).to_vec();

            // Create incoming party's TRS aa1 vector
            let aa1_vec: Vec<u8> = (&msg[aa1_index..aa1_index_end]).to_vec();

            // Create incoming party's TRS cs vector
            let cs_vec: Vec<u8> = (&msg[cs_index..cs_index_end]).to_vec(); // 32 * num_parties
            
            // Create incoming party's TRS zs vector
            let zs_vec: Vec<u8> = (&msg[zs_index..zs_index_end]).to_vec(); // 32 * num_parties

            // Convert anonymous public key vector into array
            let mut spk_arr: [u8; 32] = [0; 32];
            let mut i: usize = 0;
            for spk_byte in spk_vec.iter() {
                spk_arr[i] = spk_vec[i];
                i += 1;
            }

            // Recreate the anonymous public key
            let received_spk: PublicKey = PublicKey::from(spk_arr);

            // Convert TRS aa1 vector into array
            let mut j: usize = 0;
            let mut aa1_arr: [u8; 32] = [0; 32];
            for aa1_byte in aa1_vec.iter() {
                aa1_arr[j] = aa1_vec[j];
                j += 1;
            }

            
            // recreate aa1 for TRS
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&aa1_arr);
            let c = CompressedRistretto(arr);
            let re_aa1: RistrettoPoint = c.decompress().unwrap();
            
            
            // Parameters to recreate cs for TRS
            let mut cs_count: usize = 0;
            let mut re_cs_vec: Vec<Scalar> = Vec::new();
            
            // Parameters to recreate cs for TRS
            loop {
                if (cs_count == num_cs.into()) {
                    break;
                }
                let mut cur_arr: [u8; 32] = [0; 32];
                let mut cur_i: usize = 0;
                

                let cs_vec_temp:Vec<u8> = (&cs_vec[cs_count*32..cs_count*32 + 32]).to_vec();
            
                for cs_byte in cs_vec_temp.iter() {
                    cur_arr[cur_i] = cs_vec_temp[cur_i];
                    cur_i += 1;
                }

                let cur_cs: Scalar =  Scalar::from_canonical_bytes(cur_arr).unwrap();
                re_cs_vec.push(cur_cs);

                cs_count += 1;
            }

            // assert_eq!(re_cs_vec, cs_r);
            // println!("cs assert passed");

            // Parameters to recreate zs for TRS
            let mut zs_count: usize = 0;
            let mut re_zs_vec: Vec<Scalar> = Vec::new();
            
            // Parameters to recreate zs for TRS
            loop {
                if (zs_count == num_zs.into()) {
                    break;
                }
                let mut cur_arr: [u8; 32] = [0; 32];
                let mut cur_i: usize = 0;
                
                // let cs_vec: Vec<u8> = (&spki_trs_vec[cs_index..cs_index_end]).to_vec();

                let zs_vec_temp:Vec<u8> = (&zs_vec[zs_count*32..zs_count*32 + 32]).to_vec();
            
                for zs_byte in zs_vec_temp.iter() {
                    cur_arr[cur_i] = zs_vec_temp[cur_i];
                    cur_i += 1;
                }

                let cur_zs: Scalar =  Scalar::from_canonical_bytes(cur_arr).unwrap();
                re_zs_vec.push(cur_zs);

                zs_count += 1;
            }

            
            // Recreate TRS using aa1, cs and zs
            let re_trs: Signature = Signature{aa1: re_aa1, cs: re_cs_vec, zs: re_zs_vec};
            
            
            match self.signatures_set.get(&received_spk) {
                Some(_) => (),
                None=> {
                    self.signatures_set.insert(received_spk.clone(), re_trs);
                    println!("inserted new signature!");
                }
            }

        } else if (msg_type == 2) { // TODO: double check this part
            
            if (!self.signature_byte_set.contains(&msg)) {
                msg[0] = 2;
                // self.signature_byte_set.insert(msg.clone());
            

                println!("decodeing NEW signatures");
                let spk_len: usize = msg[1].into();
                let aa1_len: usize = msg[2].into();
                let cs_len: usize = msg[3].into();
                let num_cs: usize = msg[4].into();
                let zs_len: usize = msg[5].into();
                let num_zs: usize = msg[6].into();
                let is_anonymous: usize = msg[7].into();
                let num_vec: usize = cs_len / 7; // change num parties

                let spk_index: usize = 8;
                let spk_index_end: usize = 8 + spk_len;
                let aa1_index: usize = spk_index_end;
                let aa1_index_end: usize = aa1_index + aa1_len;
                let cs_index: usize = aa1_index_end;
                let cs_index_end: usize = cs_index+ cs_len;
                let zs_index: usize = cs_index_end;
                let zs_index_end: usize = zs_index + zs_len;

                // println!("spk_len: {:?}, spk_index : {:?}, spk_index_end: {:?}", spk_len, spk_index, spk_index_end);
                // println!("aa1_len: {:?}, aa1_index : {:?}, aa1_index_end: {:?}", aa1_len, aa1_index, aa1_index_end);
                // println!("cs_len: {:?}, num_cs: {:?}, cs_index : {:?}, cs_index_end: {:?}",cs_len, num_cs, cs_index, cs_index_end);
                // println!("zs_len: {:?}, num_zs: {:?}, zs_index : {:?}, zs_index_end: {:?}", zs_len, num_zs, zs_index, zs_index_end);

                let spk_vec: Vec<u8> = (&msg[spk_index..spk_index_end]).to_vec();
                // println!("spk_vec len: {:?} spk_vec: {:?}", spk_vec.len(), spk_vec);
                let aa1_vec: Vec<u8> = (&msg[aa1_index..aa1_index_end]).to_vec();
                // println!("aa1_vec len: {:?} aa1_vec: {:?}", aa1_vec.len(), aa1_vec);
                let cs_vec: Vec<u8> = (&msg[cs_index..cs_index_end]).to_vec(); // 32 * num_parties
                // println!("cs_vec len: {:?} cs_vec: {:?}", cs_vec.len(), cs_vec);
                let zs_vec: Vec<u8> = (&msg[zs_index..zs_index_end]).to_vec(); // 32 * num_parties

                let mut spk_arr: [u8; 32] = [0; 32];
                let mut i: usize = 0;
                for spk_byte in spk_vec.iter() {
                    spk_arr[i] = spk_vec[i];
                    i += 1;
                }

                let mut j: usize = 0;
                let mut aa1_arr: [u8; 32] = [0; 32];
                for aa1_byte in aa1_vec.iter() {
                    aa1_arr[j] = aa1_vec[j];
                    j += 1;
                }

                let received_spk: PublicKey = PublicKey::from(spk_arr);
                // assert_eq!(received_spk, self.spk);
                // println!("spk assert passed");

                let mut arr = [0u8; 32];
                arr.copy_from_slice(&aa1_arr);
                let c = CompressedRistretto(arr);
                let re_aa1: RistrettoPoint = c.decompress().unwrap();
                // assert_eq!(re_aa1, aa1_r);
                // println!("aa1 assert passed");

                let mut cs_count: usize = 0;
                let mut re_cs_vec: Vec<Scalar> = Vec::new();
                
                loop {
                    if (cs_count == num_cs.into()) {
                        break;
                    }
                    let mut cur_arr: [u8; 32] = [0; 32];
                    let mut cur_i: usize = 0;
                    
                    // let cs_vec: Vec<u8> = (&spki_trs_vec[cs_index..cs_index_end]).to_vec();

                    let cs_vec_temp:Vec<u8> = (&cs_vec[cs_count*32..cs_count*32 + 32]).to_vec();
                
                    for cs_byte in cs_vec_temp.iter() {
                        cur_arr[cur_i] = cs_vec_temp[cur_i];
                        cur_i += 1;
                    }

                    let cur_cs: Scalar =  Scalar::from_canonical_bytes(cur_arr).unwrap();
                    re_cs_vec.push(cur_cs);

                    cs_count += 1;
                }

                // assert_eq!(re_cs_vec, cs_r);
                // println!("cs assert passed");

                let mut zs_count: usize = 0;
                let mut re_zs_vec: Vec<Scalar> = Vec::new();
                
                loop {
                    if (zs_count == num_zs.into()) {
                        break;
                    }
                    let mut cur_arr: [u8; 32] = [0; 32];
                    let mut cur_i: usize = 0;
                    
                    // let cs_vec: Vec<u8> = (&spki_trs_vec[cs_index..cs_index_end]).to_vec();

                    let zs_vec_temp:Vec<u8> = (&zs_vec[zs_count*32..zs_count*32 + 32]).to_vec();
                
                    for zs_byte in zs_vec_temp.iter() {
                        cur_arr[cur_i] = zs_vec_temp[cur_i];
                        cur_i += 1;
                    }

                    let cur_zs: Scalar =  Scalar::from_canonical_bytes(cur_arr).unwrap();
                    re_zs_vec.push(cur_zs);

                    zs_count += 1;
                }

                // assert_eq!(re_zs_vec, zs_r);
                // println!("zs assert passed");

                let re_trs: Signature = Signature{aa1: re_aa1, cs: re_cs_vec, zs: re_zs_vec};
                // println!("re_spk process message: {:?}", received_spk);
                // println!("re_trs process message: {:?}", re_trs);
                
                // if (!self.signature_byte_set.contains())

                match self.signatures_set.get(&received_spk) {
                    Some(_) => {
                        println!("NEW decode, NOthing to the map!");
                    },
                    None=> {
                        self.signatures_set.insert(received_spk.clone(), re_trs);
                        println!("inserted new signature FROM SET!");
                    }
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

    // Function used to received the initial broadcast message from other parties
    fn process_received(&mut self) {
        // Loop to keep receiving message from the client communication channel
        loop {
           
            match self.rx.try_recv() {
                Ok(msg) => {
                    println!("received from channel");
                    // Process received mesasge
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    //Stop receiving message when all the parties' info is received
                    // TODO: Merge all process received functions together and use mutex lock
                    if (self.parties_status.len() == NUM_PARTIES) {
                        println!("party status len is 1");
                        break;
                    }
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

    // Function to process set of bytes (msg type should be 2)
    fn process_received_trs_byte(&mut self) { 
        
        let mut num_empty: usize = 0;
        // Loop to keep receiving message from the client communication channel
        loop {
            
            match self.rx.try_recv() {
                Ok(msg) => {
                    println!("process_received_trs_byte received from channel");
                    // Process received mesasge
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    //TODO 3/31 evening: set the threshold right
                    if (self.signatures_set.len() == NUM_PARTIES && num_empty >= self.membership_list.len() * self.membership_list.len() * self.signature_byte_set.len()) {
                        println!("process_received_trs_byte full");
                        break;
                    }
                    if (num_empty % 50 == 0) {
                        println!("num_empty: {:?}", num_empty);
                    }
                    num_empty += 1;
                    // println!("No more msgs");
                    // break;
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

    // Function to received TRS of all parties and create the union of all TRS
    fn process_received_trs(&mut self) { 
        
        // Loop to keep receiving message from the client communication channel
        loop {
            
            match self.rx.try_recv() {
                Ok(msg) => {
                    println!("process_received_trs received from channel");
                    // Process received mesasge
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    if (self.signature_byte_set.len() == NUM_PARTIES) {
                        println!("process_received_trs full");
                        break;
                    }
                    // println!("No more msgs");
                    // break;
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
    
    // Function to put party's traceable ring signature into bytes for boradcast
    pub fn create_trs_msg(&self, trs: Signature) -> Vec<u8> {
        // Vector format
        // [msg_type, spki_len, aa1_len, cs_len, num_cs, zs_len, num_zs, is_anonymous, pki_vec, aa1_vec, cs_vec, zs_vec]

        // TRS struct:
        // pub struct Signature {
        //     pub aa1: RistrettoPoint,
        //     pub cs: Vec<Scalar>,
        //     pub zs: Vec<Scalar>,
        // }

        // Initialize empty vector
        let mut ret: Vec<u8> = Vec::new();
        // Push message type
        ret.push(1);

        // Create party's anonymous public key vector
        let mut spk_vec = self.spk.as_bytes().to_vec();

        // Calculate party's anonymous public key vector length
        let spk_len: u8 = spk_vec.len() as u8;

        // Add party's anonymous public key length to vector
        ret.push(spk_len);

        // Create aa1 bytee vector
        let mut trs_aa1_vec: Vec<u8> = trs.aa1.compress().as_bytes().to_vec();

        // Calculate party's TRS aa1 length
        let aa1_len = trs_aa1_vec.len() as u8;

        // Add party's TRS aa1 length to vector
        ret.push(aa1_len);

        // Initialize TRS cs and zs length values
        let mut cs_len: u8 = 0;
        let mut zs_len: u8 = 0;

        // Initialize TRS cs and zs vectors
        let mut cs_vec: Vec<u8> = Vec::new();
        let mut zs_vec: Vec<u8> = Vec::new();

        // Counter used to keep track of how many vectors are contained in TRS cs and zs
        let mut num_cs: u8 = 0;
        let mut num_zs: u8 = 0;
        
        // Loop to iterate each Scalar vector of party TRS cs
        for cs_each in trs.cs.iter() {
            
            // Put current cs Scalar vector into bytes and accumulate the length
            cs_len += cs_each.to_bytes().to_vec().len() as u8;

            // Put current cs Scalar vector into bytes and append to cs vector for final message
            cs_vec.append(&mut cs_each.to_bytes().to_vec());

            // Increase number of cs scalar vector counter
            num_cs += 1;
        }

        // Loop to iterate each Scalar vector of party TRS zs
        for zs_each in trs.zs.iter() {

            // Put current zs Scalar vector into bytes and accumulate the length
            zs_len += zs_each.to_bytes().to_vec().len() as u8;

            // Put current zs Scalar vector into bytes and append to zs vector of final message
            zs_vec.append(&mut zs_each.as_bytes().to_vec());

            // Increase number of zs Scalar vector counter
            num_zs += 1;
        }

        // Push total length of cs final vector to the trs message vector
        ret.push(cs_len);

        // Push number of cs Scalar vector to the trs message vector
        ret.push(num_cs);

        // Push total length of zs final vector to the trs message vector
        ret.push(zs_len);

        // Push number of zs Scalar vector to the trs message vector
        ret.push(num_zs);

        // Vector is anonymous so push 1 for is_anonymous variable
        ret.push(1);

        // Append party's anonymous public key vector to the trs message vector
        ret.append(&mut spk_vec);

        // Append party's TRS aa1 vector to the trs message vector
        ret.append(&mut trs_aa1_vec);

        // Append party's TRS cs vector to the trs message vector
        ret.append(&mut cs_vec);

        // Append party's TRS zs vector to the trs message vector
        ret.append(&mut zs_vec);

        // Return the final trs message
        ret

    }

    // Function to verify the authenicity or TRS and remove the anonymous pk and trs if not authentic
    // pub fn verify_trs() {
    //     for (spk, sig) in self.signatures_set.iter() {

    //     }
    // }

    // 
    pub fn create_trs(&mut self) -> Signature{
        println!("creating trs");

        // Create issue for TRS' tag
        let issue = b"anonymous pke".to_vec();

        // push all parties' publick key to a vector for TRS' tag
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

        // Create tag for trs
        // let tag = Tag { 
        //     issue, 
        //     pubkeys,
        // };

        self.trs_tag = Tag { 
            issue, 
            pubkeys,
        };

        // Put party's anonymous public key into byte as message to sign
        let msg_to_sign = self.spk.as_bytes();

        // Create random value as TRS' parameter
        let mut rng = rand::thread_rng();

        // Sign the message
        sign(&mut rng, &*msg_to_sign, &self.trs_tag, &self.secret_key)
    }

    pub fn multicast_trs(&mut self, trs_vec: Vec<u8>) {
        // Iterate through membership list and send trs message to all parties
        for party in self.membership_list.iter() {
            self.send_message(party.to_string(), trs_vec.clone());
        }
        // Hard coded for local test
        // self.send_message(INTRODUCER_IP.to_string(), trs_vec.clone());
    }

    pub fn start_honest(mut self) {
        // Hardcode membership list for now
        
            println!("starting honest node");
             // Broadcast self unanonymoud public key
            &self.client_start();
            
            
            // Create client thread
            let client_thread = thread::spawn(move || loop {
                // Sleep for 2 seconds
                thread::sleep(time::Duration::from_millis(2000));

                // Receive messages
                &self.process_received();
                println!("received done, len: {:?}", self.parties_status.len());

                // Receive initial message again if not all parties' information are received
                if (self.parties_status.len() < NUM_PARTIES) {
                    continue;
                }

                // Print for debug purpose
                for (key, val) in self.parties_status.iter() {
                    println!("src: {:?} flag: {:?}", key, val.1);
                }

                // Create traceable Signature ring
                let trs: Signature = self.create_trs();

                let aa1_r: RistrettoPoint = trs.aa1.clone();
                let cs_r: Vec<Scalar> = trs.cs.clone();
                let zs_r: Vec<Scalar> = trs.zs.clone();

                // Create Trs message to send to other parties
                let mut spki_trs_vec: Vec<u8> = self.create_trs_msg(trs);

                // Send trs message vector to all other parties
                &self.multicast_trs(spki_trs_vec.clone());
                
                // Receive and process TRS of other parties
                &self.process_received_trs(); // 

                // Send the set of received TRS to other parties
                &self.multicast_trs_set();

                // Process the received trs byte
                &self.process_received_trs_byte(); 


                // Verify the autheniticity of received TRS
                // &self.verify_trs();

                println!("YAY");

                
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

        // println!("target: {}, msg: {:?}", connect_param.clone(), msg);
        // let mut target = net::UdpSocket::bind(connect_param).expect("client Stream failed to connect");
        // target.set_nonblocking(true).expect("client failed to initialize non-blocking");
        // let mut buff = vec![0; MSG_SIZE];

        // let mut msg_string: String = String::new();
        // msg_string.push_str("hello world");


        // let buff = msg.clone().into_bytes();
        // println!("msg_vec: {:?}", msg);
        match socket.send_to(&msg, connect_param){
            Ok(number_of_bytes) => println!("bytes sent: {:?}", number_of_bytes),
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

    // Function to create the ID of a party
    fn create_id() -> String {

        // getting host ip
        let host_name = dns_lookup::get_hostname().unwrap();
        println!("hostname: {:?}", host_name);
        
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        println!("ip_addr: {:?}", ip_addr);


        // Return ipaddress in string form
        ip_addr[0].to_string()
    }

    
}
// Function to create server thread
pub fn server_thread_create(tx: std::sync::mpsc::Sender<Vec<u8>> ) {
    // Getting host Ip address
    let host_name = dns_lookup::get_hostname().unwrap();
    let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
    let mut bind_param = ip_addr[0].to_string();
    bind_param.push_str(":6000");
    println!("full address: {}", bind_param);

    // Hard coded for local test
    let local_param = "192.168.31.154:6000".to_string();

    // Create udp socket
    let server = net::UdpSocket::bind(bind_param).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    // Sleep for 1 second
    let sleep_period = time::Duration::from_millis(1000);
    loop {
        // Create buffer to store received message
        let mut buf: [u8; MSG_SIZE] = [0; MSG_SIZE];
        let number_of_bytes: usize = 0;
        let mut result: Vec<u8> = Vec::new();

        // Receive incoming messages
        match server.recv_from(&mut buf) {
            Ok((number_of_bytes, src_addr)) => {
                // Create result buffer
                result = Vec::from(&buf[0..number_of_bytes]);
                // Parse source address
                let mut addr_vec: Vec<u8> = vec![];
                addr_vec = src_addr.to_string().into_bytes();
                // Append address to result in byte form
                result.append(&mut addr_vec);

                // Send received message to client thread for process through the channel
                // tx.send(result).expect("failed to send msg to rx");
                match tx.send(result) {
                    Ok(r) => {
                        println!("Server thread send successfully!");
                    }
                    Err(e) => {
                        println!("Server thread send error {:?}, client stop receiving!", e);
                        continue;
                    }
                }
                
                println!("pushed received message to the channel");
            }, 
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            Err(fail) => println!("failed listening {:?}", fail)
        }
        // Sleep before next round
        // println!("thread finishing");
        std::thread::sleep(sleep_period);
    }
    println!("thread finishing");
}
