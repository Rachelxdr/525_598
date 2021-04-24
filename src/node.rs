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
pub use rand::rngs::ThreadRng;
use rand::rngs::OsRng;
use rand_core::{RngCore, Error, impls};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar,
    traits::Identity,
};
use x25519_dalek::{EphemeralSecret, PublicKey};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::fmt;
use sha2::Sha512;

use crate::{
    key::{gen_keypair, PrivateKey, PublicKey as Trace_key},
    prelude::*,
    sig::{compute_sigma, Signature, Tag, sign, verify},
    trace::{Trace, trace},
};

const NUM_PARTIES: usize = 7;
const NUM_MAL: usize = 3;

const TRS_VEC_SIZE: usize = 32;
const MSG_SIZE:usize = 2048;
const INTRODUCER_IP: &str = "192.168.31.154";
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
    signature_byte_set: HashSet<Vec<u8>>, // TRS message vector set to get the union of all TRS
    signatures_set: HashMap<Vec<u8>, Signature>,
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
            // Information of other nodes
            membership_list: 
                vec!["172.22.94.218".to_string(), // vm1
                     "172.22.156.221".to_string(), // vm2
                     "172.22.158.219".to_string(), //vm3
                     "172.22.94.219".to_string(), // vm4
                     "172.22.156.222".to_string(), // vm5
                     "172.22.158.220".to_string(), //vm6
                     "172.22.94.221".to_string()], // vm10
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

       // Get message type
        let msg_type: u8 = msg[0];


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
                                self.parties_status.insert(src_addr.get(0..(src_addr.len() - 5)).unwrap().to_string().clone(), new_party);
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

            // Create incoming party's anonymous public key vector
            let spk_vec: Vec<u8> = (&msg[spk_index..spk_index_end]).to_vec();

            // Create incoming party's TRS aa1 vector
            let aa1_vec: Vec<u8> = (&msg[aa1_index..aa1_index_end]).to_vec();

            // Create incoming party's TRS cs vector
            let cs_vec: Vec<u8> = (&msg[cs_index..cs_index_end]).to_vec(); // 32 * num_parties
            
            // Create incoming party's TRS zs vector
            let zs_vec: Vec<u8> = (&msg[zs_index..zs_index_end]).to_vec(); // 32 * num_parties

            // Recreate the anonymous public key

            // Convert TRS aa1 vector into array
            let mut j: usize = 0;
            let mut aa1_arr: [u8; 32] = [0; 32];
            for aa1_byte in aa1_vec.iter() {
                aa1_arr[j] = aa1_vec[j];
                j += 1;
            }

            
            // Recreate aa1 for TRS
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
            
            
            match self.signatures_set.get(&spk_vec) {    
                Some(_) => (),
                None=> {
                    self.signatures_set.insert(spk_vec.clone(), re_trs);
                }
            }

        } else if (msg_type == 2) { 
            
            if (!self.signature_byte_set.contains(&msg)) {
                msg[0] = 2;
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

                let spk_vec: Vec<u8> = (&msg[spk_index..spk_index_end]).to_vec();
                let aa1_vec: Vec<u8> = (&msg[aa1_index..aa1_index_end]).to_vec();
                let cs_vec: Vec<u8> = (&msg[cs_index..cs_index_end]).to_vec(); 
                let zs_vec: Vec<u8> = (&msg[zs_index..zs_index_end]).to_vec(); 
            
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

                let mut arr = [0u8; 32];
                arr.copy_from_slice(&aa1_arr);
                let c = CompressedRistretto(arr);
                let re_aa1: RistrettoPoint = c.decompress().unwrap();

                let mut cs_count: usize = 0;
                let mut re_cs_vec: Vec<Scalar> = Vec::new();
                
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

                let mut zs_count: usize = 0;
                let mut re_zs_vec: Vec<Scalar> = Vec::new();
                
                loop {
                    if (zs_count == num_zs.into()) {
                        break;
                    }
                    let mut cur_arr: [u8; 32] = [0; 32];
                    let mut cur_i: usize = 0;
                    

                    let zs_vec_temp:Vec<u8> = (&zs_vec[zs_count*32..zs_count*32 + 32]).to_vec();
                
                    for zs_byte in zs_vec_temp.iter() {
                        cur_arr[cur_i] = zs_vec_temp[cur_i];
                        cur_i += 1;
                    }

                    let cur_zs: Scalar =  Scalar::from_canonical_bytes(cur_arr).unwrap();
                    re_zs_vec.push(cur_zs);

                    zs_count += 1;
                }


                let re_trs: Signature = Signature{aa1: re_aa1, cs: re_cs_vec, zs: re_zs_vec};

                match self.signatures_set.get(&spk_vec) {
                    Some(_) => {
                    },
                    None=> {
                        self.signatures_set.insert(spk_vec.clone(), re_trs);
                        
                    }

                }
            }
                
        }

    }

    // Function used to received the initial broadcast message from other parties
    fn process_received(&mut self) {
        // Loop to keep receiving message from the client communication channel
        loop {
           
            match self.rx.try_recv() {
                Ok(msg) => {
                    // Process received mesasge
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    //Stop receiving message when all the parties' info is received
                    if (self.parties_status.len() == NUM_PARTIES) {
                        // println!("party status len is 1");
                        break;
                    }
                },
                Err(TryRecvError::Disconnected) => {
                    break;
                },
                Err(e) => {
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
                    // Process received mesasge
                    &self.process_message(msg.clone());
                    // msg_received.push(msg);

                },
                Err(TryRecvError::Empty) => {
                    if (self.signatures_set.len() == NUM_PARTIES + NUM_MAL && num_empty >= self.membership_list.len() * self.membership_list.len() * self.signature_byte_set.len()) {
                        break;
                    }
                    num_empty += 1;
                },
                Err(TryRecvError::Disconnected) => {
                    break;
                },
                Err(e) => {
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
                    // Process received mesasge
                    &self.process_message(msg.clone());

                },
                Err(TryRecvError::Empty) => {
                    if (self.signature_byte_set.len() == NUM_PARTIES) {
                        break;
                    }
      
                },
                Err(TryRecvError::Disconnected) => {
                    break;
                },
                Err(e) => {
                    break;
                }
            }
        }

        
    }

    
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

    // Function for malicious party to create the sceond trs message
    pub fn create_trs_msg_diff(&self, trs: Signature, pk_diff: PublicKey) -> Vec<u8> {
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
        let mut spk_vec = pk_diff.as_bytes().to_vec();

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
    pub fn verify_trs(&mut self) {
        // let mut to_remove: Vec<x25519_dalek::PublicKey> = vec![];
        let mut to_remove: Vec<Vec<u8>> = vec![];
        for (spk_map, sig) in self.signatures_set.iter() {
            for (spk_map_a, sig_a) in self.signatures_set.iter() {
                if((Trace::Linked == trace(&*spk_map, &sig, &*spk_map_a, &sig_a, &self.trs_tag))) {
                } else if ((Trace::Indep == trace(&*spk_map, &sig, &*spk_map_a, &sig_a, &self.trs_tag))) {
               
                } else {
                    to_remove.push(spk_map.to_vec());
                    to_remove.push(spk_map_a.to_vec());
                }
            }
        }

        for remove_key in to_remove {
            match self.signatures_set.remove(&remove_key) {
                Some(_) => {
                }, 
                None => {
                }
            }
        }
    }

    // 
    pub fn create_trs(&mut self, mut trs_rng: ThreadRng) -> Signature{
        // Create issue for TRS' tag
        let issue = b"anonymous pke".to_vec();

        // push all parties' publick key to a vector for TRS' tag
        let mut pubkeys: Vec<Trace_key> = vec![];

        for ip_addr in self.membership_list.iter(){

            match self.parties_status.get(&ip_addr.clone()) {
                Some(pk) => {
                    let pk_vec: Vec<u8> = pk.0.as_bytes().to_vec();
                    match Trace_key::from_bytes(&pk_vec) {
                        Some(pk_trs) => {
        
                            pubkeys.push(pk_trs);
                        }
                        None => {
                        }
                    }
                }
                None => {
                }
            }
            
        }
        self.trs_tag = Tag { 
            issue, 
            pubkeys,
        };

        // Put party's anonymous public key into byte as message to sign
        let msg_to_sign = self.spk.as_bytes();

        // Create random value as TRS' parameter

        // Sign the message
        sign(&mut trs_rng, &*msg_to_sign, &self.trs_tag, &self.secret_key)
    }

    // function for malicious party to create another TRS using the second anonymous public key 
    pub fn create_trs_diff(&mut self, pk_diff: PublicKey, mut trs_rng: ThreadRng) -> Signature{

        // Create issue for TRS' tag

        // push all parties' publick key to a vector for TRS' tag
        let mut pubkeys: Vec<Trace_key> = vec![];

        for ip_addr in self.membership_list.iter(){
            match self.parties_status.get(&ip_addr.clone()) {
                Some(pk) => {
                    let pk_vec: Vec<u8> = pk.0.as_bytes().to_vec();
                    match Trace_key::from_bytes(&pk_vec) {
                        Some(pk_trs) => {
        
                            pubkeys.push(pk_trs);
                        }
                        None => {
                        }
                    }
                }
                None => {
                }
            }
            
        }

        let msg_to_sign = pk_diff.as_bytes();

        // Sign the message
        sign(&mut trs_rng, &*msg_to_sign, &self.trs_tag, &self.secret_key)
    }

    pub fn multicast_trs(&mut self, trs_vec: Vec<u8>) {
        // Iterate through membership list and send trs message to all parties
        for party in self.membership_list.iter() {
            self.send_message(party.to_string(), trs_vec.clone());
        }
    }

    pub fn multicast_trs_diff(&mut self, trs_vec: Vec<u8>, trs_vec_diff: Vec<u8>) {
        // Iterate through membership list and send trs message to all parties
        // Send different public key to different parties
        let mut r = 1;
        for party in self.membership_list.iter() {

            if (r % 2 == 0) {
                self.send_message(party.to_string(), trs_vec.clone());
            } else{
                self.send_message(party.to_string(), trs_vec_diff.clone());
            }
            r = r + 1;
            
        }
    }


    
    // Starting Byzantine party. This party sends different TRS to different parties
    pub fn start_diff(mut self) {
        println!("starting malicious node, send different anonymous keys to different parties");
        // Broadcast self unanonymoud public key
        println!("Broadcasting unanonymous public key...");
        &self.client_start();
        
        
        // Create client thread
        let client_thread = thread::spawn(move || loop {

            // Receive messages
            &self.process_received();
            println!("All members unanonymous public key received");
            // Receive initial message again if not all parties' information are received
            if (self.parties_status.len() < NUM_PARTIES) {
                continue;
            }

            // Create traceable Signature ring
            let trs_rng:ThreadRng = rand::thread_rng();
            println!("Creating Traceable ring signature...");
            let trs: Signature = self.create_trs(trs_rng);
            

            let aa1_r: RistrettoPoint = trs.aa1.clone();
            let cs_r: Vec<Scalar> = trs.cs.clone();
            let zs_r: Vec<Scalar> = trs.zs.clone();

            // Create Trs message to send to other parties
            let mut spki_trs_vec: Vec<u8> = self.create_trs_msg(trs);

            //Create second trs with another anonymous public key
            let mut rng1 = OsRng;
            let sk_diff = EphemeralSecret::new(rng1);
            let pk_diff = PublicKey::from(&sk_diff);
            let trs_multi:Signature = self.create_trs_diff(pk_diff, trs_rng);

            // Create second TRS message
            println!("Creating second Traceable ring signature...");
            let mut spki_trs_vec_diff: Vec<u8> = self.create_trs_msg_diff(trs_multi, pk_diff);

            println!("Broadcasting Traceable ring signature...");
            // Send trs message vector to all other parties
            &self.multicast_trs_diff(spki_trs_vec.clone(), spki_trs_vec_diff.clone());
            
            // Receive and process TRS of other parties
            println!("Collecting all TRS...");
            &self.process_received_trs(); // 

            // Send the set of received TRS to other parties
            println!("Broadcasting TRS set...");
            &self.multicast_trs_set();

            // Process the received trs byte
            println!("Creating TRS union...");
            &self.process_received_trs_byte(); 


            // Verify the autheniticity of received TRS
            println!("Verifying TRS...");
            &self.verify_trs();

            println!("Result:");
            for (spk_map, sig) in self.signatures_set.iter() {
                println!("{:?}", spk_map);
                println!("============================================================");
            }

            
            break;
        });

        let client_res = client_thread.join();
       
    }

    pub fn start_honest(mut self) {
        // Hardcode membership list for now
        
            println!("starting honest node");
             // Broadcast self unanonymous public key
            println!("Broadcasting unanonymous public key...");
            &self.client_start();
            
            
            // Create client thread
            let client_thread = thread::spawn(move || loop {
                // Receive messages
                &self.process_received();
                println!("All members unanonymous public key received");

                // Receive initial message again if not all parties' information are received
                if (self.parties_status.len() < NUM_PARTIES) {
                    continue;
                }

                // Create traceable Signature ring
                let trs_rng:ThreadRng = rand::thread_rng();


                println!("Creating Traceable ring signature...");
                let trs: Signature = self.create_trs(trs_rng);

                let aa1_r: RistrettoPoint = trs.aa1.clone();
                let cs_r: Vec<Scalar> = trs.cs.clone();
                let zs_r: Vec<Scalar> = trs.zs.clone();

                // Create Trs message to send to other parties
                let mut spki_trs_vec: Vec<u8> = self.create_trs_msg(trs);

                // Send trs message vector to all other parties
                println!("Broadcasting Traceable ring signature...");
                &self.multicast_trs(spki_trs_vec.clone());
                
                // Receive and process TRS of other parties
                println!("Collecting all TRS...");
                &self.process_received_trs(); // 

                // Send the set of received TRS to other parties
                println!("Broadcasting TRS set...");
                &self.multicast_trs_set();

                // Process the received trs byte
                println!("Creating TRS union...");
                &self.process_received_trs_byte(); 


                // Verify the autheniticity of received TRS
                println!("Verifying TRS...");
                &self.verify_trs();

                println!("Result:");
                for (spk_map, sig) in self.signatures_set.iter() {
                    println!("{:?}", spk_map);
                    println!("============================================================");
                }

                
                break;
            });

            let client_res = client_thread.join();
    }

    pub fn create_msg(&self, mut msg_vec: Vec<u8>, mut msg_type: u8, mut is_anonymous: u8) -> Vec<u8>{
        let msg_len: u8 = msg_vec.len() as u8;
        let mut result_vec: Vec<u8> = vec![msg_type, msg_len, is_anonymous];
        result_vec.append(&mut msg_vec);
        result_vec

    }

    // Function to send party's unanonymous public key to other parties
    pub fn client_start(&self){
        let mut msg: String = String::new();
        msg.push_str("[0]::");
        
        // Convert public key to byte to send
        let mut public_key_vec: Vec<u8> = self.public_key.as_bytes();
        let mut my_vec: Vec<u8> = vec![1];
        
        let msg_to_send: Vec<u8> = self.create_msg(public_key_vec.clone(), 0, 0);
        
        // Send public key vector to all parties
        for party in self.membership_list.iter() {
            self.send_message(party.to_string(), msg_to_send.clone());
        }
    }

    // Function to send message
    pub fn send_message(&self, target: String, msg: Vec<u8>) {
        
        // Get the host address
        let host_name = dns_lookup::get_hostname().unwrap();
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        let mut bind_param = ip_addr[0].to_string();
        bind_param.push_str(CLIENT_PORT);

        // Bind to UDP socket
        let socket = net::UdpSocket::bind(bind_param).expect("client failed to bind");

        let mut connect_param = target.clone();
        connect_param.push_str(PORT);
        
        // Send UDP packet
        match socket.send_to(&msg, connect_param){
            Ok(number_of_bytes) => {},
            Err(fail) => {},
        }
       
    }



    // Function to create the ID of a party
    fn create_id() -> String {

        // getting host ip
        let host_name = dns_lookup::get_hostname().unwrap();
        
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();


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
                match tx.send(result) {
                    Ok(r) => {
                    }
                    Err(e) => {
                        continue;
                    }
                }
                
            }, 
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            Err(fail) => println!("failed listening {:?}", fail)
        }
    }
    println!("thread finishing");
}
