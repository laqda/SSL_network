use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    pub packet_type: PacketType,
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PacketType {
    CONNECT,
    ALLOWED,
    NEW_CERTIFICATE,
    REFUSED,
    CONNECTED,
}

impl Packet {
    pub fn connect(name: String, pub_key: Vec<u8>) -> Packet {
        Packet {
            packet_type: PacketType::CONNECT,
            payload: serde_json::to_string(
                &Connect {
                    name,
                    pub_key,
                }
            ).unwrap(),
        }
    }
    pub fn allowed(name: String, pub_key: Vec<u8>) -> Packet {
        Packet {
            packet_type: PacketType::ALLOWED,
            payload: serde_json::to_string(
                &Allowed {
                    name,
                    pub_key,
                }
            ).unwrap(),
        }
    }
    pub fn new_certificate(name: String, pub_key: Vec<u8>, certificate: Vec<u8>) -> Packet {
        Packet {
            packet_type: PacketType::NEW_CERTIFICATE,
            payload: serde_json::to_string(
                &NewCertificate {
                    name,
                    pub_key,
                    certificate,
                }
            ).unwrap(),
        }
    }
    pub fn refused() -> Packet {
        Packet {
            packet_type: PacketType::REFUSED,
            payload: serde_json::to_string(
                &Connected {}
            ).unwrap(),
        }
    }
    pub fn connected() -> Packet {
        Packet {
            packet_type: PacketType::CONNECTED,
            payload: serde_json::to_string(
                &Connected {}
            ).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Connect {
    // sender wants to communicate with receiver
    pub name: String,
    pub pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Allowed {
    // sender got a certification chain
    pub name: String,
    pub pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewCertificate {
    // sender do not possess a certification chain, User OK to add receiver
    pub name: String,
    pub pub_key: Vec<u8>,
    pub certificate: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Refused {} // sender do not possess a certification chain, User NOT OK to add receiver

#[derive(Serialize, Deserialize, Debug)]
pub struct Connected {} // sender acknowledge the connection process
