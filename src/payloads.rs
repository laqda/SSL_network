use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    packet_type: String,
    payload: String,
}

impl Packet {
    pub fn connect(name: String, pub_key: Vec<u8>) -> Packet {
        Packet {
            packet_type: "CONNECT".to_string(),
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
            packet_type: "ALLOWED".to_string(),
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
            packet_type: "NEW_CERTIFICATE".to_string(),
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
            packet_type: "REFUSED".to_string(),
            payload: serde_json::to_string(
                &Connected {}
            ).unwrap(),
        }
    }
    pub fn connected() -> Packet {
        Packet {
            packet_type: "CONNECTED".to_string(),
            payload: serde_json::to_string(
                &Connected {}
            ).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Connect {
    // sender wants to communicate with receiver
    name: String,
    pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Allowed {
    // sender got a certification chain
    name: String,
    pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewCertificate {
    // sender do not possess a certification chain, User OK to add receiver
    name: String,
    pub_key: Vec<u8>,
    certificate: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Refused {} // sender do not possess a certification chain, User NOT OK to add receiver

#[derive(Serialize, Deserialize, Debug)]
pub struct Connected {} // sender acknowledge the connection process
