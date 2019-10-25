use serde::{Serialize, Deserialize};
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use crate::errors::{SSLNetworkError, ResultSSL};
use openssl::pkey::PKey;

pub type Nonce = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionPacket {
    payload: String,
    signature: Option<Vec<u8>>,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "data")]
pub enum ConnectionPacketTypes {
    DISCOVER_SYN {
        name: String,
        pub_key: Vec<u8>,
        nonce: Nonce,
    },
    DISCOVER_SYN_ACK {
        name: String,
        pub_key: Vec<u8>,
        nonce: Nonce,
    },
    DISCOVER_ACK,
    ALLOWED_SYN {
        new_certificate: Option<Vec<u8>>,
    },
    ALLOWED_SYN_ACK {
        new_certificate: Option<Vec<u8>>,
    },
    ALLOWED_ACK,
    REFUSED,
}

impl ConnectionPacket {
    pub fn generate_discover_syn(name: String, pub_key: Vec<u8>, nonce: String) -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::DISCOVER_SYN {
                name,
                pub_key,
                nonce,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_discover_syn_ack(name: String, pub_key: Vec<u8>, nonce: String) -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::DISCOVER_SYN_ACK {
                name,
                pub_key,
                nonce,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_discover_ack() -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::DISCOVER_ACK {}).unwrap(),
            signature: None,
        }
    }
    pub fn generate_allowed_syn(new_certificate: Option<Vec<u8>>) -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::ALLOWED_SYN {
                new_certificate,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_allowed_syn_ack(new_certificate: Option<Vec<u8>>) -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::ALLOWED_SYN_ACK {
                new_certificate,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_allowed_ack() -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::ALLOWED_ACK {}).unwrap(),
            signature: None,
        }
    }
    pub fn generate_refused() -> ConnectionPacket {
        ConnectionPacket {
            payload: serde_json::to_string(&ConnectionPacketTypes::REFUSED {}).unwrap(),
            signature: None,
        }
    }
    pub fn sign(mut self, local_nonce: &String, peer_nonce: &String, eq_pri_key: &Vec<u8>) -> ConnectionPacket {
        let pri_key = PKey::private_key_from_pem(eq_pri_key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pri_key).unwrap();
        signer.update(self.payload.as_ref()).unwrap();
        signer.update(local_nonce.as_ref()).unwrap();
        signer.update(peer_nonce.as_ref()).unwrap();
        self.signature = Some(signer.sign_to_vec().unwrap());
        self
    }
    pub fn verify(&self, local_nonce: &String, peer_nonce: &String, peer_pub_key: &Vec<u8>) -> ResultSSL<()> {
        let pub_key = PKey::public_key_from_pem(peer_pub_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key).unwrap();
        verifier.update(self.payload.as_ref()).unwrap();
        verifier.update(local_nonce.as_ref()).unwrap();
        verifier.update(peer_nonce.as_ref()).unwrap();
        match verifier.verify(self.signature.clone().ok_or(SSLNetworkError::ConnectionProtocolViolation {})?.as_ref()).unwrap() {
            true => Ok(()),
            false => Err(SSLNetworkError::InvalidSignature {})
        }
    }
    pub fn get_payload(&self) -> Result<ConnectionPacketTypes, SSLNetworkError> { serde_json::from_str(&self.payload).map_err(|_| SSLNetworkError::InvalidPayload {}) }
}
