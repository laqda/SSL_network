use serde::{Serialize, Deserialize};
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use crate::errors::{SSLNetworkError, ResultSSL};
use openssl::pkey::{PKey, Private};
use getrandom;
use crate::certification::{CertificationChain, PublicKey, Certificate};

pub type Nonce = [u8; 32];

pub fn gen_nonce() -> Nonce {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap();
    buf
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    payload: String,
    signature: Option<Vec<u8>>,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum PacketTypes {
    // COMMON
    DISCOVER_SYN {
        name: String,
        pub_key: PublicKey,
        nonce: Nonce,
    },
    DISCOVER_SYN_ACK {
        name: String,
        pub_key: PublicKey,
        nonce: Nonce,
        proof: Option<CertificationChain>,
    },
    DISCOVER_ACK {
        proof: Option<CertificationChain>,
    },
    REFUSED,
    // CONNECTION
    CONNECTION_ALLOWED_SYN {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    CONNECTION_ALLOWED_SYN_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    CONNECTION_ALLOWED_ACK,
    // SYNCHRONIZATION
    SYNCHRONIZATION_SEND_KNOWLEDGE_SYN {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    SYNCHRONIZATION_SEND_KNOWLEDGE_SYN_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    SYNCHRONIZATION_SEND_KNOWLEDGE_ACK,
}

impl Packet {
    pub fn generate_discover_syn(name: &str, pub_key: &PublicKey, nonce: Nonce) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::DISCOVER_SYN {
                name: name.clone().to_string(),
                pub_key: pub_key.clone(),
                nonce,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_discover_syn_ack(name: &str, pub_key: &PublicKey, nonce: Nonce, proof: Option<CertificationChain>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::DISCOVER_SYN_ACK {
                name: name.clone().to_string(),
                pub_key: pub_key.clone(),
                nonce,
                proof,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_discover_ack(proof: Option<CertificationChain>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::DISCOVER_ACK {
                proof,
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_refused() -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::REFUSED {}).unwrap(),
            signature: None,
        }
    }
    pub fn generate_connection_allowed_syn(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_SYN {
                new_certificate,
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_connection_allowed_syn_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_SYN_ACK {
                new_certificate,
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_connection_allowed_ack() -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_ACK {}).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_syn(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN {
                new_certificate,
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_syn_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN_ACK {
                new_certificate,
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_ack() -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_ACK {}).unwrap(),
            signature: None,
        }
    }
    pub fn sign(mut self, server_nonce: &Nonce, client_nonce: &Nonce, eq_pri_key: &PKey<Private>) -> Packet {
        let mut signer = Signer::new(MessageDigest::sha256(), eq_pri_key).unwrap();
        signer.update(self.payload.as_bytes()).unwrap();
        signer.update(server_nonce).unwrap();
        signer.update(client_nonce).unwrap();
        self.signature = Some(signer.sign_to_vec().unwrap());
        self
    }
    pub fn verify(&self, server_nonce: &Nonce, client_nonce: &Nonce, peer_pub_key: &PublicKey) -> ResultSSL<()> {
        let pub_key = PKey::public_key_from_pem(peer_pub_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key).unwrap();
        verifier.update(self.payload.as_bytes()).unwrap();
        verifier.update(server_nonce).unwrap();
        verifier.update(client_nonce).unwrap();
        match verifier.verify(self.signature.clone().ok_or(SSLNetworkError::ProtocolViolation {})?.as_ref()).unwrap() {
            true => Ok(()),
            false => Err(SSLNetworkError::InvalidSignature {})
        }
    }
    pub fn get_payload(&self) -> Result<PacketTypes, SSLNetworkError> { serde_json::from_str(&self.payload).map_err(|_| SSLNetworkError::InvalidPayload {}) }
}
