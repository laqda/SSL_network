use serde::{Serialize, Deserialize};
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use crate::errors::{SSLNetworkError, ResultSSL};
use openssl::pkey::{PKey, Private};
use getrandom;
use crate::certification::{CertificationChain, PublicKey, Certificate};

pub type Nonce = [u8; 32];

// random number, use only once to make connection unique
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
#[serde(tag = "type")] // add type parameter in JSON next to values to make payload type unique
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
    CONNECTION_ALLOWED_SYN,
    CONNECTION_ALLOWED_SYN_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    CONNECTION_ALLOWED_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    // SYNCHRONIZATION
    SYNCHRONIZATION_SEND_KNOWLEDGE_SYN,
    SYNCHRONIZATION_SEND_KNOWLEDGE_SYN_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
    SYNCHRONIZATION_SEND_KNOWLEDGE_ACK {
        new_certificate: Option<Certificate>,
        knowledge: Vec<Certificate>,
    },
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
    pub fn generate_connection_allowed_syn() -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_SYN {}).unwrap(),
            signature: None,
        }
    }
    pub fn generate_connection_allowed_syn_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_SYN_ACK {
                new_certificate: new_certificate.clone(),
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_connection_allowed_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::CONNECTION_ALLOWED_ACK {
                new_certificate: new_certificate.clone(),
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_syn() -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN {
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_syn_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN_ACK {
                new_certificate: new_certificate.clone(),
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn generate_synchronization_send_knowledge_ack(new_certificate: Option<Certificate>, knowledge: &Vec<Certificate>) -> Packet {
        Packet {
            payload: serde_json::to_string(&PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_ACK {
                new_certificate: new_certificate.clone(),
                knowledge: knowledge.clone(),
            }).unwrap(),
            signature: None,
        }
    }
    pub fn sign(mut self, server_nonce: &Nonce, client_nonce: &Nonce, eq_pri_key: &PKey<Private>) -> Packet {
        let mut signer = Signer::new(MessageDigest::sha256(), eq_pri_key).unwrap(); // use sha256 to hash content
        signer.update(self.payload.as_bytes()).unwrap(); // add payload to sign content
        signer.update(server_nonce).unwrap(); // add server nonce to sign content
        signer.update(client_nonce).unwrap(); // add client nonce to sign content
        self.signature = Some(signer.sign_to_vec().unwrap());
        self
    }
    pub fn verify(&self, server_nonce: &Nonce, client_nonce: &Nonce, peer_pub_key: &PublicKey) -> ResultSSL<()> {
        let pub_key = PKey::public_key_from_pem(peer_pub_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key).unwrap(); // use sha256 to hash content
        verifier.update(self.payload.as_bytes()).unwrap(); // add payload to sign content
        verifier.update(server_nonce).unwrap(); // add server nonce to sign content
        verifier.update(client_nonce).unwrap(); // add client nonce to sign content
        match verifier.verify(self.signature.clone().ok_or(SSLNetworkError::ProtocolViolation {})?.as_ref()).unwrap() {
            true => Ok(()),
            false => Err(SSLNetworkError::InvalidSignature {})
        }
    }
    pub fn get_payload(&self) -> Result<PacketTypes, SSLNetworkError> { serde_json::from_str(&self.payload).map_err(|_| SSLNetworkError::InvalidPayload {}) }
}
