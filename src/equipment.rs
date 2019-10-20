extern crate openssl;

use crate::errors::SSLNetworkError;
use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use std::fmt::{Display, Formatter, Error};
use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use self::openssl::pkey::Private;
use crate::network::Network;
use crate::network;

pub struct Equipment {
    name: String,
    address: Ipv4Addr,
    port: u16,
    certificate: Option<Certificate>,
    rsa: Rsa<Private>,
    network: Network,
}

impl Equipment {
    pub fn new(address: Ipv4Addr, port: u16) -> Result<Equipment, SSLNetworkError> {
        let name = format!("Equipment_{}:{}", address, port);
        let name_init_network = name.clone();

        let rsa = Rsa::generate(2048).unwrap();
        let rsa_verify = rsa.clone();
        let rsa_init_network = rsa.clone();

        let mut eq = Equipment {
            name,
            address,
            port,
            certificate: None,
            rsa,
            network: Network::new(network::Equipment::new(name_init_network, rsa_init_network.public_key_to_pem().unwrap())),
        };
        eq.self_certify();
        let public_key = PKey::from_rsa(rsa_verify).unwrap();
        match eq.certificate.as_ref().unwrap().0.verify(&public_key).unwrap() {
            true => Ok(eq),
            false => Err(SSLNetworkError::EquipmentCreationFailInvalidSelfCertificate {}),
        }
    }
    pub fn get_name(&self) -> String { self.name.clone() }
    pub fn get_public_key(&self) -> Vec<u8> { self.rsa.public_key_to_pem().unwrap() }
    pub fn get_private_key(&self) -> Vec<u8> { self.rsa.private_key_to_pem().unwrap() }
    pub fn get_network(&mut self) -> &mut Network { &mut self.network }
    pub fn get_socket_address(&self) -> SocketAddr { SocketAddr::new(IpAddr::V4(self.address), self.port) }
    pub fn self_certify(&mut self) { self.certificate = Some(self.certify(self.name.clone(), self.get_public_key())); }
    pub fn certify(&self, subject_name: String, subject_pub_key: Vec<u8>) -> Certificate { Certificate::certify(subject_name, subject_pub_key, self.name.clone(), self.get_private_key()) }
}

impl Display for Equipment {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let certificate = match &self.certificate {
            Some(c) => String::from_utf8(c.0.to_pem().unwrap()).unwrap(),
            None => String::from("None"),
        };
        write!(f,
               "[name] {}\n\
                [port] {}\n\
                [self-certificate]\n\n{}",
               self.name,
               self.port,
               certificate,
        )
    }
}

pub struct Certificate(pub X509);

impl Certificate {
    pub fn certify(subject_name: String, subject_pub_key: Vec<u8>, issuer_name: String, issuer_pri_key: Vec<u8>) -> Certificate {
        let subject_pkey = PKey::public_key_from_pem(subject_pub_key.as_ref()).unwrap();
        let issuer_pkey = PKey::private_key_from_pem(issuer_pri_key.as_ref()).unwrap();

        let mut subject_name_builder = X509Name::builder().unwrap();
        subject_name_builder.append_entry_by_nid(Nid::COMMONNAME, subject_name.as_str()).unwrap();
        let subject_name = subject_name_builder.build();

        let mut issuer_name_builder = X509Name::builder().unwrap();
        issuer_name_builder.append_entry_by_nid(Nid::COMMONNAME, issuer_name.as_str()).unwrap();
        let issuer_name = issuer_name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&subject_name.as_ref()).unwrap();
        builder.set_issuer_name(&issuer_name.as_ref()).unwrap();
        builder.set_pubkey(&subject_pkey).unwrap();
        builder.sign(&issuer_pkey, MessageDigest::sha256()).unwrap();

        Certificate(builder.build())
    }
}

impl Display for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "[certificate]\n{}", String::from_utf8(self.0.to_pem().unwrap()).unwrap(),
        )
    }
}