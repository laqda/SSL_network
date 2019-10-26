use std::net::{Ipv4Addr, SocketAddr, IpAddr};
use openssl::pkey::{Private, PKey};
use openssl::rsa::Rsa;
use crate::errors::{ResultSSL, SSLNetworkError};
use crate::certification::{PublicKey, PrivateKey, Certificate, Equipment};
use crate::network::{EquipmentNetwork, Network};
use std::fmt::{Display, Formatter, Error};

pub struct SimulatedEquipment {
    name: String,
    address: Ipv4Addr,
    port: u16,
    pub_key: PublicKey,
    pri_key: PrivateKey,
    cert: Certificate,
    net: EquipmentNetwork,
}

impl SimulatedEquipment {
    pub fn new(address: Ipv4Addr, port: u16) -> ResultSSL<SimulatedEquipment> {
        let name = format!("Equipment_{}:{}", address, port);
        let rsa = Rsa::generate(2048).unwrap();
        let pri_key: PKey<Private> = PKey::from_rsa(rsa).unwrap();
        let pub_key = pri_key.public_key_to_pem().unwrap();
        let equipment = Equipment {
            name: name.clone(),
            pub_key: pub_key.clone(),
        };
        let cert = Certificate::new(equipment.clone(), equipment.clone(), pri_key.clone());
        if !cert.is_valid()? {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
        let net = EquipmentNetwork::new(&equipment);
        Ok(SimulatedEquipment {
            name,
            address,
            port,
            pub_key,
            pri_key,
            cert,
            net,
        })
    }
    pub fn get_name(&self) -> &str { &self.name }
    pub fn get_public_key(&self) -> &PublicKey { &self.pub_key }
    pub fn get_private_key(&self) -> &PrivateKey { &self.pri_key }
    pub fn get_network(&mut self) -> &mut EquipmentNetwork { &mut self.net }
    pub fn get_socket_address(&self) -> SocketAddr { SocketAddr::new(IpAddr::V4(self.address), self.port) }
    pub fn certify(&self, subject: &Equipment) -> Certificate { Certificate::new(Equipment { name: self.name.clone(), pub_key: self.pub_key.clone() }, subject.clone(), self.pri_key.clone()) }
}

impl Display for SimulatedEquipment {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f,
               "[name] {}\n\
                [port] {}\n\
                [self-certificate]\n{}",
               self.name,
               self.port,
               self.cert,
        )
    }
}