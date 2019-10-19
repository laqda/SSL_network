extern crate openssl;

use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use self::openssl::pkey::{Private, Public};
use std::fmt::{Display, Formatter, Error};
use crate::errors::SSLNetworkError;
use std::net::IpAddr;

pub struct Equipment {
    name: String,
    address: IpAddr::V4,
    port: u32,
    certificate: Option<Certificate>,
    rsa: Rsa<Private>,
}

impl Equipment {
    pub fn new(address: IpAddr::V4, port: u32) -> Result<Equipment, SSLNetworkError> {
        let name = format!("Equipment_{}:{}", address, port);
        let rsa = Rsa::generate(2048).unwrap();
        let mut eq = Equipment {
            name,
            address,
            port,
            certificate: None,
            rsa,
        };
        eq.certificate = Some(Certificate::self_certified(&eq));
        let public_key = (&eq).get_public_key();
        match eq.certificate.as_ref().unwrap().0.verify(&public_key).unwrap() {
            true => Ok(eq),
            false => Err(SSLNetworkError::EquipmentCreationFailInvalidSelfCertificate {}),
        }
    }
    pub fn get_public_key(&self) -> PKey<Public> {
        self.certificate.as_ref().unwrap().0.public_key().unwrap()
    }
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
    pub fn self_certified(eq: &Equipment) -> Certificate {
        Certificate::certify(&eq, &eq)
    }

    pub fn certify(subject: &Equipment, issuer: &Equipment) -> Certificate {
        let subject_pkey = PKey::from_rsa(subject.rsa.clone()).unwrap();
        let issuer_pkey = PKey::from_rsa(issuer.rsa.clone()).unwrap();

        let mut subject_name_builder = X509Name::builder().unwrap();
        subject_name_builder.append_entry_by_nid(Nid::COMMONNAME, subject.name.as_str()).unwrap();
        let subject_name = subject_name_builder.build();

        let mut issuer_name_builder = X509Name::builder().unwrap();
        issuer_name_builder.append_entry_by_nid(Nid::COMMONNAME, issuer.name.as_str()).unwrap();
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