use serde::{Serialize, Deserialize};
use openssl::x509::{X509Name, X509};
use openssl::nid::Nid;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use std::fmt;
use openssl::pkey::{Private, PKey};
use crate::errors::{ResultSSL, SSLNetworkError};
use std::fmt::Display;
use failure::_core::fmt::{Formatter, Error};

pub type PublicKey = Vec<u8>;
pub type PrivateKey = PKey<Private>;
pub type Pem = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Equipment {
    pub name: String,
    pub pub_key: PublicKey,
}

impl PartialEq for Equipment {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key && self.name == other.name
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate {
    issuer: Equipment,
    subject: Equipment,
    cert: Pem,
}

impl Certificate {
    pub fn new(issuer: Equipment, subject: Equipment, issuer_pri_key: PrivateKey) -> Certificate {
        let subject_pub_key = PKey::public_key_from_pem(&subject.pub_key).unwrap();

        let mut subject_name_builder = X509Name::builder().unwrap();
        subject_name_builder.append_entry_by_nid(Nid::COMMONNAME, &subject.name).unwrap();
        let subject_name = subject_name_builder.build();

        let mut issuer_name_builder = X509Name::builder().unwrap();
        issuer_name_builder.append_entry_by_nid(Nid::COMMONNAME, &issuer.name).unwrap();
        let issuer_name = issuer_name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&subject_name.as_ref()).unwrap();
        builder.set_issuer_name(&issuer_name.as_ref()).unwrap();
        builder.set_pubkey(&subject_pub_key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(7).unwrap()).unwrap();
        builder.sign(&issuer_pri_key, MessageDigest::sha256()).unwrap();

        let cert = builder.build();
        let cert = cert.to_pem().unwrap();
        Certificate {
            issuer,
            subject,
            cert,
        }
    }
    pub fn is_valid(&self) -> ResultSSL<bool> {
        let cert = match X509::from_pem(&self.cert) {
            Ok(cert) => cert,
            Err(_) => return Err(SSLNetworkError::InvalidCertificateFormat {})
        };
        let is_ok = match cert.verify(&PKey::public_key_from_pem(&self.issuer.pub_key).unwrap()) {
            Ok(is_ok) => is_ok,
            Err(_) => return Err(SSLNetworkError::InvalidCertificateFormat {})
        };
        Ok(is_ok)
    }
    pub fn subject(&self) -> &Equipment {
        &self.subject
    }
    pub fn issuer(&self) -> &Equipment {
        &self.issuer
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let mut to_write = String::new();
        to_write.push_str(&format!("[CERTIFICATE]\n"));
        to_write.push_str(&format!("(issuer.name) {}\n", self.issuer.name));
        to_write.push_str(&format!("(issuer.pub_key)\n{}", String::from_utf8(self.issuer.pub_key.clone()).unwrap()));
        to_write.push_str(&format!("(subject.name) {}\n", self.subject.name));
        to_write.push_str(&format!("(subject.pub_key)\n{}", String::from_utf8(self.subject.pub_key.clone()).unwrap()));
        to_write.push_str(&format!("(cert)\n{}", String::from_utf8(self.cert.clone()).unwrap()));
        to_write.push_str(&format!("[END_CERTIFICATE]\n"));
        write!(f, "{}", to_write)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificationChain(pub Vec<Certificate>);

impl CertificationChain {
    pub fn chain_certifier(&self) -> Option<&Equipment> {
        match self.0.first() {
            Some(certificate) => Some(&certificate.issuer),
            None => None,
        }
    }
    pub fn chain_certified(&self) -> Option<&Equipment> {
        match self.0.last() {
            Some(certificate) => Some(&certificate.subject),
            None => None,
        }
    }
    pub fn is_valid(&self) -> ResultSSL<bool> {
        let mut certified = match self.chain_certifier() {
            Some(certificate) => certificate.clone(),
            None => return Ok(true), // empty chain
        };
        for certificate in self.0.clone() {
            if certified != certificate.issuer {
                return Ok(false);
            }
            if !certificate.is_valid()? {
                return Ok(false);
            }
            certified = certificate.subject.clone();
        }
        Ok(true)
    }
    pub fn get_certificates(&self) -> &Vec<Certificate> {
        &self.0
    }
}

impl Display for CertificationChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut to_write = String::new();
        to_write.push_str(&format!("[CERTIFICATION CHAIN]\n"));
        if let Some(certifier) = self.chain_certifier() { to_write.push_str(&format!("(main_certifier.name) {}\n", certifier.name)); }
        if let Some(certified) = self.chain_certified() { to_write.push_str(&format!("(main_certified.name) {}\n", certified.name)); }
        to_write.push_str(&format!("(is_valid) {}\n", self.is_valid().unwrap()));
        for cert in self.get_certificates() {
            to_write.push_str(&format!("{}\n", cert));
        }
        to_write.push_str(&format!("[END_CERTIFICATION CHAIN]\n"));
        write!(f, "{}", to_write)
    }
}