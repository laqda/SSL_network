use serde::{Serialize, Deserialize};

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
pub struct Refuse {} // sender do not possess a certification chain, User NOT OK to add receiver

#[derive(Serialize, Deserialize, Debug)]
pub struct Connected {} // sender acknowledge the connection process
