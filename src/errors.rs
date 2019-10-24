extern crate failure;

#[derive(Debug, Fail)]
pub enum SSLNetworkError {
    #[fail(display = "[ERROR] Invalid port : {}", port)]
    InvalidPort {
        port: String,
    },
    #[fail(display = "[ERROR] Fail during equipment creation because self certificate was not valid")]
    EquipmentCreationFailInvalidSelfCertificate {},
    #[fail(display = "[ERROR] Invalid address : {}", address)]
    InvalidAddress {
        address: String,
    },
    #[fail(display = "[ERROR] Process violation")]
    ConnectionProtocolViolation {},
    #[fail(display = "[ERROR] Connection refused")]
    ConnectionRefused {},
    #[fail(display = "[ERROR] Connection loss")]
    NoConnection {},
    #[fail(display = "[ERROR] Invalid payload")]
    InvalidPayload {},
    #[fail(display = "[ERROR] Invalid signature")]
    InvalidSignature {},
}