extern crate failure;

#[derive(Debug, Fail)]
pub enum SSLNetworkError {
    #[fail(display = "[ERROR] invalid port : {}", port)]
    InvalidPort {
        port: String,
    },
    #[fail(display = "[ERROR] fail during equipment creation because self certificate was not valid")]
    EquipmentCreationFailInvalidSelfCertificate {},
    #[fail(display = "[ERROR] invalid address : {}", address)]
    InvalidAddress {
        address: String,
    },
    #[fail(display = "[ERROR] process violation")]
    ConnectionProcessViolation {},
    #[fail(display = "[ERROR] connection refused")]
    ConnectionRefused {},
    #[fail(display = "[ERROR] connection loss")]
    NoConnection {},
}