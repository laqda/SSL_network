extern crate failure;

// custom result type
pub type ResultSSL<T> = Result<T, SSLNetworkError>;

#[derive(Debug, Fail)]
pub enum SSLNetworkError {
    #[fail(display = "[ERROR] Invalid port : {}", port)]
    InvalidPort {
        port: String,
    },
    #[fail(display = "[ERROR] Invalid address : {}", address)]
    InvalidAddress {
        address: String,
    },
    #[fail(display = "[ERROR] Process violation")]
    ProtocolViolation {},
    #[fail(display = "[ERROR] Refuse")]
    Refused {},
    #[fail(display = "[ERROR] Connection loss")]
    NoConnection {},
    #[fail(display = "[ERROR] Invalid payload")]
    InvalidPayload {},
    #[fail(display = "[ERROR] Invalid signature")]
    InvalidSignature {},
    #[fail(display = "[ERROR] Invalid certificate format")]
    InvalidCertificateFormat {},
    #[fail(display = "[ERROR] Invalid public key format")]
    InvalidPublicKeyFormat {},
    #[fail(display = "[ERROR] Invalid certificate")]
    InvalidCertificate {},
    #[fail(display = "[ERROR] Equipment not found")]
    EquipmentNotFound {},
    #[fail(display = "[ERROR] Certificate not found")]
    CertificateNotFound {},
}