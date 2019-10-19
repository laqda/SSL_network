extern crate failure;

#[derive(Debug, Fail)]
pub enum SSLNetworkError {
    #[fail(display = "[ERROR] invalid port : {}", port)]
    InvalidPort {
        port: String,
    },
}