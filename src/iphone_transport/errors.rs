// Jackson Coxson

/// Errors specific to remote pairing operations
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum RemotePairingError {
    #[error("Unknown TLV: {0}")]
    UnknownTlv(u8),
    #[error("Malformed TLV")]
    MalformedTlv,
    #[error("Pairing rejected: {0}")]
    PairingRejected(String),
    #[error("Base64 decode error")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Pair verify failed")]
    PairVerifyFailed,
    #[error("SRP auth failed")]
    SrpAuthFailed,
    #[error("Chacha encryption error")]
    ChachaEncryption(chacha20poly1305::Error),
}

impl RemotePairingError {
    pub fn sub_code(&self) -> i32 {
        match self {
            Self::UnknownTlv(_) => 1,
            Self::MalformedTlv => 2,
            Self::PairingRejected(_) => 3,
            Self::Base64DecodeError(_) => 4,
            Self::PairVerifyFailed => 5,
            Self::SrpAuthFailed => 6,
            Self::ChachaEncryption(_) => 7,
        }
    }
}

impl From<RemotePairingError> for idevice::IdeviceError {
    fn from(_: RemotePairingError) -> Self {
        Self::UnexpectedResponse("remote pairing failed".into())
    }
}
