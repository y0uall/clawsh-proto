use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    #[error("invalid message type: 0x{0:02X}")]
    InvalidMessageType(u8),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("incomplete frame: need {needed} bytes, have {have}")]
    IncompleteFrame { needed: usize, have: usize },

    #[error("protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("checksum mismatch")]
    ChecksumMismatch,
}

impl From<bincode::Error> for ProtoError {
    fn from(e: bincode::Error) -> Self {
        ProtoError::Deserialization(e.to_string())
    }
}
