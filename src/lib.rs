// clawsh-proto — Shared protocol between handler and implants
//
// This crate defines the wire protocol, message types, framing,
// and crypto layer shared by clawsh (handler) and all implants.

pub mod crypto;
pub mod error;
pub mod frame;
pub mod messages;
pub mod noise;
pub mod types;

pub use error::ProtoError;
pub use frame::Frame;
pub use messages::Message;
pub use noise::NoiseLevel;
pub use types::*;
