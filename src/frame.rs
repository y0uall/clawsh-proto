use crate::error::ProtoError;
use crate::messages::Message;
use crate::types::MAX_FRAME_SIZE;

/// Wire frame format:
/// ```text
/// [4 bytes: payload length (big-endian u32)]
/// [1 byte:  protocol version]
/// [1 byte:  message type ID]
/// [N bytes: bincode-serialized payload]
/// ```
///
/// Total frame size = 6 + N bytes.
/// Maximum payload size: MAX_FRAME_SIZE.
pub struct Frame;

impl Frame {
    /// Encode a message into a wire frame.
    pub fn encode(msg: &Message) -> Result<Vec<u8>, ProtoError> {
        let payload = bincode::serialize(msg)
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;

        if payload.len() > MAX_FRAME_SIZE {
            return Err(ProtoError::FrameTooLarge {
                size: payload.len(),
                max: MAX_FRAME_SIZE,
            });
        }

        // Total: 4 (length) + 1 (version) + 1 (type) + payload
        let frame_len = 2 + payload.len(); // version + type + payload
        let mut frame = Vec::with_capacity(4 + frame_len);

        // Length prefix (does NOT include the 4 length bytes themselves)
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        // Protocol version
        frame.push(crate::types::PROTOCOL_VERSION);
        // Message type ID
        frame.push(msg.type_id());
        // Serialized payload
        frame.extend_from_slice(&payload);

        Ok(frame)
    }

    /// Decode a wire frame into a message.
    ///
    /// Input `data` must be a complete frame (after reading length prefix).
    /// The first 2 bytes are version + type, rest is payload.
    pub fn decode(data: &[u8]) -> Result<Message, ProtoError> {
        if data.len() < 2 {
            return Err(ProtoError::IncompleteFrame {
                needed: 2,
                have: data.len(),
            });
        }

        let version = data[0];
        if version != crate::types::PROTOCOL_VERSION {
            return Err(ProtoError::VersionMismatch {
                expected: crate::types::PROTOCOL_VERSION,
                got: version,
            });
        }

        let _type_id = data[1]; // Available for routing/filtering before deserialization
        let payload = &data[2..];

        let msg: Message = bincode::deserialize(payload)?;
        Ok(msg)
    }

    /// Read the frame length from a 4-byte big-endian prefix.
    /// Returns None if not enough data.
    pub fn read_length(buf: &[u8]) -> Option<usize> {
        if buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        if len > MAX_FRAME_SIZE {
            return None; // Will be caught as FrameTooLarge during decode
        }

        Some(len)
    }
}

/// Async frame reader/writer for tokio streams.
pub mod async_io {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Read a single framed message from an async stream.
    pub async fn read_message<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<Message, ProtoError> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > MAX_FRAME_SIZE {
            return Err(ProtoError::FrameTooLarge {
                size: frame_len,
                max: MAX_FRAME_SIZE,
            });
        }

        // Read frame body
        let mut body = vec![0u8; frame_len];
        reader.read_exact(&mut body).await?;

        Frame::decode(&body)
    }

    /// Write a single framed message to an async stream.
    pub async fn write_message<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        msg: &Message,
    ) -> Result<(), ProtoError> {
        let frame = Frame::encode(msg)?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Heartbeat;

    #[test]
    fn roundtrip_encode_decode() {
        let msg = Message::Heartbeat(Heartbeat {
            session_id: 42,
            timestamp: 1234567890,
            pid: 1337,
            uid: 1000,
            idle_secs: 5,
        });

        let encoded = Frame::encode(&msg).unwrap();

        // Verify length prefix
        let len = Frame::read_length(&encoded).unwrap();
        assert_eq!(len, encoded.len() - 4);

        // Decode body (skip 4-byte length prefix)
        let decoded = Frame::decode(&encoded[4..]).unwrap();

        assert_eq!(decoded.type_id(), 0x03);
        assert_eq!(decoded.name(), "Heartbeat");
    }

    #[test]
    fn rejects_oversized_frame() {
        let huge = vec![0xFF, 0xFF, 0xFF, 0xFF]; // ~4GB
        assert!(Frame::read_length(&huge).is_none());
    }

    #[test]
    fn rejects_wrong_version() {
        let data = [0xFF, 0x01]; // version 255, type 1
        let result = Frame::decode(&data);
        assert!(matches!(result, Err(ProtoError::VersionMismatch { .. })));
    }
}
