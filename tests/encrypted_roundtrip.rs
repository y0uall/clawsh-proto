//! Integration test: full handshake + encrypted message roundtrip.
//!
//! Simulates both sides of a connection using tokio::io::duplex(),
//! performing the complete handshake and encrypted message exchange.

use clawsh_proto::crypto::{self, KeyPair};
use clawsh_proto::frame::{async_io, Frame};
use clawsh_proto::messages::*;
use clawsh_proto::types::MAX_FRAME_SIZE;
use clawsh_proto::{AgentConfig, AgentInfo, ExecCapabilitiesReport, Message, Psk, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper: write an encrypted message to a stream.
async fn write_encrypted<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &Message,
    enc_key: &mut clawsh_proto::crypto::SessionEncryptKey,
) {
    let frame = Frame::encode(msg).unwrap();
    let body = &frame[4..];
    let encrypted = enc_key.encrypt(body).unwrap();
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await.unwrap();
    writer.write_all(&encrypted).await.unwrap();
    writer.flush().await.unwrap();
}

/// Helper: read and decrypt a message from a stream.
async fn read_encrypted<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    dec_key: &clawsh_proto::crypto::SessionDecryptKey,
) -> Message {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.unwrap();
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    assert!(frame_len <= MAX_FRAME_SIZE);

    let mut encrypted = vec![0u8; frame_len];
    reader.read_exact(&mut encrypted).await.unwrap();

    let body = dec_key.decrypt(&encrypted).unwrap();
    Frame::decode(&body).unwrap()
}

fn make_test_agent_info() -> AgentInfo {
    AgentInfo {
        version: "0.1.0".into(),
        hostname: "test-host".into(),
        os_release: "TestOS 1.0".into(),
        kernel: "6.0.0-test".into(),
        arch: "x86_64".into(),
        uid: 1000,
        gid: 1000,
        username: "tester".into(),
        pid: 12345,
        process_name: "[kworker/0:1]".into(),
        exec_capabilities: ExecCapabilitiesReport {
            memfd_create: true,
            shm_exec: true,
            tmp_exec: true,
            noexec_mounts: vec![],
        },
        ebpf_detected: false,
        seccomp_mode: 0,
    }
}

#[tokio::test]
async fn full_handshake_then_encrypted_heartbeat() {
    // Create a bidirectional pipe
    let (agent_stream, handler_stream) = tokio::io::duplex(8192);
    let (mut agent_read, mut agent_write) = tokio::io::split(agent_stream);
    let (mut handler_read, mut handler_write) = tokio::io::split(handler_stream);

    let psk = Psk::from_passphrase("test-integration-key");

    // === Step 1: Agent sends Handshake (plaintext) ===
    let agent_kp = KeyPair::generate();
    let agent_pubkey = agent_kp.public_bytes();

    let agent_info = make_test_agent_info();
    let info_bytes = bincode::serialize(&agent_info).unwrap();
    let auth_hmac = crypto::compute_auth_hmac(&info_bytes, &psk);

    let handshake_msg = Message::Handshake(Handshake {
        protocol_version: PROTOCOL_VERSION,
        agent_info: agent_info.clone(),
        auth_hmac,
        ephemeral_pubkey: agent_pubkey,
    });
    async_io::write_message(&mut agent_write, &handshake_msg).await.unwrap();

    // === Step 2: Handler reads Handshake, sends HandshakeAck (plaintext) ===
    let received = async_io::read_message(&mut handler_read).await.unwrap();
    let handshake = match received {
        Message::Handshake(h) => h,
        other => panic!("expected Handshake, got {:?}", other.name()),
    };

    // Verify HMAC
    let recv_info_bytes = bincode::serialize(&handshake.agent_info).unwrap();
    assert!(crypto::verify_auth_hmac(&recv_info_bytes, &handshake.auth_hmac, &psk));

    let handler_kp = KeyPair::generate();
    let handler_pubkey = handler_kp.public_bytes();
    let session_id: u32 = 42;

    let ack_msg = Message::HandshakeAck(HandshakeAck {
        session_id,
        config: AgentConfig::default(),
        ephemeral_pubkey: handler_pubkey,
    });
    async_io::write_message(&mut handler_write, &ack_msg).await.unwrap();

    // === Step 3: Both sides derive session keys ===
    let (mut agent_enc, agent_dec) = agent_kp.derive_session_keys(&handler_pubkey);
    let (mut handler_enc, handler_dec) = handler_kp.derive_session_keys(&agent_pubkey);

    // === Step 4: Agent reads HandshakeAck (plaintext) ===
    let ack_received = async_io::read_message(&mut agent_read).await.unwrap();
    match ack_received {
        Message::HandshakeAck(ack) => {
            assert_eq!(ack.session_id, 42);
        }
        other => panic!("expected HandshakeAck, got {:?}", other.name()),
    }

    // === Step 5: Agent sends encrypted Heartbeat ===
    let heartbeat = Message::Heartbeat(Heartbeat {
        session_id,
        timestamp: 1700000000,
        pid: 12345,
        uid: 1000,
        idle_secs: 0,
    });
    write_encrypted(&mut agent_write, &heartbeat, &mut agent_enc).await;

    // === Step 6: Handler decrypts Heartbeat ===
    let decrypted_hb = read_encrypted(&mut handler_read, &handler_dec).await;
    match decrypted_hb {
        Message::Heartbeat(hb) => {
            assert_eq!(hb.session_id, session_id);
            assert_eq!(hb.timestamp, 1700000000);
            assert_eq!(hb.pid, 12345);
            assert_eq!(hb.uid, 1000);
        }
        other => panic!("expected Heartbeat, got {:?}", other.name()),
    }

    // === Step 7: Handler sends encrypted HeartbeatAck ===
    let hb_ack = Message::HeartbeatAck(HeartbeatAck {
        timestamp: 1700000001,
        config_update: None,
    });
    write_encrypted(&mut handler_write, &hb_ack, &mut handler_enc).await;

    // === Step 8: Agent decrypts HeartbeatAck ===
    let decrypted_ack = read_encrypted(&mut agent_read, &agent_dec).await;
    match decrypted_ack {
        Message::HeartbeatAck(ack) => {
            assert_eq!(ack.timestamp, 1700000001);
            assert!(ack.config_update.is_none());
        }
        other => panic!("expected HeartbeatAck, got {:?}", other.name()),
    }
}

#[tokio::test]
async fn encrypted_multiple_messages_nonce_advances() {
    let (agent_stream, handler_stream) = tokio::io::duplex(8192);
    let (mut agent_read, mut agent_write) = tokio::io::split(agent_stream);
    let (mut handler_read, mut handler_write) = tokio::io::split(handler_stream);

    let agent_kp = KeyPair::generate();
    let handler_kp = KeyPair::generate();
    let agent_pub = agent_kp.public_bytes();
    let handler_pub = handler_kp.public_bytes();

    let (mut agent_enc, agent_dec) = agent_kp.derive_session_keys(&handler_pub);
    let (mut handler_enc, handler_dec) = handler_kp.derive_session_keys(&agent_pub);

    // Send multiple messages from agent to handler
    for i in 0..5u64 {
        let msg = Message::Heartbeat(Heartbeat {
            session_id: 1,
            timestamp: 1000 + i,
            pid: 1,
            uid: 1,
            idle_secs: i,
        });
        write_encrypted(&mut agent_write, &msg, &mut agent_enc).await;
    }

    // Handler decrypts all
    for i in 0..5u64 {
        let decrypted = read_encrypted(&mut handler_read, &handler_dec).await;
        match decrypted {
            Message::Heartbeat(hb) => {
                assert_eq!(hb.timestamp, 1000 + i);
                assert_eq!(hb.idle_secs, i);
            }
            other => panic!("expected Heartbeat, got {:?}", other.name()),
        }
    }

    // Send multiple messages from handler to agent
    for i in 0..3u64 {
        let msg = Message::HeartbeatAck(HeartbeatAck {
            timestamp: 2000 + i,
            config_update: None,
        });
        write_encrypted(&mut handler_write, &msg, &mut handler_enc).await;
    }

    for i in 0..3u64 {
        let decrypted = read_encrypted(&mut agent_read, &agent_dec).await;
        match decrypted {
            Message::HeartbeatAck(ack) => {
                assert_eq!(ack.timestamp, 2000 + i);
            }
            other => panic!("expected HeartbeatAck, got {:?}", other.name()),
        }
    }
}

#[tokio::test]
async fn wrong_key_fails_decryption() {
    // Create two unrelated key pairs (not from same DH exchange)
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let kp3 = KeyPair::generate();

    let pub2 = kp2.public_bytes();

    // Agent encrypts with kp1<->kp2 derived key
    let (mut enc_key, _) = kp1.derive_session_keys(&pub2);

    // "Wrong handler" tries to decrypt with kp3<->kp2 derived key
    let (_, wrong_dec_key) = kp3.derive_session_keys(&pub2);

    let msg = Message::Heartbeat(Heartbeat {
        session_id: 1,
        timestamp: 999,
        pid: 1,
        uid: 1,
        idle_secs: 0,
    });

    let frame = Frame::encode(&msg).unwrap();
    let body = &frame[4..];
    let encrypted = enc_key.encrypt(body).unwrap();

    // Decryption with wrong key should fail
    let result = wrong_dec_key.decrypt(&encrypted);
    assert!(result.is_err(), "decryption with wrong key should fail");
}
