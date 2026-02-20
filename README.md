# clawsh-proto

<p align="center">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <a href="https://github.com/y0uall/clawsh"><img src="https://img.shields.io/badge/used%20by-clawsh-blue" alt="clawsh"></a>
</p>

Shared wire protocol and cryptography library for the clawsh C2 framework. Used by both the handler ([clawsh](https://github.com/y0uall/clawsh)) and the implant ([clawsh-imp](https://github.com/y0uall/clawsh-imp)).

This library is open source so the protocol and cryptographic design can be audited independently of either implementation.

---

## Wire Format

Every message is framed identically:

```
[4 bytes: payload length (big-endian u32)]
[1 byte:  protocol version]
[1 byte:  message type]
[N bytes: bincode-serialized payload]
```

Maximum frame size: 4 MB (prevents memory exhaustion). Protocol version is checked at handshake time and must match on both sides.

The type byte allows the handler's listener to route incoming connections from the first 6 bytes — agent sessions and raw shell sessions can share the same port.

---

## Cryptography

Two independent layers of encryption:

**Transport (optional)**: TLS via rustls. Not required — the message layer is encrypted regardless.

**Message layer**: X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305. All messages are encrypted even if TLS is stripped or intercepted.

### Key Derivation

```
shared_secret = X25519(my_ephemeral_secret, peer_ephemeral_pubkey)
key_material  = HKDF-SHA256(ikm=shared_secret, info="clawsh-imp-session")
session_key   = key_material[0..32]  →  ChaCha20-Poly1305
```

Both sides generate ephemeral X25519 keypairs per session. Static keys are never used.

### Nonce Scheme

```
[4 bytes: zeros][8 bytes: monotonic counter (big-endian)]
```

The counter is stateful on the writer side. The reader extracts the nonce from the received ciphertext. This means reader and writer keys are fully independent — the session can be split into a `ConnectionReader` and `ConnectionWriter` for concurrent I/O without locking. This is required for the interactive shell, where reads and writes happen simultaneously.

All key material is zeroized on drop via the `zeroize` crate.

### Traffic Padding

Every plaintext message is padded to a minimum of 256 bytes before encryption:

```
[4B real_length (BE)] [plaintext] [random padding to reach 256B minimum]
```

A heartbeat message is ~25–30 bytes. Without padding it would be trivially distinguishable from file transfer traffic by size alone. With padding, the real length is only visible after decryption.

### Authentication

The agent's handshake includes `HMAC-SHA256(AgentInfo, PSK)`. The handler verifies this before completing the handshake. PSK derivation: `SHA256(passphrase)` → `[u8; 32]`. Prevents unauthorized agents from registering with the handler.

---

## Handshake Flow

```
Agent                                   Handler
  |                                        |
  |-- Handshake (plaintext) ------------->|
  |   agent_info, auth_hmac,              |
  |   agent_ephemeral_pubkey              |
  |                                        |
  |<-- HandshakeAck (plaintext) ----------|
  |   session_id, initial_config,         |
  |   handler_ephemeral_pubkey            |
  |                                        |
  | (both sides derive session keys)      |
  |                                        |
  |======= encryption activated ==========|
  |                                        |
  |-- Heartbeat (encrypted) ------------->|
  |<-- HeartbeatAck (encrypted) ----------|
  |                                        |
  | (task / response loop)                |
  |                                        |
  |<-- SelfDestruct (encrypted) ----------|
  |-- SelfDestructAck (encrypted) ------->|
  | (agent cleanup + exit)                |
```

Encryption activates immediately after the handshake exchange — the first heartbeat is already encrypted.

---

## AgentInfo

Sent by the implant inside the `Handshake` message. HMAC-authenticated with PSK.

| Field | Source |
|---|---|
| `version` | Build-time implant version |
| `hostname` | `/proc/sys/kernel/hostname` |
| `os_release` | `/etc/os-release` |
| `kernel` | `uname()` release string |
| `arch` | `uname()` machine string |
| `uid` / `gid` | `getuid()` / `getgid()` |
| `username` | `/etc/passwd` lookup |
| `pid` | `getpid()` |
| `process_name` | `/proc/self/comm` (post-disguise) |
| `exec_capabilities` | `memfd_create`, `/dev/shm` exec, `/tmp` exec, `noexec` mounts |
| `ebpf_detected` | eBPF monitor or active kprobes found at startup |
| `seccomp_mode` | `/proc/self/status` → Disabled / Strict / Filter |

---

## Message Types

25 message types, each with a fixed 1-byte type ID:

### Connection Lifecycle

| Type | ID | Description |
|---|---|---|
| `Handshake` | `0x01` | Agent → Handler. Contains `AgentInfo`, HMAC, ephemeral pubkey. |
| `HandshakeAck` | `0x02` | Handler → Agent. Contains session ID, initial config, ephemeral pubkey. |
| `Heartbeat` | `0x03` | Agent → Handler. Session ID, timestamp, PID, UID, idle seconds. |
| `HeartbeatAck` | `0x04` | Handler → Agent. Timestamp, optional config update piggybacked. |

### Task Execution

| Type | ID | Description |
|---|---|---|
| `TaskRequest` | `0x10` | Handler → Agent. Task ID, required noise level, task variant. |
| `TaskResponse` | `0x11` | Agent → Handler. Task ID, success/failure, stdout/stderr. |
| `TaskOutput` | `0x12` | Agent → Handler. Streaming output (stdout or stderr), `is_final` flag. |

`Task` variants inside `TaskRequest`:

| Variant | Noise | Description |
|---|---|---|
| `Builtin { cmd, args }` | Silent | Built-in syscall-based commands (ls, cat, pwd, …) |
| `ShellExec { command }` | Quiet | Execute shell command |
| `RunModule { name }` | Varies | Run a named recon module |
| `ExecMem { elf_data, args }` | Varies | Execute ELF in memory |
| `InteractiveShell` | Loud | Allocate PTY, enter interactive shell |
| `Persist(PersistRequest)` | Varies | Install/remove/list persistence |
| `StartTunnelMode` | Loud | Enter tunnel relay mode |

### File Transfer

| Type | ID | Description |
|---|---|---|
| `FileUploadStart` | `0x20` | Handler → Agent. File metadata, chunk count, memory-only flag. |
| `FileData` | `0x21` | Chunk payload with CRC32. |
| `FileTransferComplete` | `0x22` | Final SHA256 and success status. |
| `FileDownloadRequest` | `0x23` | Agent → Handler. Remote path, chunk size. |

### Configuration

| Type | ID | Description |
|---|---|---|
| `ConfigUpdate` | `0x30` | Handler → Agent. New `AgentConfig`. |
| `ConfigAck` | `0x31` | Agent → Handler. Applied flag, optional message. |

`AgentConfig` fields: `beacon_interval_secs`, `jitter_percent`, `noise_level`, `max_retry_interval_secs`, `kill_date` (Unix timestamp), `disguise_name`.

### Module Results

| Type | ID | Description |
|---|---|---|
| `ModuleOutput` | `0x40` | Agent → Handler. Structured recon result (9 data variants). |

`ModuleResult` contains: `module`, `noise_level`, `timestamp`, `duration_ms`, `data` (typed), `findings` (severity-rated list).

### Interactive Shell

| Type | ID | Description |
|---|---|---|
| `ShellData` | `0x50` | Bidirectional PTY byte stream. |
| `ShellResize` | `0x51` | Terminal resize event (cols, rows). |
| `ShellClose` | `0x52` | Shell terminated, optional exit code. |

### Tunneling

| Type | ID | Description |
|---|---|---|
| `TunnelOpen` | `0x60` | Handler → Agent. Channel ID, target host, target port. |
| `TunnelData` | `0x61` | Bidirectional relay data. |
| `TunnelClose` | `0x62` | Close channel, optional reason. |
| `TunnelReady` | `0x63` | Agent → Handler. Connection status. |

### Control

| Type | ID | Description |
|---|---|---|
| `SelfDestruct` | `0xF0` | Handler → Agent. Clean persistence, exit. |
| `SelfDestructAck` | `0xF1` | Agent → Handler. Sent before exit. |
| `Error` | `0xFF` | Either direction. Error code, message, optional task ID. |

---

## Noise Levels

Every `TaskRequest` carries a required noise level. The implant's dispatcher rejects tasks that exceed the current session level — enforced in code, not by convention.

```
Silent (0)  Syscall-only reads — /proc, /sys, /etc.
            No sockets, no process spawning, no file writes.

Quiet  (1)  + Network reads, non-sensitive file access.
            Still no process spawning.

Loud   (2)  Unrestricted — process spawning, disk writes, aggressive scanning.
```

The current noise level is part of `AgentConfig` and can be changed at runtime via `ConfigUpdate` or piggybacked on `HeartbeatAck`.

---

## Tech Stack

| Crate | Purpose |
|---|---|
| `x25519-dalek` | X25519 ECDH key exchange |
| `chacha20poly1305` | Authenticated encryption |
| `hkdf` | Key derivation (HKDF-SHA256) |
| `sha2` | SHA-256 |
| `hmac` | HMAC-SHA256 |
| `zeroize` | Wipe key material on drop |
| `bincode` + `serde` | Binary serialization |
| `tokio` | Async I/O traits |

All cryptography uses audited crates from the RustCrypto ecosystem. No custom crypto primitives.

---

## Usage

```toml
[dependencies]
clawsh-proto = { git = "https://github.com/y0uall/clawsh-proto" }
```

See `tests/` for full handshake and encryption roundtrip examples.
