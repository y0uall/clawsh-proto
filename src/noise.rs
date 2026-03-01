use serde::{Deserialize, Serialize};
use std::fmt;

/// Operational noise level — determines which code paths are allowed.
///
/// This is not just a label. The agent enforces noise level restrictions
/// at the syscall/operation layer. A Silent operation that tries to spawn
/// a process will be rejected before execution.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NoiseLevel {
    /// Passive only — reads from /proc, /sys, /etc.
    /// No sockets opened, no processes spawned, no files written.
    #[default]
    Silent = 0,

    /// Adds network reads, non-sensitive file access.
    /// Still no process spawning.
    Quiet = 1,

    /// All restrictions lifted. Process spawning, disk writes,
    /// aggressive scanning. Operator explicitly acknowledges OPSEC cost.
    Loud = 2,
}

impl NoiseLevel {
    /// Check if an operation at `required` level is permitted
    /// under the current noise level.
    pub fn permits(&self, required: NoiseLevel) -> bool {
        *self >= required
    }
}

impl fmt::Display for NoiseLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseLevel::Silent => write!(f, "silent"),
            NoiseLevel::Quiet => write!(f, "quiet"),
            NoiseLevel::Loud => write!(f, "loud"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_level_ordering() {
        assert!(NoiseLevel::Loud.permits(NoiseLevel::Silent));
        assert!(NoiseLevel::Loud.permits(NoiseLevel::Quiet));
        assert!(NoiseLevel::Quiet.permits(NoiseLevel::Silent));
        assert!(!NoiseLevel::Silent.permits(NoiseLevel::Quiet));
        assert!(!NoiseLevel::Silent.permits(NoiseLevel::Loud));
        assert!(!NoiseLevel::Quiet.permits(NoiseLevel::Loud));
    }
}
