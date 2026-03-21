//! Bincode serialization roundtrip tests for all ModuleData variants.

use clawsh_proto::types::*;
use clawsh_proto::NoiseLevel;

fn roundtrip(result: &ModuleResult) -> ModuleResult {
    let bytes = bincode::serialize(result).expect("serialize failed");
    bincode::deserialize(&bytes).expect("deserialize failed")
}

fn make_result(module: &str, data: ModuleData) -> ModuleResult {
    ModuleResult {
        module: module.to_string(),
        noise_level: NoiseLevel::Silent,
        timestamp: 1700000000,
        duration_ms: 42,
        data,
        findings: vec![
            Finding {
                severity: Severity::High,
                category: FindingCategory::PrivEsc,
                title: "Test finding".into(),
                detail: "Details here".into(),
            },
        ],
    }
}

#[test]
fn roundtrip_sysinfo() {
    let data = ModuleData::Sysinfo(SysinfoData {
        hostname: "testhost".into(),
        os: "Linux".into(),
        kernel: "6.1.0".into(),
        arch: "x86_64".into(),
        cpu_model: "Intel i7".into(),
        cpu_cores: 8,
        mem_total: "16 GB".into(),
        mem_available: "8 GB".into(),
        uptime_secs: 3600,
        container_type: Some("docker".into()),
    });
    let result = make_result("sysinfo", data);
    let decoded = roundtrip(&result);
    assert_eq!(decoded.module, "sysinfo");
    assert!(matches!(decoded.data, ModuleData::Sysinfo(_)));
    assert_eq!(decoded.findings.len(), 1);
}

#[test]
fn roundtrip_users() {
    let data = ModuleData::Users(UsersData {
        current_uid: 1000,
        current_gid: 1000,
        current_euid: 0,
        current_username: "user".into(),
        login_users: vec![LoginUser {
            username: "root".into(),
            uid: 0,
            home: "/root".into(),
            shell: "/bin/bash".into(),
        }],
        sudoers_rules: vec!["user ALL=(ALL) NOPASSWD: ALL".into()],
        active_sessions: vec![ActiveSession {
            pid: 1234,
            username: "user".into(),
            process_name: "bash".into(),
        }],
    });
    let result = make_result("users", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Users(u) = &decoded.data {
        assert_eq!(u.current_uid, 1000);
        assert_eq!(u.login_users.len(), 1);
    } else {
        panic!("expected Users variant");
    }
}

#[test]
fn roundtrip_network() {
    let data = ModuleData::Network(NetworkData {
        interfaces: vec![NetworkInterface {
            name: "eth0".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            state: "UP".into(),
            mtu: "1500".into(),
        }],
        listening_ports: vec![PortInfo {
            addr: "0.0.0.0".into(),
            port: 22,
            uid: 0,
            username: "root".into(),
        }],
        established: vec![],
        routes: vec![RouteInfo {
            iface: "eth0".into(),
            destination: "0.0.0.0".into(),
            gateway: "10.0.0.1".into(),
            mask: "0.0.0.0".into(),
        }],
        dns_servers: vec!["8.8.8.8".into()],
        arp_entries: vec![ArpEntry {
            ip: "10.0.0.1".into(),
            mac: "00:11:22:33:44:55".into(),
            device: "eth0".into(),
        }],
    });
    let result = make_result("network", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Network(n) = &decoded.data {
        assert_eq!(n.interfaces.len(), 1);
        assert_eq!(n.listening_ports[0].port, 22);
    } else {
        panic!("expected Network variant");
    }
}

#[test]
fn roundtrip_processes() {
    let data = ModuleData::Processes(ProcessesData {
        total_count: 100,
        processes: vec![ProcessEntry {
            pid: 1,
            ppid: 0,
            uid: 0,
            name: "systemd".into(),
            cmdline: "/sbin/init".into(),
        }],
        interesting: vec![],
        security_tools: vec![InterestingProcess {
            pid: 500,
            name: "auditd".into(),
            cmdline: "/sbin/auditd".into(),
            username: "root".into(),
            description: "Linux Audit Daemon".into(),
        }],
    });
    let result = make_result("processes", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Processes(p) = &decoded.data {
        assert_eq!(p.total_count, 100);
        assert_eq!(p.security_tools.len(), 1);
    } else {
        panic!("expected Processes variant");
    }
}

#[test]
fn roundtrip_filesystem() {
    let data = ModuleData::Filesystem(FilesystemData {
        mounts: vec![MountInfo {
            device: "/dev/sda1".into(),
            mountpoint: "/".into(),
            fstype: "ext4".into(),
            options: "rw,relatime".into(),
        }],
        suid_files: vec![SuidFile {
            path: "/usr/bin/sudo".into(),
            owner_uid: 0,
            mode: 0o4755,
        }],
        sgid_files: vec![],
        writable_dirs: vec!["/tmp".into()],
        interesting_files: vec![InterestingFile {
            path: "/etc/shadow".into(),
            readable: true,
            description: "Shadow password file".into(),
        }],
        capabilities: CapabilityInfo {
            effective: "0000000000000000".into(),
            permitted: "0000000000000000".into(),
            bounding: "000001ffffffffff".into(),
        },
    });
    let result = make_result("filesystem", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Filesystem(f) = &decoded.data {
        assert_eq!(f.suid_files.len(), 1);
        assert!(f.interesting_files[0].readable);
    } else {
        panic!("expected Filesystem variant");
    }
}

#[test]
fn roundtrip_container_detect() {
    let data = ModuleData::ContainerDetect(ContainerData {
        container_type: Some("docker".into()),
        evidence: vec!["/.dockerenv exists".into()],
        k8s_info: Some(K8sInfo {
            namespace: "default".into(),
            service_account: "default".into(),
            token_present: true,
            ca_cert_present: true,
        }),
        namespaces: vec![NamespaceInfo {
            ns_type: "pid".into(),
            self_inode: "4026532198".into(),
            init_inode: "4026531836".into(),
            shared: false,
        }],
        escape_vectors: vec![EscapeVector {
            name: "Docker Socket".into(),
            description: "/var/run/docker.sock is accessible".into(),
            severity: Severity::Critical,
        }],
    });
    let result = make_result("container", data);
    let decoded = roundtrip(&result);
    if let ModuleData::ContainerDetect(c) = &decoded.data {
        assert_eq!(c.container_type, Some("docker".into()));
        assert_eq!(c.escape_vectors.len(), 1);
    } else {
        panic!("expected ContainerDetect variant");
    }
}

#[test]
fn roundtrip_credentials() {
    let data = ModuleData::Credentials(CredentialsData {
        shadow_entries: vec![ShadowEntry {
            username: "root".into(),
            hash_type: "SHA-512".into(),
            has_password: true,
        }],
        ssh_keys: vec![SshKeyInfo {
            path: "/root/.ssh/id_rsa".into(),
            key_type: "RSA".into(),
            encrypted: false,
            owner_uid: 0,
        }],
        history_secrets: vec![HistorySecret {
            file: "/root/.bash_history".into(),
            line: "mysql -u root -psecret".into(),
            pattern: "password".into(),
        }],
        env_secrets: vec![EnvSecret {
            key: "AWS_SECRET_ACCESS_KEY".into(),
            value_preview: "AKIA...".into(),
        }],
        cloud_creds: vec![CloudCredential {
            provider: "AWS".into(),
            path: "/root/.aws/credentials".into(),
            credential_type: "credentials file".into(),
        }],
    });
    let result = make_result("credentials", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Credentials(c) = &decoded.data {
        assert_eq!(c.shadow_entries.len(), 1);
        assert!(!c.ssh_keys[0].encrypted);
    } else {
        panic!("expected Credentials variant");
    }
}

#[test]
fn roundtrip_privesc() {
    let data = ModuleData::PrivEsc(PrivEscData {
        kernel_version: "6.1.52-generic".into(),
        kernel_cves: vec![KernelCve {
            cve: "CVE-2023-3269".into(),
            name: "StackRot".into(),
            affected_range: "6.1.0 – 6.4.1".into(),
        }],
        sudo_vectors: vec![SudoVector {
            rule: "user ALL=(ALL) NOPASSWD: /usr/bin/vim".into(),
            vector: "NOPASSWD".into(),
        }],
        writable_path_dirs: vec!["/usr/local/bin".into()],
        cron_vectors: vec![CronVector {
            cron_file: "/etc/crontab".into(),
            script_path: "/opt/backup.sh".into(),
            writable: true,
            wildcard: false,
        }],
        group_vectors: vec![GroupVector {
            group_name: "docker".into(),
            gid: 999,
            exploit: "docker run -v /:/mnt alpine".into(),
        }],
        writable_sensitive: vec![WritableSensitive {
            path: "/etc/passwd".into(),
            impact: "add root-equivalent user".into(),
        }],
    });
    let result = make_result("privesc", data);
    let decoded = roundtrip(&result);
    if let ModuleData::PrivEsc(p) = &decoded.data {
        assert_eq!(p.kernel_version, "6.1.52-generic");
        assert_eq!(p.kernel_cves.len(), 1);
        assert_eq!(p.kernel_cves[0].name, "StackRot");
        assert_eq!(p.sudo_vectors.len(), 1);
        assert!(p.cron_vectors[0].writable);
        assert_eq!(p.group_vectors[0].group_name, "docker");
    } else {
        panic!("expected PrivEsc variant");
    }
}

#[test]
fn roundtrip_harvest() {
    let data = ModuleData::Harvest(HarvestData {
        db_credentials: vec![DbCredential {
            db_type: "mysql".into(),
            path: "/etc/mysql/debian.cnf".into(),
            username: Some("root".into()),
            has_password: true,
        }],
        web_configs: vec![WebConfig {
            path: "/var/www/app/.env".into(),
            config_type: "dotenv".into(),
            secrets_found: vec!["DB_PASSWORD".into(), "API_KEY".into()],
        }],
        service_tokens: vec![ServiceToken {
            service: "kubernetes".into(),
            path: "/var/run/secrets/kubernetes.io/serviceaccount/token".into(),
            token_preview: "eyJhbGci...".into(),
        }],
        app_credentials: vec![AppCredential {
            app: "firefox".into(),
            path: "/home/user/.mozilla/firefox/abc.default/logins.json".into(),
            credential_type: "login_db".into(),
        }],
        network_credentials: vec![NetworkCredential {
            service: "openvpn".into(),
            path: "/etc/openvpn/client.conf".into(),
            has_password: true,
        }],
    });
    let result = make_result("harvest", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Harvest(h) = &decoded.data {
        assert_eq!(h.db_credentials.len(), 1);
        assert_eq!(h.db_credentials[0].db_type, "mysql");
        assert!(h.db_credentials[0].has_password);
        assert_eq!(h.web_configs[0].secrets_found.len(), 2);
        assert_eq!(h.service_tokens[0].service, "kubernetes");
        assert_eq!(h.app_credentials[0].app, "firefox");
        assert!(h.network_credentials[0].has_password);
    } else {
        panic!("expected Harvest variant");
    }
}

#[test]
fn roundtrip_raw() {
    let data = ModuleData::Raw(b"raw binary data here".to_vec());
    let result = make_result("custom", data);
    let decoded = roundtrip(&result);
    if let ModuleData::Raw(bytes) = &decoded.data {
        assert_eq!(bytes, b"raw binary data here");
    } else {
        panic!("expected Raw variant");
    }
}

#[test]
fn roundtrip_all_severities() {
    let findings = vec![
        Finding { severity: Severity::Critical, category: FindingCategory::PrivEsc, title: "a".into(), detail: "".into() },
        Finding { severity: Severity::High, category: FindingCategory::Credential, title: "b".into(), detail: "".into() },
        Finding { severity: Severity::Medium, category: FindingCategory::Misconfiguration, title: "c".into(), detail: "".into() },
        Finding { severity: Severity::Low, category: FindingCategory::Container, title: "d".into(), detail: "".into() },
        Finding { severity: Severity::Info, category: FindingCategory::Network, title: "e".into(), detail: "".into() },
    ];
    let result = ModuleResult {
        module: "test".into(),
        noise_level: NoiseLevel::Loud,
        timestamp: 0,
        duration_ms: 0,
        data: ModuleData::Raw(vec![]),
        findings,
    };
    let decoded = roundtrip(&result);
    assert_eq!(decoded.findings.len(), 5);
    assert_eq!(decoded.findings[0].severity, Severity::Critical);
    assert_eq!(decoded.findings[4].category, FindingCategory::Network);
}
