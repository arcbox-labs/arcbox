use super::*;

#[test]
fn test_parse_minimal_spec() {
    let json = r#"{
        "ociVersion": "1.2.0"
    }"#;

    let spec = Spec::from_json(json).unwrap();
    assert_eq!(spec.oci_version, "1.2.0");
    assert!(spec.root.is_none());
    assert!(spec.process.is_none());
}

#[test]
fn test_parse_spec_with_root() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "root": {
            "path": "rootfs",
            "readonly": true
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let root = spec.root.unwrap();
    assert_eq!(root.path, "rootfs");
    assert!(root.readonly);
}

#[test]
fn test_parse_spec_with_process() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "terminal": true,
            "cwd": "/app",
            "args": ["./start.sh"],
            "env": ["PATH=/usr/bin", "HOME=/root"]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let process = spec.process.unwrap();
    assert!(process.terminal);
    assert_eq!(process.cwd, "/app");
    assert_eq!(process.args, vec!["./start.sh"]);
    assert_eq!(process.env.len(), 2);
}

#[test]
fn test_invalid_cwd() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": "relative/path"
        }
    }"#;

    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_default_linux_spec() {
    let spec = Spec::default_linux();
    assert_eq!(spec.oci_version, OCI_VERSION);
    assert!(spec.root.is_some());
    assert!(spec.process.is_some());
    assert!(!spec.mounts.is_empty());
    assert!(spec.linux.is_some());
}

#[test]
fn test_serialize_roundtrip() {
    let spec = Spec::default_linux();
    let json = spec.to_json().unwrap();
    let parsed = Spec::from_json(&json).unwrap();
    assert_eq!(spec.oci_version, parsed.oci_version);
}

#[test]
fn test_invalid_oci_version_empty() {
    let json = r#"{
        "ociVersion": ""
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_invalid_oci_version_format() {
    let json = r#"{
        "ociVersion": "invalid"
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_empty_root_path() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "root": {
            "path": ""
        }
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_empty_process_cwd() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": ""
        }
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_invalid_mount_destination_relative() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "mounts": [
            {
                "destination": "relative/path",
                "source": "/source"
            }
        ]
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_invalid_mount_destination_empty() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "mounts": [
            {
                "destination": "",
                "source": "/source"
            }
        ]
    }"#;
    let result = Spec::from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_parse_mounts() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"]
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755"]
            }
        ]
    }"#;

    let spec = Spec::from_json(json).unwrap();
    assert_eq!(spec.mounts.len(), 2);
    assert_eq!(spec.mounts[0].destination, "/proc");
    assert_eq!(spec.mounts[0].mount_type, Some("proc".to_string()));
    assert_eq!(spec.mounts[0].options.as_ref().unwrap().len(), 3);
}

#[test]
fn test_parse_linux_namespaces() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network"},
                {"type": "mount"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
                {"type": "cgroup"}
            ]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let linux = spec.linux.unwrap();
    assert_eq!(linux.namespaces.len(), 7);
    assert_eq!(linux.namespaces[0].ns_type, NamespaceType::Pid);
    assert_eq!(linux.namespaces[1].ns_type, NamespaceType::Network);
}

#[test]
fn test_parse_linux_resources_memory() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "resources": {
                "memory": {
                    "limit": 536870912,
                    "reservation": 268435456,
                    "swap": 1073741824,
                    "swappiness": 60
                }
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let resources = spec.linux.unwrap().resources.unwrap();
    let memory = resources.memory.unwrap();
    assert_eq!(memory.limit, Some(536_870_912));
    assert_eq!(memory.reservation, Some(268_435_456));
    assert_eq!(memory.swap, Some(1_073_741_824));
    assert_eq!(memory.swappiness, Some(60));
}

#[test]
fn test_parse_linux_resources_cpu() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "resources": {
                "cpu": {
                    "shares": 1024,
                    "quota": 100000,
                    "period": 100000,
                    "cpus": "0-3",
                    "mems": "0"
                }
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let resources = spec.linux.unwrap().resources.unwrap();
    let cpu = resources.cpu.unwrap();
    assert_eq!(cpu.shares, Some(1024));
    assert_eq!(cpu.quota, Some(100_000));
    assert_eq!(cpu.period, Some(100_000));
    assert_eq!(cpu.cpus, Some("0-3".to_string()));
    assert_eq!(cpu.mems, Some("0".to_string()));
}

#[test]
fn test_parse_linux_resources_pids() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "resources": {
                "pids": {
                    "limit": 1024
                }
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let resources = spec.linux.unwrap().resources.unwrap();
    let pids = resources.pids.unwrap();
    assert_eq!(pids.limit, 1024);
}

#[test]
fn test_parse_linux_devices() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "devices": [
                {
                    "type": "c",
                    "path": "/dev/null",
                    "major": 1,
                    "minor": 3,
                    "fileMode": 438,
                    "uid": 0,
                    "gid": 0
                }
            ]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let linux = spec.linux.unwrap();
    assert_eq!(linux.devices.len(), 1);
    assert_eq!(linux.devices[0].device_type, "c");
    assert_eq!(linux.devices[0].path, "/dev/null");
    assert_eq!(linux.devices[0].major, Some(1));
    assert_eq!(linux.devices[0].minor, Some(3));
}

#[test]
fn test_parse_capabilities() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": "/",
            "capabilities": {
                "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
                "effective": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                "inheritable": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL"],
                "ambient": ["CAP_AUDIT_WRITE"]
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let caps = spec.process.unwrap().capabilities.unwrap();
    assert_eq!(caps.bounding.len(), 3);
    assert_eq!(caps.effective.len(), 2);
    assert_eq!(caps.inheritable.len(), 2);
    assert_eq!(caps.permitted.len(), 2);
    assert_eq!(caps.ambient.len(), 1);
}

#[test]
fn test_parse_user() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": "/",
            "user": {
                "uid": 1000,
                "gid": 1000,
                "umask": 18,
                "additionalGids": [100, 200, 300]
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let user = spec.process.unwrap().user.unwrap();
    assert_eq!(user.uid, 1000);
    assert_eq!(user.gid, 1000);
    assert_eq!(user.umask, Some(18));
    assert_eq!(user.additional_gids, vec![100, 200, 300]);
}

#[test]
fn test_parse_rlimits() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": "/",
            "rlimits": [
                {
                    "type": "RLIMIT_NOFILE",
                    "soft": 1024,
                    "hard": 4096
                },
                {
                    "type": "RLIMIT_NPROC",
                    "soft": 512,
                    "hard": 1024
                }
            ]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let rlimits = spec.process.unwrap().rlimits;
    assert_eq!(rlimits.len(), 2);
    assert_eq!(rlimits[0].rlimit_type, "RLIMIT_NOFILE");
    assert_eq!(rlimits[0].soft, 1024);
    assert_eq!(rlimits[0].hard, 4096);
}

#[test]
fn test_parse_seccomp() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "seccomp": {
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 1,
                "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"],
                "syscalls": [
                    {
                        "names": ["read", "write", "exit"],
                        "action": "SCMP_ACT_ALLOW"
                    }
                ]
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let seccomp = spec.linux.unwrap().seccomp.unwrap();
    assert_eq!(seccomp.default_action, "SCMP_ACT_ERRNO");
    assert_eq!(seccomp.default_errno_ret, Some(1));
    assert_eq!(seccomp.architectures.len(), 2);
    assert_eq!(seccomp.syscalls.len(), 1);
    assert_eq!(seccomp.syscalls[0].names, vec!["read", "write", "exit"]);
}

#[test]
fn test_parse_annotations() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "annotations": {
            "org.opencontainers.image.os": "linux",
            "org.opencontainers.image.architecture": "amd64",
            "custom.key": "custom.value"
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    assert_eq!(spec.annotations.len(), 3);
    assert_eq!(
        spec.annotations.get("org.opencontainers.image.os"),
        Some(&"linux".to_string())
    );
}

#[test]
fn test_parse_hostname_and_domainname() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "hostname": "test-container",
        "domainname": "example.com"
    }"#;

    let spec = Spec::from_json(json).unwrap();
    assert_eq!(spec.hostname, Some("test-container".to_string()));
    assert_eq!(spec.domainname, Some("example.com".to_string()));
}

#[test]
fn test_parse_console_size() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {
            "cwd": "/",
            "terminal": true,
            "consoleSize": {
                "height": 24,
                "width": 80
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let process = spec.process.unwrap();
    assert!(process.terminal);
    let size = process.console_size.unwrap();
    assert_eq!(size.height, 24);
    assert_eq!(size.width, 80);
}

#[test]
fn test_parse_linux_masked_and_readonly_paths() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "maskedPaths": ["/proc/kcore", "/proc/latency_stats"],
            "readonlyPaths": ["/proc/sys", "/proc/sysrq-trigger"]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let linux = spec.linux.unwrap();
    assert_eq!(linux.masked_paths.len(), 2);
    assert_eq!(linux.readonly_paths.len(), 2);
    assert!(linux.masked_paths.contains(&"/proc/kcore".to_string()));
}

#[test]
fn test_parse_linux_sysctl() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "sysctl": {
                "net.ipv4.ip_forward": "1",
                "net.core.somaxconn": "1024"
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let linux = spec.linux.unwrap();
    assert_eq!(linux.sysctl.len(), 2);
    assert_eq!(
        linux.sysctl.get("net.ipv4.ip_forward"),
        Some(&"1".to_string())
    );
}

#[test]
fn test_parse_uid_gid_mappings() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "uidMappings": [
                {"containerId": 0, "hostId": 1000, "size": 1000}
            ],
            "gidMappings": [
                {"containerId": 0, "hostId": 1000, "size": 1000}
            ]
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let linux = spec.linux.unwrap();
    assert_eq!(linux.uid_mappings.len(), 1);
    assert_eq!(linux.uid_mappings[0].container_id, 0);
    assert_eq!(linux.uid_mappings[0].host_id, 1000);
    assert_eq!(linux.uid_mappings[0].size, 1000);
}

#[test]
fn test_parse_block_io() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "resources": {
                "blockIO": {
                    "weight": 500,
                    "leafWeight": 300,
                    "throttleReadBpsDevice": [
                        {"major": 8, "minor": 0, "rate": 104857600}
                    ],
                    "throttleWriteBpsDevice": [
                        {"major": 8, "minor": 0, "rate": 52428800}
                    ]
                }
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let block_io = spec.linux.unwrap().resources.unwrap().block_io.unwrap();
    assert_eq!(block_io.weight, Some(500));
    assert_eq!(block_io.leaf_weight, Some(300));
    assert_eq!(block_io.throttle_read_bps_device.len(), 1);
    assert_eq!(block_io.throttle_read_bps_device[0].rate, 104_857_600);
}

#[test]
fn test_parse_hugepage_limits() {
    let json = r#"{
        "ociVersion": "1.2.0",
        "linux": {
            "resources": {
                "hugepageLimits": [
                    {"pageSize": "2MB", "limit": 209715200},
                    {"pageSize": "1GB", "limit": 1073741824}
                ]
            }
        }
    }"#;

    let spec = Spec::from_json(json).unwrap();
    let limits = spec.linux.unwrap().resources.unwrap().hugepage_limits;
    assert_eq!(limits.len(), 2);
    assert_eq!(limits[0].page_size, "2MB");
    assert_eq!(limits[0].limit, 209_715_200);
}

#[test]
fn test_default_process() {
    let process = Process::default();
    assert!(!process.terminal);
    assert_eq!(process.cwd, "/");
    assert!(!process.args.is_empty());
    assert!(!process.env.is_empty());
}

#[test]
fn test_namespace_type_serialization() {
    let ns = Namespace {
        ns_type: NamespaceType::Network,
        path: Some("/var/run/netns/custom".to_string()),
    };
    let json = serde_json::to_string(&ns).unwrap();
    assert!(json.contains("\"type\":\"network\""));
    assert!(json.contains("/var/run/netns/custom"));
}

#[test]
fn test_valid_oci_versions() {
    // Valid semver versions should pass.
    for version in ["1.0.0", "1.2.0", "2.0.0-rc1", "1.0.0-alpha+build"] {
        let json = format!(r#"{{"ociVersion": "{version}"}}"#);
        assert!(
            Spec::from_json(&json).is_ok(),
            "Version {version} should be valid"
        );
    }
}
