//! Unit tests for the nftables rendering, its teardown reader, and the
//! tolerance the seam demands of removal. Nothing here needs a kernel; the
//! real-ruleset half lives in `tests/integration.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::*;
use crate::packet_filter::iptables_legacy::translation_rules as xt_rules;

fn pool() -> Ipv4Addr {
    "172.20.0.2".parse().unwrap()
}

/// The batch is the NAT contract as this backend states it; pin it exactly
/// so drift is loud, the way `translation_rules_pin_the_nat_contract` pins
/// the iptables specs. Every line here was applied to a live kernel on both
/// nft 1.0.2 (CI's floor) and 1.1.6 — which is what the numeric priorities
/// buy: the readable `dstnat` / `srcnat` keywords are hook-scoped on 1.0.2
/// and it rejects them on the output and input hooks (see `BASE_CHAINS`).
#[test]
fn install_batch_pins_the_nat_contract() {
    assert_eq!(
        install_batch("vmtap0-2", pool()),
        "\
add table ip arcbox
add chain ip arcbox mangle_prerouting { type filter hook prerouting priority -150 ; policy accept ; }
add chain ip arcbox mangle_output { type route hook output priority -150 ; policy accept ; }
add chain ip arcbox nat_prerouting { type nat hook prerouting priority -100 ; policy accept ; }
add chain ip arcbox nat_output { type nat hook output priority -100 ; policy accept ; }
add chain ip arcbox nat_input { type nat hook input priority 100 ; policy accept ; }
add chain ip arcbox nat_postrouting { type nat hook postrouting priority 100 ; policy accept ; }
add rule ip arcbox mangle_prerouting iifname \"vmtap0-2\" meta mark set 0xac140002 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox mangle_prerouting ip daddr 172.20.0.2 meta mark set 0xac140002 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox mangle_output ip daddr 172.20.0.2 meta mark set 0xac140002 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox nat_prerouting ip daddr 172.20.0.2 dnat to 169.254.100.2 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox nat_output ip daddr 172.20.0.2 dnat to 169.254.100.2 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox nat_input iifname \"vmtap0-2\" snat to 172.20.0.2 comment \"arcbox-nat:vmtap0-2\"
add rule ip arcbox nat_postrouting ip saddr 169.254.100.2 meta mark 0xac140002 snat to 172.20.0.2 comment \"arcbox-nat:vmtap0-2\"
"
    );
}

/// The two backends are a pair, not two dialects: same rules, same order,
/// each in the chain that corresponds to its iptables table+hook, each
/// carrying the same identity values. A rule added to one and not the other
/// — or reordered, or built on a different selector — fails here.
#[test]
fn renderings_agree_on_the_contract() {
    let (tap, pool) = ("vmtap0-2", pool());
    let mark = format!("{:#x}", fwmark(pool));
    let xt = xt_rules(tap, pool);
    let nft = translation_rules(tap, pool);

    assert_eq!(xt.len(), 7, "the contract is seven rules");
    assert_eq!(xt.len(), nft.len(), "the contract is seven rules on both");

    for (xt, nft) in xt.iter().zip(&nft) {
        let hook = format!("{}_{}", xt.table, xt.chain.to_lowercase());
        assert_eq!(
            nft.chain, hook,
            "{} {} landed elsewhere",
            xt.table, xt.chain
        );

        let xt_spec = xt.spec.join(" ");
        for value in [tap, &pool.to_string(), &mark, &GUEST_IP.to_string()] {
            assert_eq!(
                xt_spec.contains(value),
                nft.expr.contains(value),
                "{hook}: {value} appears in only one rendering\n  iptables: {xt_spec}\n  nft:      {}",
                nft.expr
            );
        }
    }
}

/// The postrouting SNAT must be gated on the fixed guest source, not the
/// mark alone: to-sandbox packets carry the same mark but a client source,
/// and rewriting those would hide real client IPs from guests.
#[test]
fn snat_selection_never_rewrites_client_sources() {
    let rules = translation_rules("vmtap0-2", pool());
    let postrouting = rules
        .iter()
        .find(|r| r.chain == "nat_postrouting")
        .expect("postrouting SNAT rule");
    assert!(
        postrouting
            .expr
            .starts_with(&format!("ip saddr {GUEST_IP} ")),
        "{}",
        postrouting.expr
    );
}

/// A real `nft -j -a list table` document, trimmed to two taps' rules.
const LISTING: &[u8] = br#"{"nftables": [
  {"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
  {"table": {"family": "ip", "name": "arcbox", "handle": 1}},
  {"chain": {"family": "ip", "table": "arcbox", "name": "nat_prerouting",
             "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100,
             "policy": "accept"}},
  {"rule": {"family": "ip", "table": "arcbox", "chain": "nat_prerouting",
            "handle": 2, "comment": "arcbox-nat:vmtap0-2",
            "expr": [{"match": {"op": "==", "left": {"payload":
                     {"protocol": "ip", "field": "daddr"}},
                     "right": "172.20.0.2"}},
                     {"dnat": {"addr": "169.254.100.2"}}]}},
  {"rule": {"family": "ip", "table": "arcbox", "chain": "nat_prerouting",
            "handle": 3, "comment": "arcbox-nat:vmtap0-3",
            "expr": [{"dnat": {"addr": "169.254.100.2"}}]}},
  {"rule": {"family": "ip", "table": "arcbox", "chain": "nat_postrouting",
            "handle": 9, "comment": "arcbox-nat:vmtap0-2",
            "expr": [{"snat": {"addr": "172.20.0.2"}}]}},
  {"rule": {"family": "ip", "table": "arcbox", "chain": "nat_postrouting",
            "handle": 11, "expr": [{"masquerade": null}]}}
]}"#;

/// Teardown must collect this TAP's rules across every chain and leave
/// another sandbox's — and an untagged rule the node installed itself —
/// alone.
#[test]
fn rule_handles_picks_only_this_taps_tagged_rules() {
    let handles = rule_handles(LISTING, "arcbox-nat:vmtap0-2").unwrap();
    assert_eq!(
        handles,
        [
            RuleHandle {
                chain: "nat_prerouting".into(),
                handle: 2
            },
            RuleHandle {
                chain: "nat_postrouting".into(),
                handle: 9
            },
        ]
    );
}

/// A listing that is not the document we asked for is a parse error, not an
/// empty rule set — "nothing to remove" and "could not read the ruleset" are
/// opposite answers, and only the first may report a clean teardown.
#[test]
fn a_listing_that_will_not_parse_is_an_error_not_an_empty_set() {
    let err = rule_handles(b"not json", "arcbox-nat:vmtap0-2").unwrap_err();
    assert!(err.contains("parse nft listing"), "{err}");
}

// ---- stand-in `nft` -------------------------------------------------------

/// An `nft` stand-in driving `body` as a `case "$*"` body. Returns the
/// binary, the log of argv lines, and the log of whatever was fed to stdin.
fn fake_nft(dir: &Path, body: &str) -> (Nftables, PathBuf, PathBuf) {
    let calls = dir.join("nft.calls");
    let stdin = dir.join("nft.stdin");
    let script = dir.join("nft");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\n\
             if [ \"$1\" = \"-f\" ]; then cat >> {}; fi\n\
             case \"$*\" in\n{body}\nesac\n",
            calls.display(),
            stdin.display()
        ),
    );
    // The probe in `write_script` ran it, so every test starts from an empty
    // record.
    std::fs::remove_file(&calls).ok();
    std::fs::remove_file(&stdin).ok();
    (Nftables::new(script), calls, stdin)
}

/// Write `body` to `path`, make it executable, and do not return until the
/// kernel agrees to exec it: a sibling test thread that forks between this
/// thread's `create` and `close` holds a write fd to the script, and Linux
/// will not exec a file open for writing (`ETXTBSY`).
fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match Command::new(path).output() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{} stayed busy for 5s",
                    path.display()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            other => {
                other.unwrap();
                return;
            }
        }
    }
}

fn lines(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

const LIST_ONE_RULE: &str = "\"-j -a list table ip arcbox\") echo '{\"nftables\": [{\"rule\": \
     {\"chain\": \"nat_prerouting\", \"handle\": 2, \"comment\": \"arcbox-nat:vmtap0-2\"}}]}' ;;";

#[test]
fn install_feeds_the_rendered_batch_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, calls, stdin) = fake_nft(dir.path(), "*) exit 0 ;;");

    nft.install_translation("vmtap0-2", pool()).unwrap();

    assert_eq!(lines(&calls), ["-f -"]);
    assert_eq!(
        std::fs::read_to_string(&stdin).unwrap(),
        install_batch("vmtap0-2", pool()),
        "the kernel must receive exactly what the renderer produced"
    );
}

#[test]
fn a_failed_install_carries_nfts_own_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, _, _) = fake_nft(
        dir.path(),
        "*) echo \"Error: Could not process rule: Operation not permitted\" >&2; exit 1 ;;",
    );

    let err = nft.install_translation("vmtap0-2", pool()).unwrap_err();

    assert!(err.to_string().contains("install vmtap0-2"), "{err}");
    assert!(err.to_string().contains("Operation not permitted"), "{err}");
}

#[test]
fn a_missing_table_reads_clean_and_deletes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, calls, _) = fake_nft(
        dir.path(),
        "\"-j -a list table ip arcbox\") echo \"Error: No such file or directory\" >&2; exit 1 ;;\n\
         *) echo \"unexpected: $*\" >&2; exit 2 ;;",
    );

    nft.remove_translation("vmtap0-2", pool()).unwrap();

    assert_eq!(
        lines(&calls),
        ["-j -a list table ip arcbox"],
        "an absent table leaves nothing to delete"
    );
}

#[test]
fn a_handle_a_concurrent_teardown_freed_reads_clean() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, _, stdin) = fake_nft(
        dir.path(),
        &format!(
            "{LIST_ONE_RULE}\n\
             \"-f -\") echo \"Error: Could not process rule: No such file or directory\" >&2; \
             exit 1 ;;"
        ),
    );

    nft.remove_translation("vmtap0-2", pool()).unwrap();

    assert_eq!(
        lines(&stdin),
        ["delete rule ip arcbox nat_prerouting handle 2"]
    );
}

#[test]
fn a_removal_failure_that_is_not_absence_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, _, _) = fake_nft(
        dir.path(),
        &format!(
            "{LIST_ONE_RULE}\n\
             \"-f -\") echo \"Error: Operation not permitted\" >&2; exit 1 ;;"
        ),
    );

    let err = nft.remove_translation("vmtap0-2", pool()).unwrap_err();

    assert!(err.to_string().contains("handle 2"), "{err}");
    assert!(err.to_string().contains("Operation not permitted"), "{err}");
}

#[test]
fn a_listing_failure_that_is_not_absence_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let (nft, _, _) = fake_nft(
        dir.path(),
        "*) echo \"Error: Operation not permitted\" >&2; exit 1 ;;",
    );

    let err = nft.remove_translation("vmtap0-2", pool()).unwrap_err();

    assert!(err.to_string().contains("list table ip arcbox"), "{err}");
}

#[test]
fn a_missing_binary_is_an_error_even_on_tolerant_removal() {
    // Tolerance covers "the object is gone", never "could not run nft at
    // all": a wrong path must surface, not read as clean.
    let nft = Nftables::new("/nonexistent/arcbox-nft");
    let err = nft.remove_translation("vmtap0-2", pool()).unwrap_err();
    assert!(err.to_string().contains("run "), "{err}");
}

#[test]
fn the_default_path_is_where_a_stock_distro_installs_nft() {
    assert_eq!(
        Nftables::default().nft,
        PathBuf::from(Nftables::DEFAULT_PATH)
    );
}

#[test]
fn discovery_names_the_candidates_it_could_not_find() {
    let err = Nftables::discover_in(&["/nonexistent/arcbox-nft"]).unwrap_err();
    assert!(err.to_string().contains("no nft"), "{err}");
    assert!(err.to_string().contains("/nonexistent/arcbox-nft"), "{err}");
}

#[test]
fn discovery_skips_a_binary_that_does_not_answer_as_nftables() {
    let dir = tempfile::tempdir().unwrap();
    let impostor = dir.path().join("nft-impostor");
    write_script(&impostor, "#!/bin/sh\necho 'iptables v1.8.7 (nf_tables)'\n");
    let real = dir.path().join("nft-real");
    write_script(
        &real,
        "#!/bin/sh\necho 'nftables v1.0.6 (Lester Gooch #5)'\n",
    );

    let found =
        Nftables::discover_in(&[impostor.to_str().unwrap(), real.to_str().unwrap()]).unwrap();

    assert_eq!(found.nft, real);
}
