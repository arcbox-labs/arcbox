//! [`PacketFilter`] over nftables — a stock distro's netfilter userland.
//!
//! Renders the seam's contract (see [`super`]) as the same seven rules
//! [`IptablesLegacy`](super::IptablesLegacy) renders, in the same order, in a
//! dedicated `table ip arcbox` whose base chains sit at the hook priorities
//! the iptables tables occupy. Two shape differences follow from nftables
//! itself rather than from taste:
//!
//! - **Install is one atomic batch.** `nft -f -` commits a transaction, so a
//!   rejected rule leaves nothing behind instead of a partial rule set. The
//!   batch also `add`s the table and chains, which is idempotent, so a
//!   ruleset an operator flushed is rebuilt by the next activation.
//! - **Removal is by comment, not by spec.** nftables can only delete a rule
//!   by handle, and handles are assigned by the kernel. Every rule therefore
//!   carries `comment "arcbox-nat:<tap>"`, and teardown lists the table, keeps
//!   the handles whose comment matches, and deletes those. That tag is the
//!   only key, which makes teardown strictly more thorough than the iptables
//!   path's delete-by-spec: it also collects a rule whose spec has drifted,
//!   and it collects *every* copy when a crash replay appended a second set
//!   (`iptables -D` removes only the first match).

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::Deserialize;

use super::{PacketFilter, RULE_COMMENT};
use crate::error::{Result, TapNetError};
use crate::invariant::{GUEST_IP, fwmark};

/// Family and name of the table every arcbox rule lives in.
const TABLE: &str = "ip arcbox";

/// Reference search list for `nft`. The first entry that exists and answers
/// `--version` as nftables wins; `/usr/sbin` covers usrmerged distros,
/// `/sbin` the rest.
const NFT_CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft"];

/// The base chains, in table order, each at the hook priority of the
/// iptables table it stands in for: `NF_IP_PRI_MANGLE` (-150),
/// `NF_IP_PRI_NAT_DST` (-100), `NF_IP_PRI_NAT_SRC` (100).
///
/// The priorities are numeric rather than the readable `mangle` / `dstnat` /
/// `srcnat` keywords because those keywords are **hook-scoped** on older
/// nftables: nft 1.0.2 (Ubuntu 22.04, and the floor below Debian 12's 1.0.6)
/// rejects `dstnat` in the output hook and `srcnat` in the input hook with
/// "invalid priority expression value in this context", while nft 1.1.6
/// accepts both. The numbers mean the same thing on every version.
///
/// `mangle_output` is `type route`, not `type filter`: that is what makes a
/// mark set there trigger a re-route, which is the whole point of rule 3 and
/// what iptables' mangle OUTPUT does.
const BASE_CHAINS: &[(&str, &str)] = &[
    (
        "mangle_prerouting",
        "type filter hook prerouting priority -150 ; policy accept ;",
    ),
    (
        "mangle_output",
        "type route hook output priority -150 ; policy accept ;",
    ),
    (
        "nat_prerouting",
        "type nat hook prerouting priority -100 ; policy accept ;",
    ),
    (
        "nat_output",
        "type nat hook output priority -100 ; policy accept ;",
    ),
    (
        "nat_input",
        "type nat hook input priority 100 ; policy accept ;",
    ),
    (
        "nat_postrouting",
        "type nat hook postrouting priority 100 ; policy accept ;",
    ),
];

/// [`PacketFilter`] over the `nft` binary.
///
/// Every rule carries the `arcbox-nat:<tap>` comment, which is both the
/// forensic tag (`nft list ruleset`) and the teardown key.
#[derive(Debug, Clone)]
pub struct Nftables {
    nft: PathBuf,
}

impl Nftables {
    /// Where a stock distro installs `nft`.
    pub const DEFAULT_PATH: &'static str = "/usr/sbin/nft";

    /// Use the binary at `nft` as given. Nothing is probed: a composer that
    /// knows where its userland lives (a bundled copy, a non-standard
    /// prefix) says so and is believed.
    pub fn new(nft: impl Into<PathBuf>) -> Self {
        Self { nft: nft.into() }
    }

    /// Find `nft` in the reference search list, failing when it is absent or
    /// is not nftables.
    ///
    /// `PATH` is deliberately not searched: a node agent's `PATH` is whatever
    /// its unit file happened to inherit.
    pub fn discover() -> Result<Self> {
        Self::discover_in(NFT_CANDIDATES)
    }

    fn discover_in(candidates: &[&str]) -> Result<Self> {
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|bin| is_nftables(bin))
            .map(|nft| Self { nft })
            .ok_or_else(|| TapNetError::Network(format!("no nft among {}", candidates.join(", "))))
    }

    /// Run one `nft` invocation, optionally feeding `script` to its stdin.
    ///
    /// `LC_ALL=C` is forced so [`is_missing`]'s match on strerror text holds
    /// whatever locale the node agent inherited. The failure is the bare
    /// diagnostic: callers wrap it into [`TapNetError::Network`] once, so a
    /// collected teardown report carries one prefix, not one per rule.
    fn run(&self, args: &[&str], script: Option<&str>) -> std::result::Result<Output, String> {
        let spawn_failed = |e| format!("run {}: {e}", self.nft.display());
        let mut child = Command::new(&self.nft)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(if script.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_failed)?;
        if let Some(script) = script {
            // Taking the handle closes the pipe at the end of this block,
            // which is what lets nft reach EOF and exit.
            let mut stdin = child
                .stdin
                .take()
                .expect("stdin is piped when a script is given");
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("write batch to {}: {e}", self.nft.display()))?;
        }
        child.wait_with_output().map_err(spawn_failed)
    }

    /// Chain and handle of every rule in the table tagged for this TAP.
    ///
    /// An absent table is an empty list, not an error: teardown runs for TAPs
    /// that never had rules (legacy, partially activated) and on hosts where
    /// a previous sweep already removed the last one.
    fn tagged_rules(&self, tag: &str) -> std::result::Result<Vec<RuleHandle>, String> {
        let output = self.run(&["-j", "-a", "list", "table", TABLE], None)?;
        if !output.status.success() {
            let stderr = stderr_of(&output);
            if is_missing(&stderr) {
                return Ok(Vec::new());
            }
            return Err(format!("nft list table {TABLE}: {stderr}"));
        }
        rule_handles(&output.stdout, tag)
    }
}

impl Default for Nftables {
    fn default() -> Self {
        Self::new(Self::DEFAULT_PATH)
    }
}

impl PacketFilter for Nftables {
    fn install_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
        let output = self
            .run(&["-f", "-"], Some(&install_batch(tap, pool_ip)))
            .map_err(TapNetError::Network)?;
        if output.status.success() {
            return Ok(());
        }
        Err(TapNetError::Network(format!(
            "nft -f - (install {tap}): {}",
            stderr_of(&output)
        )))
    }

    /// `pool_ip` is not read: the TAP name derives from the pool address
    /// (`vmtap<c>-<d>`), so the tag alone names the sandbox, and matching on
    /// the tag rather than on a rendered spec is what lets teardown collect
    /// drifted and duplicated rules too.
    fn remove_translation(&self, tap: &str, _pool_ip: Ipv4Addr) -> Result<()> {
        let tag = rule_tag(tap);
        let rules = self.tagged_rules(&tag).map_err(TapNetError::Network)?;
        // One delete per rule rather than one batch: a batch is a
        // transaction, so a single handle a concurrent teardown already freed
        // would roll back the deletion of every other rule and report the
        // whole thing as "already gone".
        let mut failures = Vec::new();
        for rule in rules {
            let delete = format!("delete rule {TABLE} {} handle {}", rule.chain, rule.handle);
            match self.run(&["-f", "-"], Some(&format!("{delete}\n"))) {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    let stderr = stderr_of(&output);
                    if !is_missing(&stderr) {
                        failures.push(format!("nft {delete}: {stderr}"));
                    }
                }
                Err(failure) => failures.push(failure),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(TapNetError::Network(failures.join("; ")))
        }
    }
}

/// The tag every rule of one TAP's translation carries.
fn rule_tag(tap: &str) -> String {
    format!("{RULE_COMMENT}:{tap}")
}

/// One nft rule of the per-TAP translation set: the chain it is appended to
/// and the expression that goes in it (the comment is added on rendering).
#[derive(Debug, PartialEq, Eq)]
pub struct NftRule {
    pub chain: &'static str,
    pub expr: String,
}

/// The complete per-TAP translation rule set, in install order — the nft
/// rendering of the module-level contract, point for point with
/// [`iptables_legacy::translation_rules`](super::iptables_legacy::translation_rules).
pub fn translation_rules(tap: &str, pool_ip: Ipv4Addr) -> Vec<NftRule> {
    let mark = format!("{:#x}", fwmark(pool_ip));
    let mut rules = Vec::new();
    let mut rule = |chain, expr: String| rules.push(NftRule { chain, expr });

    // 1. Mark sandbox-originated packets so postrouting NAT (which cannot
    //    match the input interface) can select the right source identity.
    rule(
        "mangle_prerouting",
        format!("iifname \"{tap}\" meta mark set {mark}"),
    );
    // 2. Mark to-sandbox packets from their pre-NAT destination; the fwmark
    //    fib rule then routes the DNAT'd destination out this TAP.
    rule(
        "mangle_prerouting",
        format!("ip daddr {pool_ip} meta mark set {mark}"),
    );
    rule(
        "mangle_output",
        format!("ip daddr {pool_ip} meta mark set {mark}"),
    );
    // 3. External identity → fixed guest identity, both directions.
    rule(
        "nat_prerouting",
        format!("ip daddr {pool_ip} dnat to {GUEST_IP}"),
    );
    rule(
        "nat_output",
        format!("ip daddr {pool_ip} dnat to {GUEST_IP}"),
    );
    // 4. Local services (DNS, relays) see the pool identity, and their
    //    replies are addressed to it — which is what makes them routable
    //    back out the right TAP (dst-based mark + fwmark table).
    rule("nat_input", format!("iifname \"{tap}\" snat to {pool_ip}"));
    // 5. Forwarded sandbox-originated traffic. The source match is the
    //    definitive sandbox-origin signature at postrouting (only pre-SNAT
    //    sandbox packets carry the fixed guest source); the mark picks which
    //    sandbox, keeping to-sandbox packets (marked with the same value but
    //    carrying a client source) out of this rewrite.
    rule(
        "nat_postrouting",
        format!("ip saddr {GUEST_IP} meta mark {mark} snat to {pool_ip}"),
    );
    rules
}

/// The batch that installs one TAP's translation: the table and chains
/// (`add` is idempotent, so this is also the repair path) followed by the
/// seven rules, each appended and tagged.
pub fn install_batch(tap: &str, pool_ip: Ipv4Addr) -> String {
    let tag = rule_tag(tap);
    std::iter::once(format!("add table {TABLE}\n"))
        .chain(
            BASE_CHAINS
                .iter()
                .map(|(chain, spec)| format!("add chain {TABLE} {chain} {{ {spec} }}\n")),
        )
        .chain(
            translation_rules(tap, pool_ip)
                .into_iter()
                .map(|NftRule { chain, expr }| {
                    format!("add rule {TABLE} {chain} {expr} comment \"{tag}\"\n")
                }),
        )
        .collect()
}

/// Chain and handle of one rule the kernel reports.
#[derive(Debug, PartialEq, Eq)]
pub struct RuleHandle {
    chain: String,
    handle: u64,
}

/// `nft -j` output, narrowed to the rules it lists. Every other item of the
/// array (metainfo, table, chain) deserializes with `rule: None`.
#[derive(Deserialize)]
struct Listing {
    nftables: Vec<ListingItem>,
}

#[derive(Deserialize)]
struct ListingItem {
    rule: Option<ListedRule>,
}

#[derive(Deserialize)]
struct ListedRule {
    chain: String,
    handle: u64,
    comment: Option<String>,
}

/// Every rule in an `nft -j -a list table` document carrying `tag`.
///
/// `comment`, `chain` and `handle` are top-level fields on the rule object
/// under nft's declared-stable `json_schema_version: 1`, so this stays a flat
/// filter rather than a walk of the expression tree — the rendering can
/// change without touching the reader.
pub fn rule_handles(listing: &[u8], tag: &str) -> std::result::Result<Vec<RuleHandle>, String> {
    let listing: Listing =
        serde_json::from_slice(listing).map_err(|e| format!("parse nft listing: {e}"))?;
    Ok(listing
        .nftables
        .into_iter()
        .filter_map(|item| item.rule)
        .filter(|rule| rule.comment.as_deref() == Some(tag))
        .map(|rule| RuleHandle {
            chain: rule.chain,
            handle: rule.handle,
        })
        .collect())
}

/// Whether `bin` answers `--version` as nftables.
fn is_nftables(bin: &Path) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|out| {
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("nftables")
        })
}

/// Whether a failed invocation failed because the object was not there.
///
/// nft reports a missing table, chain, or handle as exit 1 with
/// `strerror(ENOENT)`; [`Nftables::run`] forces `LC_ALL=C` so that text is
/// stable. This is what makes removal idempotent — a table that was never
/// created and a handle a concurrent teardown just freed both read as
/// "already gone" — and it is deliberately narrower than the whole of exit 1,
/// which also covers syntax errors and permission failures.
fn is_missing(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

#[cfg(test)]
mod tests;
