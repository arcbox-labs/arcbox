//! Guards on the committed sandbox NAT BPF object (CORE-83).
//!
//! The object is generated offline (`cargo xtask dev bpf`) and committed, so
//! nothing in a normal build would notice a stale or malformed artifact.
//! These tests do: the hash sidecar pins the source the object was built
//! from, and the ELF checks pin the shape the loader depends on.

use sha2::{Digest, Sha256};

const SOURCE: &str = include_str!("../bpf/sandbox_nat.bpf.c");
const SOURCE_HASH: &str = include_str!("../bpf/sandbox_nat.bpf.c.sha256");
const OBJECT: &[u8] = include_bytes!("../bpf/sandbox_nat.bpf.o");
const OBJECT_HASH: &str = include_str!("../bpf/sandbox_nat.bpf.o.sha256");

/// The committed object must have been rebuilt from the committed source:
/// both sidecars are written by the same `cargo xtask dev bpf` run, so the
/// source half catches an edited `.c` without a rebuild and the object half
/// catches a rebuilt-but-not-recommitted (or hand-swapped) `.o`.
#[test]
fn bpf_object_matches_source() {
    let digest = format!("{:x}", Sha256::digest(SOURCE.as_bytes()));
    assert_eq!(
        digest,
        SOURCE_HASH.trim(),
        "bpf/sandbox_nat.bpf.c changed but the committed object was not \
         rebuilt — run `cargo xtask dev bpf` and commit the result"
    );
    let object_digest = format!("{:x}", Sha256::digest(OBJECT));
    assert_eq!(
        object_digest,
        OBJECT_HASH.trim(),
        "bpf/sandbox_nat.bpf.o does not match its sidecar — run \
         `cargo xtask dev bpf` and commit BOTH the object and the sidecars"
    );
}

/// The object must be the little-endian 64-bit BPF ELF the loader embeds —
/// e.g. a host-endian or accidental native-target rebuild must not slip in.
#[test]
fn bpf_object_is_a_little_endian_bpf_elf() {
    assert_eq!(&OBJECT[..4], b"\x7fELF", "not an ELF object");
    assert_eq!(OBJECT[4], 2, "must be ELFCLASS64");
    assert_eq!(OBJECT[5], 1, "must be little-endian (bpfel)");
    let machine = u16::from_le_bytes([OBJECT[18], OBJECT[19]]);
    assert_eq!(machine, 247, "e_machine must be EM_BPF");
}

/// The symbols and sections the loader looks up by name must exist. A rename
/// in the C source would otherwise only fail at agent runtime in the guest.
#[test]
fn bpf_object_carries_the_loader_contract_names() {
    let contains = |needle: &[u8]| OBJECT.windows(needle.len()).any(|w| w == needle);
    for name in [
        "sandbox_nat_ingress",
        "sandbox_nat_egress",
        "SANDBOX_NAT",
        "SANDBOX_NAT_POOL",
        "classifier",
        "maps",
        "license",
    ] {
        assert!(
            contains(name.as_bytes()),
            "object is missing the {name:?} loader contract name"
        );
    }
    assert!(
        contains(b"Dual MIT/GPL"),
        "license string must stay GPL-compatible for kernel helpers"
    );
}
