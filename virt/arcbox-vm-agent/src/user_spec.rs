//! Docker-style `user` specification parsing for sandbox workloads.
//!
//! Resolves `"uid"`, `"uid:gid"`, `"name"`, and `"name:group"` against the
//! *sandbox rootfs*'s `/etc/passwd` and `/etc/group` contents (passed in as
//! strings so the logic stays pure and host-testable). Semantics follow
//! `docker run --user`: a numeric uid that has no passwd entry falls back to
//! gid 0, a named user must exist, and an explicit group part wins.

/// A resolved uid/gid pair for workload execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedUser {
    /// Numeric user ID to run as.
    pub uid: u32,
    /// Numeric group ID to run as.
    pub gid: u32,
}

/// Resolve a Docker-style user spec against passwd/group file contents.
///
/// Returns `Ok(None)` for an empty spec (run as the agent's own user, i.e.
/// root inside the microVM). Fails with an actionable message when a named
/// user or group does not exist in the sandbox rootfs.
pub fn resolve_user(spec: &str, passwd: &str, group: &str) -> Result<Option<ResolvedUser>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }

    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    let (uid, passwd_gid) = if let Ok(uid) = user_part.parse::<u32>() {
        // Numeric uid: passwd entry is optional; without one Docker runs the
        // process with gid 0.
        (uid, passwd_entry_by_uid(passwd, uid).map(|(_, gid)| gid))
    } else {
        let (uid, gid) = passwd_entry_by_name(passwd, user_part)
            .ok_or_else(|| format!("user '{user_part}' not found in the sandbox /etc/passwd"))?;
        (uid, Some(gid))
    };

    let gid = match group_part {
        None => passwd_gid.unwrap_or(0),
        Some(g) => {
            if let Ok(gid) = g.parse::<u32>() {
                gid
            } else {
                group_entry_by_name(group, g)
                    .ok_or_else(|| format!("group '{g}' not found in the sandbox /etc/group"))?
            }
        }
    };

    Ok(Some(ResolvedUser { uid, gid }))
}

/// Find `(uid, gid)` for a passwd entry by user name.
fn passwd_entry_by_name(passwd: &str, name: &str) -> Option<(u32, u32)> {
    passwd_entries(passwd)
        .find_map(|(entry_name, uid, gid)| (entry_name == name).then_some((uid, gid)))
}

/// Find `(name-ignored, gid)` for a passwd entry by uid.
fn passwd_entry_by_uid(passwd: &str, uid: u32) -> Option<(u32, u32)> {
    passwd_entries(passwd).find_map(|(_, entry_uid, gid)| (entry_uid == uid).then_some((uid, gid)))
}

/// Iterate `name:pw:uid:gid` prefixes of well-formed passwd lines.
fn passwd_entries(passwd: &str) -> impl Iterator<Item = (&str, u32, u32)> {
    passwd.lines().filter_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pw = fields.next()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        Some((name, uid, gid))
    })
}

/// Find a gid for a group entry (`name:pw:gid:members`) by group name.
fn group_entry_by_name(group: &str, name: &str) -> Option<u32> {
    group.lines().find_map(|line| {
        let mut fields = line.split(':');
        let entry_name = fields.next()?;
        let _pw = fields.next()?;
        let gid = fields.next()?.parse().ok()?;
        (entry_name == name).then_some(gid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nweb:x:1000:1001:web:/home/web:/bin/sh\n";
    const GROUP: &str = "root:x:0:\nstaff:x:2000:web\n";

    #[test]
    fn empty_spec_is_none() {
        assert_eq!(resolve_user("", PASSWD, GROUP).unwrap(), None);
        assert_eq!(resolve_user("  ", PASSWD, GROUP).unwrap(), None);
    }

    #[test]
    fn numeric_uid_uses_passwd_gid() {
        let u = resolve_user("1000", PASSWD, GROUP).unwrap().unwrap();
        assert_eq!(
            u,
            ResolvedUser {
                uid: 1000,
                gid: 1001
            }
        );
    }

    #[test]
    fn numeric_uid_without_passwd_entry_falls_back_to_gid_zero() {
        let u = resolve_user("4242", PASSWD, GROUP).unwrap().unwrap();
        assert_eq!(u, ResolvedUser { uid: 4242, gid: 0 });
    }

    #[test]
    fn numeric_uid_gid_pair() {
        let u = resolve_user("7:9", PASSWD, GROUP).unwrap().unwrap();
        assert_eq!(u, ResolvedUser { uid: 7, gid: 9 });
    }

    #[test]
    fn named_user_resolves_both_ids() {
        let u = resolve_user("web", PASSWD, GROUP).unwrap().unwrap();
        assert_eq!(
            u,
            ResolvedUser {
                uid: 1000,
                gid: 1001
            }
        );
    }

    #[test]
    fn named_user_with_named_group() {
        let u = resolve_user("web:staff", PASSWD, GROUP).unwrap().unwrap();
        assert_eq!(
            u,
            ResolvedUser {
                uid: 1000,
                gid: 2000
            }
        );
    }

    #[test]
    fn unknown_named_user_errors() {
        assert!(resolve_user("ghost", PASSWD, GROUP).is_err());
        assert!(resolve_user("web:ghosts", PASSWD, GROUP).is_err());
    }
}
