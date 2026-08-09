//! Inotify event-buffer parsing and mapping to sandbox filesystem events.
//!
//! The vm-agent's directory watch (`FILE_WATCH_REQ`, see [`crate::file_io`])
//! reads raw `inotify(7)` event buffers inside the guest. Everything that
//! does not need a syscall lives here so it compiles and is unit-tested on
//! every host platform: the fixed 16-byte event header layout, the mask
//! constants, and the cookie-based rename pairing that turns kernel
//! `IN_MOVED_FROM`/`IN_MOVED_TO` pairs into single `renamed` events.

use crate::file_io::proto::{
    EVENT_CREATED, EVENT_MODIFIED, EVENT_REMOVED, EVENT_RENAMED, FsEventDto,
};

// `inotify(7)` mask bits (stable kernel ABI; mirrored here so this module
// needs no libc and stays testable off-Linux).
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ISDIR: u32 = 0x4000_0000;

/// The mask a directory watch subscribes with. `IN_CLOSE_WRITE` is left out
/// deliberately: `IN_MODIFY` already reports content changes, and reporting
/// both would emit two `modified` events per write.
pub const WATCH_MASK: u32 =
    IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF;

/// One decoded `struct inotify_event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWatchEvent {
    /// Watch descriptor the event fired on (`-1` for queue overflow).
    pub wd: i32,
    /// Event mask bits.
    pub mask: u32,
    /// Kernel cookie pairing `IN_MOVED_FROM` with `IN_MOVED_TO`.
    pub cookie: u32,
    /// Entry name relative to the watched directory (empty for events on
    /// the watched directory itself, e.g. `IN_DELETE_SELF`).
    pub name: String,
}

impl RawWatchEvent {
    /// True when the event names a directory (`IN_ISDIR`).
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.mask & IN_ISDIR != 0
    }
}

/// Decode a raw `read(2)` buffer from an inotify fd.
///
/// Layout per event: `i32 wd, u32 mask, u32 cookie, u32 len`, then `len`
/// bytes of NUL-padded name. A truncated trailing record (which the kernel
/// never produces, but arbitrary short reads must not panic) ends the parse.
#[must_use]
pub fn parse_event_buffer(buf: &[u8]) -> Vec<RawWatchEvent> {
    const HEADER: usize = 16;
    let mut events = Vec::new();
    let mut off = 0usize;
    while buf.len() - off >= HEADER {
        let wd = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let cookie = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
        let Some(end) = off.checked_add(HEADER).and_then(|s| s.checked_add(len)) else {
            break;
        };
        if end > buf.len() {
            break;
        }
        let name_bytes = &buf[off + HEADER..end];
        let name_end = name_bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(name_bytes.len());
        events.push(RawWatchEvent {
            wd,
            mask,
            cookie,
            name: String::from_utf8_lossy(&name_bytes[..name_end]).into_owned(),
        });
        off = end;
    }
    events
}

/// Map one batch of raw events onto wire events.
///
/// `path_of` resolves a watch descriptor to the absolute directory path it
/// watches (`None` for descriptors already forgotten, whose events are
/// dropped). Rename pairing is per-batch: an `IN_MOVED_FROM` whose cookie is
/// matched by an `IN_MOVED_TO` in the same batch becomes one `renamed`
/// event; an unmatched half degrades to `removed` / `created`, which is
/// exactly what a move across the watch boundary is from the watcher's view.
pub fn map_events(
    batch: &[RawWatchEvent],
    mut path_of: impl FnMut(i32) -> Option<String>,
) -> Vec<FsEventDto> {
    // Pending unmatched IN_MOVED_FROM halves: (cookie, absolute path,
    // emitted `removed` slot index).
    let mut pending_from: Vec<(u32, String, usize)> = Vec::new();
    let mut out: Vec<Option<FsEventDto>> = Vec::new();

    for event in batch {
        if event.mask & (IN_Q_OVERFLOW | IN_IGNORED) != 0 {
            continue;
        }
        let Some(dir) = path_of(event.wd) else {
            continue;
        };
        let path = join_path(&dir, &event.name);

        if event.mask & IN_MOVED_FROM != 0 {
            // Tentatively a removal; upgraded to `renamed` if the TO half
            // arrives later in this batch.
            pending_from.push((event.cookie, path.clone(), out.len()));
            out.push(Some(FsEventDto {
                kind: EVENT_REMOVED.to_owned(),
                path,
                renamed_to: String::new(),
            }));
        } else if event.mask & IN_MOVED_TO != 0 {
            if let Some(idx) = pending_from
                .iter()
                .position(|(cookie, _, _)| *cookie == event.cookie)
            {
                let (_, from_path, slot) = pending_from.swap_remove(idx);
                out[slot] = Some(FsEventDto {
                    kind: EVENT_RENAMED.to_owned(),
                    path: from_path,
                    renamed_to: path,
                });
            } else {
                out.push(Some(FsEventDto {
                    kind: EVENT_CREATED.to_owned(),
                    path,
                    renamed_to: String::new(),
                }));
            }
        } else if event.mask & IN_CREATE != 0 {
            out.push(Some(FsEventDto {
                kind: EVENT_CREATED.to_owned(),
                path,
                renamed_to: String::new(),
            }));
        } else if event.mask & (IN_DELETE | IN_DELETE_SELF) != 0 {
            out.push(Some(FsEventDto {
                kind: EVENT_REMOVED.to_owned(),
                path,
                renamed_to: String::new(),
            }));
        } else if event.mask & (IN_MODIFY | IN_ATTRIB) != 0 {
            out.push(Some(FsEventDto {
                kind: EVENT_MODIFIED.to_owned(),
                path,
                renamed_to: String::new(),
            }));
        }
    }

    out.into_iter().flatten().collect()
}

/// True when the batch ends in a rename's unmatched FROM half.
///
/// The final event is an `IN_MOVED_FROM` whose matching `IN_MOVED_TO` is
/// absent from the batch — the TO half may still be in flight, so the
/// reader should give the queue one bounded chance to complete the pair
/// before mapping (an unpaired half degrades to `removed`/`created`, which
/// then stands for a move across the watch boundary or a genuinely split
/// pair).
#[must_use]
pub fn trailing_unpaired_move_from(batch: &[RawWatchEvent]) -> bool {
    let Some(last) = batch.last() else {
        return false;
    };
    last.mask & IN_MOVED_FROM != 0
        && !batch
            .iter()
            .any(|event| event.mask & IN_MOVED_TO != 0 && event.cookie == last.cookie)
}

/// True when the kernel reported a queue overflow in this batch.
///
/// An unknown number of events was dropped, so the consumer's view can no
/// longer be kept consistent and the watch must fail rather than stream on.
#[must_use]
pub fn has_overflow(batch: &[RawWatchEvent]) -> bool {
    batch.iter().any(|event| event.mask & IN_Q_OVERFLOW != 0)
}

/// Join a watched directory and an event's relative name (empty name means
/// the directory itself, e.g. `IN_DELETE_SELF`).
fn join_path(dir: &str, name: &str) -> String {
    if name.is_empty() {
        dir.to_owned()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(events: &[(i32, u32, u32, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (wd, mask, cookie, name) in events {
            // NUL-pad to a 4-byte boundary like the kernel does.
            let mut name_bytes = name.as_bytes().to_vec();
            if !name_bytes.is_empty() {
                name_bytes.push(0);
                while name_bytes.len() % 4 != 0 {
                    name_bytes.push(0);
                }
            }
            buf.extend_from_slice(&wd.to_ne_bytes());
            buf.extend_from_slice(&mask.to_ne_bytes());
            buf.extend_from_slice(&cookie.to_ne_bytes());
            buf.extend_from_slice(&(name_bytes.len() as u32).to_ne_bytes());
            buf.extend_from_slice(&name_bytes);
        }
        buf
    }

    fn root_only(wd: i32) -> Option<String> {
        (wd == 1).then(|| "/watch".to_owned())
    }

    #[test]
    fn parses_events_and_strips_nul_padding() {
        let buf = encode(&[(1, IN_CREATE, 0, "a.txt"), (1, IN_DELETE_SELF, 0, "")]);
        let events = parse_event_buffer(&buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name, "a.txt");
        assert_eq!(events[0].mask, IN_CREATE);
        assert_eq!(events[1].name, "");
    }

    #[test]
    fn truncated_buffer_does_not_panic() {
        let buf = encode(&[(1, IN_CREATE, 0, "a.txt")]);
        for cut in 0..buf.len() {
            // Every prefix parses to zero or one event, never a panic.
            assert!(parse_event_buffer(&buf[..cut]).len() <= 1);
        }
        // A header whose len field overruns the buffer is dropped.
        let mut bogus = encode(&[(1, IN_CREATE, 0, "")]);
        bogus[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_event_buffer(&bogus).is_empty());
    }

    #[test]
    fn rename_pairs_by_cookie_into_one_event() {
        let batch = parse_event_buffer(&encode(&[
            (1, IN_MOVED_FROM, 7, "old"),
            (1, IN_MOVED_TO, 7, "new"),
        ]));
        let events = map_events(&batch, root_only);
        assert_eq!(
            events,
            vec![FsEventDto {
                kind: EVENT_RENAMED.to_owned(),
                path: "/watch/old".to_owned(),
                renamed_to: "/watch/new".to_owned(),
            }]
        );
    }

    #[test]
    fn unpaired_move_halves_degrade_to_removed_and_created() {
        let batch = parse_event_buffer(&encode(&[
            (1, IN_MOVED_FROM, 7, "gone"),
            (1, IN_MOVED_TO, 9, "arrived"),
        ]));
        let events = map_events(&batch, root_only);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EVENT_REMOVED);
        assert_eq!(events[0].path, "/watch/gone");
        assert_eq!(events[1].kind, EVENT_CREATED);
        assert_eq!(events[1].path, "/watch/arrived");
    }

    #[test]
    fn modify_attrib_delete_and_self_delete_map() {
        let batch = parse_event_buffer(&encode(&[
            (1, IN_MODIFY, 0, "f"),
            (1, IN_ATTRIB, 0, "f"),
            (1, IN_DELETE, 0, "f"),
            (1, IN_DELETE_SELF, 0, ""),
        ]));
        let kinds: Vec<_> = map_events(&batch, root_only)
            .into_iter()
            .map(|e| (e.kind, e.path))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (EVENT_MODIFIED.to_owned(), "/watch/f".to_owned()),
                (EVENT_MODIFIED.to_owned(), "/watch/f".to_owned()),
                (EVENT_REMOVED.to_owned(), "/watch/f".to_owned()),
                (EVENT_REMOVED.to_owned(), "/watch".to_owned()),
            ]
        );
    }

    #[test]
    fn overflow_ignored_and_unknown_wd_events_are_dropped() {
        let batch = parse_event_buffer(&encode(&[
            (-1, IN_Q_OVERFLOW, 0, ""),
            (1, IN_IGNORED, 0, ""),
            (99, IN_CREATE, 0, "orphan"),
        ]));
        assert!(map_events(&batch, root_only).is_empty());
    }

    #[test]
    fn trailing_unpaired_move_from_flags_only_the_open_pair() {
        // FROM with no TO at the end of the batch: the pair may be split.
        let open = parse_event_buffer(&encode(&[(1, IN_MOVED_FROM, 7, "old")]));
        assert!(trailing_unpaired_move_from(&open));
        // A paired batch is complete.
        let paired = parse_event_buffer(&encode(&[
            (1, IN_MOVED_FROM, 7, "old"),
            (1, IN_MOVED_TO, 7, "new"),
        ]));
        assert!(!trailing_unpaired_move_from(&paired));
        // A trailing non-move event closes the window too.
        let closed = parse_event_buffer(&encode(&[
            (1, IN_MOVED_FROM, 7, "old"),
            (1, IN_CREATE, 0, "other"),
        ]));
        assert!(!trailing_unpaired_move_from(&closed));
        assert!(!trailing_unpaired_move_from(&[]));
    }

    #[test]
    fn overflow_is_detected() {
        let batch = parse_event_buffer(&encode(&[(-1, IN_Q_OVERFLOW, 0, "")]));
        assert!(has_overflow(&batch));
        assert!(!has_overflow(&parse_event_buffer(&encode(&[(
            1, IN_CREATE, 0, "f"
        )]))));
    }

    #[test]
    fn dir_flag_is_exposed_for_recursive_watch_maintenance() {
        let batch = parse_event_buffer(&encode(&[(1, IN_CREATE | IN_ISDIR, 0, "sub")]));
        assert!(batch[0].is_dir());
        let events = map_events(&batch, root_only);
        assert_eq!(events[0].kind, EVENT_CREATED);
    }
}
