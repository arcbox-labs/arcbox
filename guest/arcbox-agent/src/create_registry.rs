//! In-flight and completed sandbox creates keyed by caller-supplied ID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arcbox_connect::sandbox_v1::{CreateSandboxRequest, CreateSandboxResponse};
use tokio::sync::watch;

/// Coordinates idempotent sandbox creates for one guest-agent process.
#[derive(Default)]
pub struct CreateRegistry {
    entries: Mutex<HashMap<String, Entry>>,
}

enum Entry {
    Pending {
        request: CreateSandboxRequest,
        done: watch::Sender<bool>,
    },
    Completed {
        request: CreateSandboxRequest,
        response: CreateSandboxResponse,
    },
}

/// Result of reserving a caller-supplied sandbox ID.
pub enum Reserve {
    Existing(CreateSandboxResponse),
    Slot(SlotGuard),
    AwaitPending(watch::Receiver<bool>),
}

/// The ID belongs to a different create request.
#[derive(Debug)]
pub struct Collision;

/// Removes an unfinished reservation on drop.
pub struct SlotGuard {
    registry: Arc<CreateRegistry>,
    id: String,
    committed: bool,
}

impl SlotGuard {
    /// Publish the response before waking matching retries.
    pub(crate) fn commit(mut self, response: &CreateSandboxResponse) {
        let mut entries = self.registry.entries.lock().unwrap();
        let Some(Entry::Pending { request, done }) = entries.remove(&self.id) else {
            unreachable!("a create slot stays pending until commit or drop");
        };
        entries.insert(
            self.id.clone(),
            Entry::Completed {
                request,
                response: response.clone(),
            },
        );
        self.committed = true;
        drop(entries);
        let _ = done.send(true);
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let entry = self.registry.entries.lock().unwrap().remove(&self.id);
        if let Some(Entry::Pending { done, .. }) = entry {
            let _ = done.send(true);
        }
    }
}

impl CreateRegistry {
    /// Reserve an ID, replay its response, or wait for its matching request.
    pub(crate) fn reserve(
        self: &Arc<Self>,
        request: &CreateSandboxRequest,
    ) -> Result<Reserve, Collision> {
        debug_assert!(!request.id.is_empty());
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&request.id) {
            Some(Entry::Completed {
                request: existing,
                response,
                ..
            }) if existing == request => return Ok(Reserve::Existing(response.clone())),
            Some(Entry::Pending {
                request: existing,
                done,
            }) if existing == request => {
                return Ok(Reserve::AwaitPending(done.subscribe()));
            }
            Some(_) => return Err(Collision),
            None => {}
        }

        entries.insert(
            request.id.clone(),
            Entry::Pending {
                request: request.clone(),
                done: watch::channel(false).0,
            },
        );
        Ok(Reserve::Slot(SlotGuard {
            registry: Arc::clone(self),
            id: request.id.clone(),
            committed: false,
        }))
    }

    /// Forget a completed response when its sandbox is no longer live.
    pub(crate) fn clear_completed_if(&self, id: &str, should_clear: impl FnOnce() -> bool) {
        let mut entries = self.entries.lock().unwrap();
        if matches!(entries.get(id), Some(Entry::Completed { .. })) && should_clear() {
            entries.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request(template: &str) -> CreateSandboxRequest {
        CreateSandboxRequest {
            id: "fixed-id".into(),
            template: template.into(),
            ..CreateSandboxRequest::default()
        }
    }

    #[tokio::test]
    async fn matching_retry_waits_and_replays_the_original_response() {
        let registry = Arc::new(CreateRegistry::default());
        let request = create_request("docker:alpine");
        let Reserve::Slot(slot) = registry.reserve(&request).unwrap() else {
            panic!("first create must reserve the ID");
        };
        let Reserve::AwaitPending(mut waiter) = registry.reserve(&request).unwrap() else {
            panic!("matching retry must wait");
        };

        let response = CreateSandboxResponse {
            id: request.id.clone(),
            ip_address: "172.20.0.2".into(),
            ..CreateSandboxResponse::default()
        };
        slot.commit(&response);
        waiter.changed().await.expect("commit wakes retry");

        let Reserve::Existing(replayed) = registry.reserve(&request).unwrap() else {
            panic!("completed create must replay");
        };
        assert_eq!(replayed, response);
        assert!(registry.reserve(&create_request("docker:debian")).is_err());
    }

    #[tokio::test]
    async fn failed_create_releases_the_id() {
        let registry = Arc::new(CreateRegistry::default());
        let request = create_request("");
        let Reserve::Slot(slot) = registry.reserve(&request).unwrap() else {
            panic!("first create must reserve the ID");
        };
        let Reserve::AwaitPending(mut waiter) = registry.reserve(&request).unwrap() else {
            panic!("matching retry must wait");
        };
        drop(slot);
        waiter.changed().await.expect("drop wakes retry");
        assert!(matches!(
            registry.reserve(&request).unwrap(),
            Reserve::Slot(_)
        ));
    }

    #[test]
    fn stale_completed_create_releases_the_id() {
        let registry = Arc::new(CreateRegistry::default());
        let request = create_request("");
        let Reserve::Slot(slot) = registry.reserve(&request).unwrap() else {
            panic!("first create must reserve the ID");
        };
        let response = CreateSandboxResponse {
            id: request.id.clone(),
            ..CreateSandboxResponse::default()
        };
        slot.commit(&response);
        registry.clear_completed_if(&request.id, || false);
        assert!(matches!(
            registry.reserve(&request).unwrap(),
            Reserve::Existing(_)
        ));

        registry.clear_completed_if(&request.id, || true);
        assert!(matches!(
            registry.reserve(&request).unwrap(),
            Reserve::Slot(_)
        ));
    }
}
