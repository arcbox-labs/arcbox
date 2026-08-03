use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

type OperationKey = (String, String);
type OperationMap = HashMap<OperationKey, Weak<AsyncMutex<()>>>;

#[derive(Default)]
pub(super) struct SandboxOperationLocks {
    entries: Mutex<OperationMap>,
}

impl SandboxOperationLocks {
    pub(super) async fn lock(
        &self,
        machine: &str,
        sandbox_id: &str,
    ) -> Option<OwnedMutexGuard<()>> {
        if sandbox_id.is_empty() {
            return None;
        }
        let lock = {
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|_, lock| lock.strong_count() > 0);
            let key = (machine.to_owned(), sandbox_id.to_owned());
            if let Some(lock) = entries.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                entries.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        Some(lock.lock_owned().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn same_sandbox_serializes_without_blocking_other_ids() {
        let locks = SandboxOperationLocks::default();
        let first = locks.lock("machine", "box").await.unwrap();
        assert!(locks.lock("machine", "other").await.is_some());

        let same = locks.lock("machine", "box");
        tokio::pin!(same);
        tokio::select! {
            biased;
            _ = &mut same => panic!("same sandbox lock should still be held"),
            () = tokio::task::yield_now() => {}
        }
        drop(first);
        assert!(same.await.is_some());
    }
}
