//! From the port's specs to what Firecracker is told.
//!
//! The plans a render produces — the process to spawn ([`SpawnPlan`]), the
//! files a jail needs staged first ([`StagePlan`], executed by
//! [`jail::apply`](crate::jail::apply)), and the API payloads for a boot
//! ([`FcPlan`]) or a restore ([`FcRestorePlan`]). The renderer itself, the
//! one place that decides which path Firecracker sees for every host file,
//! follows.

mod plan;

pub use plan::{FcPlan, FcRestorePlan, SpawnMode, SpawnPlan, StageKind, StagePlan};

pub use crate::jail::Jail;
