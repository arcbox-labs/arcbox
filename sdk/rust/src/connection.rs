//! Connecting to the daemon: option and environment resolution.
//!
//! Resolution order: explicit option > environment > default, matching
//! the TypeScript and Python SDKs.
//!
//! | Environment      | Meaning                                             |
//! |------------------|-----------------------------------------------------|
//! | `ARCBOX_SOCKET`  | daemon Unix socket                                  |
//! | `ARCBOX_DATA_DIR`| data dir whose `run/arcbox.sock` is the default     |
//! | `ARCBOX_PROFILE` | `development` switches the default to `~/.arcbox-dev` |
//! | `ARCBOX_API_URL` | remote tier (reserved, CORE-63) — not supported here yet |

use std::env;
use std::path::PathBuf;

use crate::error::{Error, ErrorKind};

/// How to reach the daemon. `Connection::default()` resolves from the
/// environment; [`Connection::socket_path`] overrides it.
#[derive(Debug, Clone, Default)]
pub struct Connection {
    socket_path: Option<PathBuf>,
}

impl Connection {
    /// A connection resolved from the environment (see the module docs).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use this daemon socket, ignoring the environment.
    #[must_use]
    pub fn socket_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = Some(path.into());
        self
    }

    /// The socket this connection addresses.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`] when `ARCBOX_API_URL` selects the
    /// remote tier (this SDK does not speak it yet) or no home directory
    /// exists to anchor the default data dir.
    pub(crate) fn resolve(&self) -> Result<PathBuf, Error> {
        if let Some(path) = &self.socket_path {
            return Ok(path.clone());
        }
        if let Some(socket) = env_non_empty("ARCBOX_SOCKET") {
            return Ok(PathBuf::from(socket));
        }
        if env_non_empty("ARCBOX_API_URL").is_some() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "ARCBOX_API_URL selects the remote tier, which the Rust SDK \
                 does not support yet",
                "connection.resolve",
            )
            .with_suggestion(
                "unset ARCBOX_API_URL or point ARCBOX_SOCKET at a local daemon socket",
            ));
        }
        let data_dir = match env_non_empty("ARCBOX_DATA_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => {
                let home = env_non_empty("HOME").map(PathBuf::from).ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidArgument,
                        "no HOME directory to anchor the default ArcBox data dir",
                        "connection.resolve",
                    )
                    .with_suggestion("set ARCBOX_SOCKET or ARCBOX_DATA_DIR explicitly")
                })?;
                let profile_dir = match env_non_empty("ARCBOX_PROFILE").as_deref() {
                    Some("development") => ".arcbox-dev",
                    _ => ".arcbox",
                };
                home.join(profile_dir)
            }
        };
        Ok(data_dir.join("run").join("arcbox.sock"))
    }
}

/// A set, non-empty environment variable — unset and empty are the same
/// "not configured" state, as in the sibling SDKs.
fn env_non_empty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_socket_path_wins_over_everything() {
        let connection = Connection::new().socket_path("/tmp/explicit.sock");
        assert_eq!(
            connection.resolve().unwrap(),
            PathBuf::from("/tmp/explicit.sock")
        );
    }
}
