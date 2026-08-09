use crate::rpc::ErrorResponse;

pub(super) fn spawn_error(command: &str, error: std::io::Error) -> ErrorResponse {
    if error.kind() == std::io::ErrorKind::NotFound {
        ErrorResponse::new(404, format!("command not found: '{command}': {error}"))
    } else {
        ErrorResponse::new(500, format!("failed to spawn command '{command}': {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_error_classifies_missing_commands() {
        let missing = spawn_error(
            "nope",
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        );
        assert_eq!(missing.code, 404);
        assert!(missing.message.contains("nope"));

        let other = spawn_error("nope", std::io::Error::other("boom"));
        assert_eq!(other.code, 500);
    }
}
