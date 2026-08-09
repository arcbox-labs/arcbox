//! User-facing CLI error context.

use std::fmt;

use anyhow::Error;
use connectrpc::{ConnectError, ErrorCode};

#[derive(Debug)]
struct ActionableError {
    message: String,
    source: ConnectError,
}

impl fmt::Display for ActionableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ActionableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub fn machine_request(error: ConnectError, name: &str, operation: &str) -> Error {
    let message = match error.code {
        ErrorCode::NotFound => {
            format!("Machine '{name}' was not found. List machines with `abctl machine list`.")
        }
        ErrorCode::FailedPrecondition => format!(
            "Machine '{name}' must be running for {operation}. Start it with \
             `abctl machine start {name}`."
        ),
        ErrorCode::Unavailable => format!(
            "Machine '{name}' is unavailable during {operation}. Retry the command; if the \
             problem persists, check `abctl daemon status`."
        ),
        _ => format!("Could not perform {operation} for machine '{name}'."),
    };
    actionable(message, error)
}

pub fn machine_operation(error: ConnectError, name: &str, action: &str) -> Error {
    let message = match error.code {
        ErrorCode::NotFound => {
            format!("Machine '{name}' was not found. List machines with `abctl machine list`.")
        }
        ErrorCode::FailedPrecondition => format!(
            "Machine '{name}' is not in a valid state for this operation. Inspect it with \
             `abctl machine inspect {name}`."
        ),
        ErrorCode::Unavailable => format!(
            "Machine '{name}' is unavailable. Retry the command; if the problem persists, \
             check `abctl daemon status`."
        ),
        _ => format!("Could not {action} machine '{name}'."),
    };
    actionable(message, error)
}

pub fn sandbox_request(error: ConnectError, id: &str, operation: &str) -> Error {
    let message = match error.code {
        ErrorCode::NotFound => {
            format!("Sandbox '{id}' was not found. List sandboxes with `abctl sandbox list`.")
        }
        ErrorCode::FailedPrecondition => format!(
            "Sandbox '{id}' is not ready for {operation}. Inspect it with \
             `abctl sandbox inspect {id}`."
        ),
        ErrorCode::Unavailable => format!(
            "Sandbox '{id}' is unavailable during {operation}. Retry the command; if the \
             problem persists, check `abctl daemon status`."
        ),
        _ => format!("Could not perform {operation} for sandbox '{id}'."),
    };
    actionable(message, error)
}

pub fn snapshot_request(error: ConnectError, id: &str, operation: &str) -> Error {
    let message = match error.code {
        ErrorCode::NotFound => {
            format!("Snapshot '{id}' was not found. List snapshots with `abctl sandbox snapshots`.")
        }
        ErrorCode::FailedPrecondition => format!(
            "Snapshot '{id}' is not in a valid state for {operation}. List snapshots with \
             `abctl sandbox snapshots`."
        ),
        ErrorCode::Unavailable => format!(
            "Snapshot '{id}' is unavailable during {operation}. Retry the command; if the \
             problem persists, check `abctl daemon status`."
        ),
        _ => format!("Could not perform {operation} for snapshot '{id}'."),
    };
    actionable(message, error)
}

pub fn execution_wait(error: ConnectError, sandbox_id: &str, execution_id: &str) -> Error {
    let message = match error.code {
        ErrorCode::NotFound => {
            format!("Execution '{execution_id}' was not found in sandbox '{sandbox_id}'.")
        }
        ErrorCode::Unavailable => format!(
            "Sandbox '{sandbox_id}' is unavailable while waiting for execution \
             '{execution_id}'. Retry the command; if the problem persists, check \
             `abctl daemon status`."
        ),
        _ => format!(
            "Could not determine the exit status of execution '{execution_id}' in sandbox \
             '{sandbox_id}'."
        ),
    };
    actionable(message, error)
}

pub fn machine_exec_output(error: ConnectError, name: &str, command: &str) -> Error {
    let message = if connection_lost(&error) {
        format!("Connection to machine '{name}' was lost while running '{command}'.")
    } else {
        match error.code {
            ErrorCode::NotFound => {
                format!("Command '{command}' was not found in machine '{name}'.")
            }
            _ => format!("Could not read output from '{command}' in machine '{name}'."),
        }
    };
    actionable(message, error)
}

fn actionable(message: String, source: ConnectError) -> Error {
    Error::new(ActionableError { message, source })
}

fn connection_lost(error: &ConnectError) -> bool {
    if error.code == ErrorCode::Unavailable {
        return true;
    }
    // connectrpc c5c1a6f reports body-read and missing-END_STREAM failures as these Internal messages.
    error.code == ErrorCode::Internal
        && error.message.as_deref().is_some_and(|message| {
            message.starts_with("error reading response body:")
                || message == "Connect streaming response ended without END_STREAM envelope"
        })
}

pub fn render(error: &Error, debug: bool) -> String {
    if debug {
        format!("Error: {error:?}")
    } else if let Some(actionable) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ActionableError>())
    {
        format!("Error: {actionable}")
    } else {
        format!("Error: {error:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_errors_are_actionable_and_keep_debug_context() {
        let stopped = machine_request(
            ConnectError::failed_precondition("invalid state: CID not assigned"),
            "dev",
            "ping",
        );
        assert_eq!(
            render(&stopped, false),
            "Error: Machine 'dev' must be running for ping. Start it with \
             `abctl machine start dev`."
        );
        assert!(render(&stopped, true).contains("invalid state: CID not assigned"));

        let missing = sandbox_request(
            ConnectError::not_found("core error: VM not found"),
            "gone",
            "inspection",
        );
        assert_eq!(
            render(&missing, false),
            "Error: Sandbox 'gone' was not found. List sandboxes with \
             `abctl sandbox list`."
        );
        assert!(render(&missing, true).contains("core error: VM not found"));

        let already_running = machine_operation(
            ConnectError::failed_precondition("machine already running"),
            "dev",
            "start",
        );
        assert_eq!(
            render(&already_running, false),
            "Error: Machine 'dev' is not in a valid state for this operation. Inspect it with \
             `abctl machine inspect dev`."
        );
        assert!(render(&already_running, true).contains("machine already running"));

        let missing_execution = execution_wait(
            ConnectError::not_found("execution not found"),
            "sandbox-1",
            "exec-2",
        );
        assert_eq!(
            render(&missing_execution, false),
            "Error: Execution 'exec-2' was not found in sandbox 'sandbox-1'."
        );

        let unmapped = Error::msg("VM not found").context("Failed to inspect another resource");
        let rendered = render(&unmapped, false);
        assert!(rendered.contains("Failed to inspect another resource"));
        assert!(rendered.contains("VM not found"));
    }

    #[test]
    fn exec_errors_distinguish_command_transport_and_output_failures() {
        let missing = machine_exec_output(
            ConnectError::not_found("command not found: nope"),
            "dev",
            "nope",
        );
        assert_eq!(
            missing.to_string(),
            "Command 'nope' was not found in machine 'dev'."
        );

        let transport = machine_exec_output(
            ConnectError::unavailable("h2 connection closed"),
            "dev",
            "date",
        );
        assert_eq!(
            transport.to_string(),
            "Connection to machine 'dev' was lost while running 'date'."
        );

        let truncated = machine_exec_output(
            ConnectError::internal("Connect streaming response ended without END_STREAM envelope"),
            "dev",
            "date",
        );
        assert_eq!(
            truncated.to_string(),
            "Connection to machine 'dev' was lost while running 'date'."
        );

        let output = machine_exec_output(
            ConnectError::internal("failed to decode response"),
            "dev",
            "date",
        );
        assert_eq!(
            output.to_string(),
            "Could not read output from 'date' in machine 'dev'."
        );
    }
}
