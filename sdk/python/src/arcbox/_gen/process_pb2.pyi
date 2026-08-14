import datetime

from . import sandbox_pb2 as _sandbox_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ExecutionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EXECUTION_STATE_UNSPECIFIED: _ClassVar[ExecutionState]
    EXECUTION_STATE_RUNNING: _ClassVar[ExecutionState]
    EXECUTION_STATE_EXITED: _ClassVar[ExecutionState]

class StdioChannel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STDIO_CHANNEL_UNSPECIFIED: _ClassVar[StdioChannel]
    STDIO_CHANNEL_STDOUT: _ClassVar[StdioChannel]
    STDIO_CHANNEL_STDERR: _ClassVar[StdioChannel]
    STDIO_CHANNEL_PTY: _ClassVar[StdioChannel]

class Signal(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNAL_UNSPECIFIED: _ClassVar[Signal]
    SIGNAL_SIGHUP: _ClassVar[Signal]
    SIGNAL_SIGINT: _ClassVar[Signal]
    SIGNAL_SIGQUIT: _ClassVar[Signal]
    SIGNAL_SIGKILL: _ClassVar[Signal]
    SIGNAL_SIGUSR1: _ClassVar[Signal]
    SIGNAL_SIGUSR2: _ClassVar[Signal]
    SIGNAL_SIGTERM: _ClassVar[Signal]
EXECUTION_STATE_UNSPECIFIED: ExecutionState
EXECUTION_STATE_RUNNING: ExecutionState
EXECUTION_STATE_EXITED: ExecutionState
STDIO_CHANNEL_UNSPECIFIED: StdioChannel
STDIO_CHANNEL_STDOUT: StdioChannel
STDIO_CHANNEL_STDERR: StdioChannel
STDIO_CHANNEL_PTY: StdioChannel
SIGNAL_UNSPECIFIED: Signal
SIGNAL_SIGHUP: Signal
SIGNAL_SIGINT: Signal
SIGNAL_SIGQUIT: Signal
SIGNAL_SIGKILL: Signal
SIGNAL_SIGUSR1: Signal
SIGNAL_SIGUSR2: Signal
SIGNAL_SIGTERM: Signal

class TerminalSize(_message.Message):
    __slots__ = ("width", "height")
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    width: int
    height: int
    def __init__(self, width: _Optional[int] = ..., height: _Optional[int] = ...) -> None: ...

class Execution(_message.Message):
    __slots__ = ("id", "sandbox_id", "state", "tty", "started_at", "exited_at", "exit_status", "error", "stdout_len", "stderr_len", "stdin")
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    TTY_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    EXITED_AT_FIELD_NUMBER: _ClassVar[int]
    EXIT_STATUS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    STDOUT_LEN_FIELD_NUMBER: _ClassVar[int]
    STDERR_LEN_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_id: str
    state: ExecutionState
    tty: bool
    started_at: _timestamp_pb2.Timestamp
    exited_at: _timestamp_pb2.Timestamp
    exit_status: _sandbox_pb2.ExitStatus
    error: str
    stdout_len: int
    stderr_len: int
    stdin: StdinStatus
    def __init__(self, id: _Optional[str] = ..., sandbox_id: _Optional[str] = ..., state: _Optional[_Union[ExecutionState, str]] = ..., tty: _Optional[bool] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., exited_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., exit_status: _Optional[_Union[_sandbox_pb2.ExitStatus, _Mapping]] = ..., error: _Optional[str] = ..., stdout_len: _Optional[int] = ..., stderr_len: _Optional[int] = ..., stdin: _Optional[_Union[StdinStatus, _Mapping]] = ...) -> None: ...

class StartExecutionRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "cmd", "env", "working_dir", "user", "tty", "tty_size", "timeout_seconds", "stdin")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    TTY_FIELD_NUMBER: _ClassVar[int]
    TTY_SIZE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    cmd: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    working_dir: str
    user: str
    tty: bool
    tty_size: TerminalSize
    timeout_seconds: int
    stdin: bool
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., cmd: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., working_dir: _Optional[str] = ..., user: _Optional[str] = ..., tty: _Optional[bool] = ..., tty_size: _Optional[_Union[TerminalSize, _Mapping]] = ..., timeout_seconds: _Optional[int] = ..., stdin: _Optional[bool] = ...) -> None: ...

class AttachExecutionRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "stdout_offset", "stderr_offset")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    STDOUT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STDERR_OFFSET_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    stdout_offset: int
    stderr_offset: int
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., stdout_offset: _Optional[int] = ..., stderr_offset: _Optional[int] = ...) -> None: ...

class ExecutionEvent(_message.Message):
    __slots__ = ("started", "output", "exited", "keep_alive")
    STARTED_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    EXITED_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_FIELD_NUMBER: _ClassVar[int]
    started: ExecutionStarted
    output: ExecutionOutput
    exited: ExecutionExited
    keep_alive: _sandbox_pb2.KeepAlive
    def __init__(self, started: _Optional[_Union[ExecutionStarted, _Mapping]] = ..., output: _Optional[_Union[ExecutionOutput, _Mapping]] = ..., exited: _Optional[_Union[ExecutionExited, _Mapping]] = ..., keep_alive: _Optional[_Union[_sandbox_pb2.KeepAlive, _Mapping]] = ...) -> None: ...

class ExecutionStarted(_message.Message):
    __slots__ = ("execution",)
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    execution: Execution
    def __init__(self, execution: _Optional[_Union[Execution, _Mapping]] = ...) -> None: ...

class ExecutionOutput(_message.Message):
    __slots__ = ("channel", "offset", "data")
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    channel: StdioChannel
    offset: int
    data: bytes
    def __init__(self, channel: _Optional[_Union[StdioChannel, str]] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class ExecutionExited(_message.Message):
    __slots__ = ("execution",)
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    execution: Execution
    def __init__(self, execution: _Optional[_Union[Execution, _Mapping]] = ...) -> None: ...

class WriteStdinRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "offset", "data", "eof")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    offset: int
    data: bytes
    eof: bool
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ..., eof: _Optional[bool] = ...) -> None: ...

class StdinStatus(_message.Message):
    __slots__ = ("bytes_written", "closed")
    BYTES_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    CLOSED_FIELD_NUMBER: _ClassVar[int]
    bytes_written: int
    closed: bool
    def __init__(self, bytes_written: _Optional[int] = ..., closed: _Optional[bool] = ...) -> None: ...

class GetStdinStatusRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ...) -> None: ...

class SignalExecutionRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "signal")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    signal: Signal
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., signal: _Optional[_Union[Signal, str]] = ...) -> None: ...

class ResizeExecutionTtyRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "size")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    size: TerminalSize
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., size: _Optional[_Union[TerminalSize, _Mapping]] = ...) -> None: ...

class WaitExecutionRequest(_message.Message):
    __slots__ = ("sandbox_id", "execution_id", "timeout_seconds")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    execution_id: str
    timeout_seconds: int
    def __init__(self, sandbox_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., timeout_seconds: _Optional[int] = ...) -> None: ...

class ListExecutionsRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class ListExecutionsResponse(_message.Message):
    __slots__ = ("executions",)
    EXECUTIONS_FIELD_NUMBER: _ClassVar[int]
    executions: _containers.RepeatedCompositeFieldContainer[Execution]
    def __init__(self, executions: _Optional[_Iterable[_Union[Execution, _Mapping]]] = ...) -> None: ...

class WaitForPortRequest(_message.Message):
    __slots__ = ("sandbox_id", "port", "timeout_seconds")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    port: int
    timeout_seconds: int
    def __init__(self, sandbox_id: _Optional[str] = ..., port: _Optional[int] = ..., timeout_seconds: _Optional[int] = ...) -> None: ...
