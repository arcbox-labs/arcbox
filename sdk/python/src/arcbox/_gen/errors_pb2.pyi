from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ERROR_CODE_UNSPECIFIED: _ClassVar[ErrorCode]
    ERROR_CODE_SANDBOX_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_TEMPLATE_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_EXECUTION_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_FILE_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_SANDBOX_PAUSED: _ClassVar[ErrorCode]
    ERROR_CODE_SANDBOX_NOT_READY: _ClassVar[ErrorCode]
    ERROR_CODE_SANDBOX_FAILED: _ClassVar[ErrorCode]
    ERROR_CODE_TTL_EXPIRED: _ClassVar[ErrorCode]
    ERROR_CODE_COMMAND_TIMEOUT: _ClassVar[ErrorCode]
    ERROR_CODE_NESTED_VIRT_UNSUPPORTED: _ClassVar[ErrorCode]
    ERROR_CODE_TEMPLATE_INVALID: _ClassVar[ErrorCode]
    ERROR_CODE_FILE_TOO_LARGE: _ClassVar[ErrorCode]
    ERROR_CODE_STDIN_CLOSED: _ClassVar[ErrorCode]
    ERROR_CODE_TTY_REQUIRED: _ClassVar[ErrorCode]
    ERROR_CODE_PORT_IN_USE: _ClassVar[ErrorCode]
    ERROR_CODE_AUTH_REQUIRED: _ClassVar[ErrorCode]
    ERROR_CODE_PROTOCOL_MISMATCH: _ClassVar[ErrorCode]
    ERROR_CODE_RESOURCE_EXHAUSTED_HOST: _ClassVar[ErrorCode]
ERROR_CODE_UNSPECIFIED: ErrorCode
ERROR_CODE_SANDBOX_NOT_FOUND: ErrorCode
ERROR_CODE_TEMPLATE_NOT_FOUND: ErrorCode
ERROR_CODE_EXECUTION_NOT_FOUND: ErrorCode
ERROR_CODE_FILE_NOT_FOUND: ErrorCode
ERROR_CODE_SANDBOX_PAUSED: ErrorCode
ERROR_CODE_SANDBOX_NOT_READY: ErrorCode
ERROR_CODE_SANDBOX_FAILED: ErrorCode
ERROR_CODE_TTL_EXPIRED: ErrorCode
ERROR_CODE_COMMAND_TIMEOUT: ErrorCode
ERROR_CODE_NESTED_VIRT_UNSUPPORTED: ErrorCode
ERROR_CODE_TEMPLATE_INVALID: ErrorCode
ERROR_CODE_FILE_TOO_LARGE: ErrorCode
ERROR_CODE_STDIN_CLOSED: ErrorCode
ERROR_CODE_TTY_REQUIRED: ErrorCode
ERROR_CODE_PORT_IN_USE: ErrorCode
ERROR_CODE_AUTH_REQUIRED: ErrorCode
ERROR_CODE_PROTOCOL_MISMATCH: ErrorCode
ERROR_CODE_RESOURCE_EXHAUSTED_HOST: ErrorCode

class ErrorInfo(_message.Message):
    __slots__ = ("code", "suggestion", "context")
    class ContextEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CODE_FIELD_NUMBER: _ClassVar[int]
    SUGGESTION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    code: ErrorCode
    suggestion: str
    context: _containers.ScalarMap[str, str]
    def __init__(self, code: _Optional[_Union[ErrorCode, str]] = ..., suggestion: _Optional[str] = ..., context: _Optional[_Mapping[str, str]] = ...) -> None: ...
