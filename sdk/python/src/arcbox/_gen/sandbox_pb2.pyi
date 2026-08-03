import datetime

from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SandboxState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SANDBOX_STATE_UNSPECIFIED: _ClassVar[SandboxState]
    SANDBOX_STATE_STARTING: _ClassVar[SandboxState]
    SANDBOX_STATE_READY: _ClassVar[SandboxState]
    SANDBOX_STATE_RUNNING: _ClassVar[SandboxState]
    SANDBOX_STATE_STOPPING: _ClassVar[SandboxState]
    SANDBOX_STATE_STOPPED: _ClassVar[SandboxState]
    SANDBOX_STATE_FAILED: _ClassVar[SandboxState]
    SANDBOX_STATE_PAUSING: _ClassVar[SandboxState]
    SANDBOX_STATE_PAUSED: _ClassVar[SandboxState]

class SandboxEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SANDBOX_EVENT_KIND_UNSPECIFIED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_CREATED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_READY: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_RUNNING: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_IDLE: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_STOPPING: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_STOPPED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_FAILED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_REMOVED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_PAUSING: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_PAUSED: _ClassVar[SandboxEventKind]
    SANDBOX_EVENT_KIND_RESUMED: _ClassVar[SandboxEventKind]

class IdleAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    IDLE_ACTION_UNSPECIFIED: _ClassVar[IdleAction]
    IDLE_ACTION_KILL: _ClassVar[IdleAction]
    IDLE_ACTION_PAUSE: _ClassVar[IdleAction]

class NetworkMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NETWORK_MODE_UNSPECIFIED: _ClassVar[NetworkMode]
    NETWORK_MODE_ENABLED: _ClassVar[NetworkMode]
    NETWORK_MODE_NONE: _ClassVar[NetworkMode]

class PortProtocol(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PORT_PROTOCOL_UNSPECIFIED: _ClassVar[PortProtocol]
    PORT_PROTOCOL_TCP: _ClassVar[PortProtocol]
    PORT_PROTOCOL_UDP: _ClassVar[PortProtocol]
SANDBOX_STATE_UNSPECIFIED: SandboxState
SANDBOX_STATE_STARTING: SandboxState
SANDBOX_STATE_READY: SandboxState
SANDBOX_STATE_RUNNING: SandboxState
SANDBOX_STATE_STOPPING: SandboxState
SANDBOX_STATE_STOPPED: SandboxState
SANDBOX_STATE_FAILED: SandboxState
SANDBOX_STATE_PAUSING: SandboxState
SANDBOX_STATE_PAUSED: SandboxState
SANDBOX_EVENT_KIND_UNSPECIFIED: SandboxEventKind
SANDBOX_EVENT_KIND_CREATED: SandboxEventKind
SANDBOX_EVENT_KIND_READY: SandboxEventKind
SANDBOX_EVENT_KIND_RUNNING: SandboxEventKind
SANDBOX_EVENT_KIND_IDLE: SandboxEventKind
SANDBOX_EVENT_KIND_STOPPING: SandboxEventKind
SANDBOX_EVENT_KIND_STOPPED: SandboxEventKind
SANDBOX_EVENT_KIND_FAILED: SandboxEventKind
SANDBOX_EVENT_KIND_REMOVED: SandboxEventKind
SANDBOX_EVENT_KIND_PAUSING: SandboxEventKind
SANDBOX_EVENT_KIND_PAUSED: SandboxEventKind
SANDBOX_EVENT_KIND_RESUMED: SandboxEventKind
IDLE_ACTION_UNSPECIFIED: IdleAction
IDLE_ACTION_KILL: IdleAction
IDLE_ACTION_PAUSE: IdleAction
NETWORK_MODE_UNSPECIFIED: NetworkMode
NETWORK_MODE_ENABLED: NetworkMode
NETWORK_MODE_NONE: NetworkMode
PORT_PROTOCOL_UNSPECIFIED: PortProtocol
PORT_PROTOCOL_TCP: PortProtocol
PORT_PROTOCOL_UDP: PortProtocol

class NetworkSpec(_message.Message):
    __slots__ = ("mode",)
    MODE_FIELD_NUMBER: _ClassVar[int]
    mode: NetworkMode
    def __init__(self, mode: _Optional[_Union[NetworkMode, str]] = ...) -> None: ...

class Mount(_message.Message):
    __slots__ = ("source", "target", "readonly")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    READONLY_FIELD_NUMBER: _ClassVar[int]
    source: str
    target: str
    readonly: bool
    def __init__(self, source: _Optional[str] = ..., target: _Optional[str] = ..., readonly: _Optional[bool] = ...) -> None: ...

class ResourceLimits(_message.Message):
    __slots__ = ("vcpus", "memory_mib")
    VCPUS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    vcpus: int
    memory_mib: int
    def __init__(self, vcpus: _Optional[int] = ..., memory_mib: _Optional[int] = ...) -> None: ...

class ExitStatus(_message.Message):
    __slots__ = ("code", "signal")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    code: int
    signal: int
    def __init__(self, code: _Optional[int] = ..., signal: _Optional[int] = ...) -> None: ...

class KeepAlive(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CreateSandboxRequest(_message.Message):
    __slots__ = ("id", "labels", "limits", "cmd", "no_default_cmd", "env", "no_default_env", "working_dir", "user", "mounts", "network", "ttl_seconds", "ssh_public_key", "template", "idle_timeout_seconds", "on_idle")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    NO_DEFAULT_CMD_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    NO_DEFAULT_ENV_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    MOUNTS_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    SSH_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    IDLE_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ON_IDLE_FIELD_NUMBER: _ClassVar[int]
    id: str
    labels: _containers.ScalarMap[str, str]
    limits: ResourceLimits
    cmd: _containers.RepeatedScalarFieldContainer[str]
    no_default_cmd: bool
    env: _containers.ScalarMap[str, str]
    no_default_env: bool
    working_dir: str
    user: str
    mounts: _containers.RepeatedCompositeFieldContainer[Mount]
    network: NetworkSpec
    ttl_seconds: int
    ssh_public_key: str
    template: str
    idle_timeout_seconds: int
    on_idle: IdleAction
    def __init__(self, id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., limits: _Optional[_Union[ResourceLimits, _Mapping]] = ..., cmd: _Optional[_Iterable[str]] = ..., no_default_cmd: _Optional[bool] = ..., env: _Optional[_Mapping[str, str]] = ..., no_default_env: _Optional[bool] = ..., working_dir: _Optional[str] = ..., user: _Optional[str] = ..., mounts: _Optional[_Iterable[_Union[Mount, _Mapping]]] = ..., network: _Optional[_Union[NetworkSpec, _Mapping]] = ..., ttl_seconds: _Optional[int] = ..., ssh_public_key: _Optional[str] = ..., template: _Optional[str] = ..., idle_timeout_seconds: _Optional[int] = ..., on_idle: _Optional[_Union[IdleAction, str]] = ...) -> None: ...

class CreateSandboxResponse(_message.Message):
    __slots__ = ("id", "ip_address", "state")
    ID_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    id: str
    ip_address: str
    state: SandboxState
    def __init__(self, id: _Optional[str] = ..., ip_address: _Optional[str] = ..., state: _Optional[_Union[SandboxState, str]] = ...) -> None: ...

class StopSandboxRequest(_message.Message):
    __slots__ = ("id", "timeout_seconds")
    ID_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    id: str
    timeout_seconds: int
    def __init__(self, id: _Optional[str] = ..., timeout_seconds: _Optional[int] = ...) -> None: ...

class RemoveSandboxRequest(_message.Message):
    __slots__ = ("id", "force")
    ID_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    id: str
    force: bool
    def __init__(self, id: _Optional[str] = ..., force: _Optional[bool] = ...) -> None: ...

class PauseSandboxRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class ResumeSandboxRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class SetLifecycleRequest(_message.Message):
    __slots__ = ("id", "ttl_seconds", "idle_timeout_seconds", "on_idle")
    ID_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    IDLE_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ON_IDLE_FIELD_NUMBER: _ClassVar[int]
    id: str
    ttl_seconds: int
    idle_timeout_seconds: int
    on_idle: IdleAction
    def __init__(self, id: _Optional[str] = ..., ttl_seconds: _Optional[int] = ..., idle_timeout_seconds: _Optional[int] = ..., on_idle: _Optional[_Union[IdleAction, str]] = ...) -> None: ...

class GetCapabilitiesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetCapabilitiesResponse(_message.Message):
    __slots__ = ("daemon_version", "protocol", "features", "nested_virt")
    DAEMON_VERSION_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    NESTED_VIRT_FIELD_NUMBER: _ClassVar[int]
    daemon_version: str
    protocol: int
    features: _containers.RepeatedScalarFieldContainer[str]
    nested_virt: NestedVirtCapability
    def __init__(self, daemon_version: _Optional[str] = ..., protocol: _Optional[int] = ..., features: _Optional[_Iterable[str]] = ..., nested_virt: _Optional[_Union[NestedVirtCapability, _Mapping]] = ...) -> None: ...

class NestedVirtCapability(_message.Message):
    __slots__ = ("supported", "reason")
    SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    supported: bool
    reason: str
    def __init__(self, supported: _Optional[bool] = ..., reason: _Optional[str] = ...) -> None: ...

class InspectSandboxRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class SandboxInfo(_message.Message):
    __slots__ = ("id", "state", "labels", "limits", "network", "created_at", "ready_at", "last_exited_at", "last_exit_status", "error", "template", "ttl_deadline", "idle_timeout_seconds", "on_idle", "paused_at", "failed_at", "storage_bytes")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    READY_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_EXITED_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_EXIT_STATUS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    TTL_DEADLINE_FIELD_NUMBER: _ClassVar[int]
    IDLE_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ON_IDLE_FIELD_NUMBER: _ClassVar[int]
    PAUSED_AT_FIELD_NUMBER: _ClassVar[int]
    FAILED_AT_FIELD_NUMBER: _ClassVar[int]
    STORAGE_BYTES_FIELD_NUMBER: _ClassVar[int]
    id: str
    state: SandboxState
    labels: _containers.ScalarMap[str, str]
    limits: ResourceLimits
    network: SandboxNetwork
    created_at: _timestamp_pb2.Timestamp
    ready_at: _timestamp_pb2.Timestamp
    last_exited_at: _timestamp_pb2.Timestamp
    last_exit_status: ExitStatus
    error: str
    template: str
    ttl_deadline: _timestamp_pb2.Timestamp
    idle_timeout_seconds: int
    on_idle: IdleAction
    paused_at: _timestamp_pb2.Timestamp
    failed_at: _timestamp_pb2.Timestamp
    storage_bytes: int
    def __init__(self, id: _Optional[str] = ..., state: _Optional[_Union[SandboxState, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., limits: _Optional[_Union[ResourceLimits, _Mapping]] = ..., network: _Optional[_Union[SandboxNetwork, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ready_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last_exited_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last_exit_status: _Optional[_Union[ExitStatus, _Mapping]] = ..., error: _Optional[str] = ..., template: _Optional[str] = ..., ttl_deadline: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., idle_timeout_seconds: _Optional[int] = ..., on_idle: _Optional[_Union[IdleAction, str]] = ..., paused_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., failed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., storage_bytes: _Optional[int] = ...) -> None: ...

class SandboxNetwork(_message.Message):
    __slots__ = ("ip_address", "gateway")
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_FIELD_NUMBER: _ClassVar[int]
    ip_address: str
    gateway: str
    def __init__(self, ip_address: _Optional[str] = ..., gateway: _Optional[str] = ...) -> None: ...

class ListSandboxesRequest(_message.Message):
    __slots__ = ("state", "labels", "page_size", "page_token")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    STATE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    state: SandboxState
    labels: _containers.ScalarMap[str, str]
    page_size: int
    page_token: str
    def __init__(self, state: _Optional[_Union[SandboxState, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListSandboxesResponse(_message.Message):
    __slots__ = ("sandboxes", "next_page_token")
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    sandboxes: _containers.RepeatedCompositeFieldContainer[SandboxSummary]
    next_page_token: str
    def __init__(self, sandboxes: _Optional[_Iterable[_Union[SandboxSummary, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class SandboxSummary(_message.Message):
    __slots__ = ("id", "state", "labels", "ip_address", "created_at", "ready_at", "paused_at", "failed_at", "storage_bytes")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    READY_AT_FIELD_NUMBER: _ClassVar[int]
    PAUSED_AT_FIELD_NUMBER: _ClassVar[int]
    FAILED_AT_FIELD_NUMBER: _ClassVar[int]
    STORAGE_BYTES_FIELD_NUMBER: _ClassVar[int]
    id: str
    state: SandboxState
    labels: _containers.ScalarMap[str, str]
    ip_address: str
    created_at: _timestamp_pb2.Timestamp
    ready_at: _timestamp_pb2.Timestamp
    paused_at: _timestamp_pb2.Timestamp
    failed_at: _timestamp_pb2.Timestamp
    storage_bytes: int
    def __init__(self, id: _Optional[str] = ..., state: _Optional[_Union[SandboxState, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., ip_address: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ready_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., paused_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., failed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., storage_bytes: _Optional[int] = ...) -> None: ...

class SandboxEventsRequest(_message.Message):
    __slots__ = ("sandbox_id", "kind")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    kind: SandboxEventKind
    def __init__(self, sandbox_id: _Optional[str] = ..., kind: _Optional[_Union[SandboxEventKind, str]] = ...) -> None: ...

class WatchEventsResponse(_message.Message):
    __slots__ = ("event", "keep_alive")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_FIELD_NUMBER: _ClassVar[int]
    event: SandboxEvent
    keep_alive: KeepAlive
    def __init__(self, event: _Optional[_Union[SandboxEvent, _Mapping]] = ..., keep_alive: _Optional[_Union[KeepAlive, _Mapping]] = ...) -> None: ...

class SandboxEvent(_message.Message):
    __slots__ = ("sandbox_id", "kind", "time", "attributes")
    class AttributesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    kind: SandboxEventKind
    time: _timestamp_pb2.Timestamp
    attributes: _containers.ScalarMap[str, str]
    def __init__(self, sandbox_id: _Optional[str] = ..., kind: _Optional[_Union[SandboxEventKind, str]] = ..., time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., attributes: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ExposePortRequest(_message.Message):
    __slots__ = ("id", "sandbox_port", "host_port", "protocol")
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_PORT_FIELD_NUMBER: _ClassVar[int]
    HOST_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_port: int
    host_port: int
    protocol: PortProtocol
    def __init__(self, id: _Optional[str] = ..., sandbox_port: _Optional[int] = ..., host_port: _Optional[int] = ..., protocol: _Optional[_Union[PortProtocol, str]] = ...) -> None: ...

class ExposePortResponse(_message.Message):
    __slots__ = ("host_port", "guest_port")
    HOST_PORT_FIELD_NUMBER: _ClassVar[int]
    GUEST_PORT_FIELD_NUMBER: _ClassVar[int]
    host_port: int
    guest_port: int
    def __init__(self, host_port: _Optional[int] = ..., guest_port: _Optional[int] = ...) -> None: ...

class UnexposePortRequest(_message.Message):
    __slots__ = ("id", "sandbox_port", "protocol")
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_port: int
    protocol: PortProtocol
    def __init__(self, id: _Optional[str] = ..., sandbox_port: _Optional[int] = ..., protocol: _Optional[_Union[PortProtocol, str]] = ...) -> None: ...
