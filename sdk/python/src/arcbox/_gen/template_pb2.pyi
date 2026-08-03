import datetime

from . import sandbox_pb2 as _sandbox_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Template(_message.Message):
    __slots__ = ("name", "version", "digest", "rootfs_ref", "warm_snapshot_id", "defaults", "created_at", "labels", "size_bytes")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    ROOTFS_REF_FIELD_NUMBER: _ClassVar[int]
    WARM_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    DEFAULTS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    digest: str
    rootfs_ref: str
    warm_snapshot_id: str
    defaults: TemplateDefaults
    created_at: _timestamp_pb2.Timestamp
    labels: _containers.ScalarMap[str, str]
    size_bytes: int
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., digest: _Optional[str] = ..., rootfs_ref: _Optional[str] = ..., warm_snapshot_id: _Optional[str] = ..., defaults: _Optional[_Union[TemplateDefaults, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., labels: _Optional[_Mapping[str, str]] = ..., size_bytes: _Optional[int] = ...) -> None: ...

class TemplateDefaults(_message.Message):
    __slots__ = ("limits", "cmd", "env", "exposed_ports", "ready_probe")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    EXPOSED_PORTS_FIELD_NUMBER: _ClassVar[int]
    READY_PROBE_FIELD_NUMBER: _ClassVar[int]
    limits: _sandbox_pb2.ResourceLimits
    cmd: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    exposed_ports: _containers.RepeatedScalarFieldContainer[int]
    ready_probe: ReadyProbe
    def __init__(self, limits: _Optional[_Union[_sandbox_pb2.ResourceLimits, _Mapping]] = ..., cmd: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., exposed_ports: _Optional[_Iterable[int]] = ..., ready_probe: _Optional[_Union[ReadyProbe, _Mapping]] = ...) -> None: ...

class ReadyProbe(_message.Message):
    __slots__ = ("port", "command", "timeout_seconds")
    PORT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    port: int
    command: CommandProbe
    timeout_seconds: int
    def __init__(self, port: _Optional[int] = ..., command: _Optional[_Union[CommandProbe, _Mapping]] = ..., timeout_seconds: _Optional[int] = ...) -> None: ...

class CommandProbe(_message.Message):
    __slots__ = ("cmd",)
    CMD_FIELD_NUMBER: _ClassVar[int]
    cmd: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, cmd: _Optional[_Iterable[str]] = ...) -> None: ...

class BuildTemplateRequest(_message.Message):
    __slots__ = ("name", "docker_ref", "dockerfile", "snapshot_id", "defaults", "labels", "prewarm")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    DOCKER_REF_FIELD_NUMBER: _ClassVar[int]
    DOCKERFILE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    DEFAULTS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PREWARM_FIELD_NUMBER: _ClassVar[int]
    name: str
    docker_ref: str
    dockerfile: str
    snapshot_id: str
    defaults: TemplateDefaults
    labels: _containers.ScalarMap[str, str]
    prewarm: bool
    def __init__(self, name: _Optional[str] = ..., docker_ref: _Optional[str] = ..., dockerfile: _Optional[str] = ..., snapshot_id: _Optional[str] = ..., defaults: _Optional[_Union[TemplateDefaults, _Mapping]] = ..., labels: _Optional[_Mapping[str, str]] = ..., prewarm: _Optional[bool] = ...) -> None: ...

class PublishTemplateRequest(_message.Message):
    __slots__ = ("name", "version")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class GetTemplateRequest(_message.Message):
    __slots__ = ("reference",)
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    reference: str
    def __init__(self, reference: _Optional[str] = ...) -> None: ...

class ListTemplatesRequest(_message.Message):
    __slots__ = ("labels", "page_size", "page_token")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    labels: _containers.ScalarMap[str, str]
    page_size: int
    page_token: str
    def __init__(self, labels: _Optional[_Mapping[str, str]] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListTemplatesResponse(_message.Message):
    __slots__ = ("templates", "next_page_token")
    TEMPLATES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    templates: _containers.RepeatedCompositeFieldContainer[Template]
    next_page_token: str
    def __init__(self, templates: _Optional[_Iterable[_Union[Template, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class DeleteTemplateRequest(_message.Message):
    __slots__ = ("reference",)
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    reference: str
    def __init__(self, reference: _Optional[str] = ...) -> None: ...
