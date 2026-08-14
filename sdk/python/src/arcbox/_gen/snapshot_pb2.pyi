import datetime

from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CheckpointRequest(_message.Message):
    __slots__ = ("sandbox_id", "name", "labels")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    name: str
    labels: _containers.ScalarMap[str, str]
    def __init__(self, sandbox_id: _Optional[str] = ..., name: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CheckpointResponse(_message.Message):
    __slots__ = ("snapshot_id", "created_at")
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, snapshot_id: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class RestoreRequest(_message.Message):
    __slots__ = ("id", "snapshot_id", "labels", "network_override", "ttl_seconds")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    NETWORK_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    id: str
    snapshot_id: str
    labels: _containers.ScalarMap[str, str]
    network_override: bool
    ttl_seconds: int
    def __init__(self, id: _Optional[str] = ..., snapshot_id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., network_override: _Optional[bool] = ..., ttl_seconds: _Optional[int] = ...) -> None: ...

class RestoreResponse(_message.Message):
    __slots__ = ("id", "ip_address")
    ID_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    id: str
    ip_address: str
    def __init__(self, id: _Optional[str] = ..., ip_address: _Optional[str] = ...) -> None: ...

class ListSnapshotsRequest(_message.Message):
    __slots__ = ("sandbox_id", "labels", "page_size", "page_token")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    labels: _containers.ScalarMap[str, str]
    page_size: int
    page_token: str
    def __init__(self, sandbox_id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListSnapshotsResponse(_message.Message):
    __slots__ = ("snapshots", "next_page_token")
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    snapshots: _containers.RepeatedCompositeFieldContainer[SnapshotSummary]
    next_page_token: str
    def __init__(self, snapshots: _Optional[_Iterable[_Union[SnapshotSummary, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class SnapshotSummary(_message.Message):
    __slots__ = ("id", "sandbox_id", "name", "labels", "created_at")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_id: str
    name: str
    labels: _containers.ScalarMap[str, str]
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., sandbox_id: _Optional[str] = ..., name: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class DeleteSnapshotRequest(_message.Message):
    __slots__ = ("snapshot_id",)
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    def __init__(self, snapshot_id: _Optional[str] = ...) -> None: ...
