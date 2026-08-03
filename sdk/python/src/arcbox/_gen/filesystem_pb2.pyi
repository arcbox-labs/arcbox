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

class FileKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FILE_KIND_UNSPECIFIED: _ClassVar[FileKind]
    FILE_KIND_FILE: _ClassVar[FileKind]
    FILE_KIND_DIRECTORY: _ClassVar[FileKind]
    FILE_KIND_SYMLINK: _ClassVar[FileKind]
    FILE_KIND_OTHER: _ClassVar[FileKind]

class FsEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FS_EVENT_KIND_UNSPECIFIED: _ClassVar[FsEventKind]
    FS_EVENT_KIND_CREATED: _ClassVar[FsEventKind]
    FS_EVENT_KIND_MODIFIED: _ClassVar[FsEventKind]
    FS_EVENT_KIND_REMOVED: _ClassVar[FsEventKind]
    FS_EVENT_KIND_RENAMED: _ClassVar[FsEventKind]
FILE_KIND_UNSPECIFIED: FileKind
FILE_KIND_FILE: FileKind
FILE_KIND_DIRECTORY: FileKind
FILE_KIND_SYMLINK: FileKind
FILE_KIND_OTHER: FileKind
FS_EVENT_KIND_UNSPECIFIED: FsEventKind
FS_EVENT_KIND_CREATED: FsEventKind
FS_EVENT_KIND_MODIFIED: FsEventKind
FS_EVENT_KIND_REMOVED: FsEventKind
FS_EVENT_KIND_RENAMED: FsEventKind

class ReadFileRequest(_message.Message):
    __slots__ = ("id", "path")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class FileChunk(_message.Message):
    __slots__ = ("data", "done")
    DATA_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    done: bool
    def __init__(self, data: _Optional[bytes] = ..., done: _Optional[bool] = ...) -> None: ...

class WriteFileOpen(_message.Message):
    __slots__ = ("id", "path", "mode")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    mode: int
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ..., mode: _Optional[int] = ...) -> None: ...

class WriteFileRequest(_message.Message):
    __slots__ = ("open", "chunk")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    open: WriteFileOpen
    chunk: FileChunk
    def __init__(self, open: _Optional[_Union[WriteFileOpen, _Mapping]] = ..., chunk: _Optional[_Union[FileChunk, _Mapping]] = ...) -> None: ...

class FileStat(_message.Message):
    __slots__ = ("name", "kind", "size", "mode", "modified_at", "uid", "gid", "symlink_target")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_AT_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    GID_FIELD_NUMBER: _ClassVar[int]
    SYMLINK_TARGET_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: FileKind
    size: int
    mode: int
    modified_at: _timestamp_pb2.Timestamp
    uid: int
    gid: int
    symlink_target: str
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[FileKind, str]] = ..., size: _Optional[int] = ..., mode: _Optional[int] = ..., modified_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., uid: _Optional[int] = ..., gid: _Optional[int] = ..., symlink_target: _Optional[str] = ...) -> None: ...

class StatFileRequest(_message.Message):
    __slots__ = ("id", "path")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class ListDirRequest(_message.Message):
    __slots__ = ("id", "path")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class ListDirResponse(_message.Message):
    __slots__ = ("entries",)
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[FileStat]
    def __init__(self, entries: _Optional[_Iterable[_Union[FileStat, _Mapping]]] = ...) -> None: ...

class MakeDirRequest(_message.Message):
    __slots__ = ("id", "path", "mode")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    mode: int
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ..., mode: _Optional[int] = ...) -> None: ...

class RemoveEntryRequest(_message.Message):
    __slots__ = ("id", "path", "recursive")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    recursive: bool
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ..., recursive: _Optional[bool] = ...) -> None: ...

class MoveEntryRequest(_message.Message):
    __slots__ = ("id", "from_path", "to_path")
    ID_FIELD_NUMBER: _ClassVar[int]
    FROM_PATH_FIELD_NUMBER: _ClassVar[int]
    TO_PATH_FIELD_NUMBER: _ClassVar[int]
    id: str
    from_path: str
    to_path: str
    def __init__(self, id: _Optional[str] = ..., from_path: _Optional[str] = ..., to_path: _Optional[str] = ...) -> None: ...

class WatchDirRequest(_message.Message):
    __slots__ = ("id", "path", "recursive")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    id: str
    path: str
    recursive: bool
    def __init__(self, id: _Optional[str] = ..., path: _Optional[str] = ..., recursive: _Optional[bool] = ...) -> None: ...

class FsEvent(_message.Message):
    __slots__ = ("kind", "path", "renamed_to")
    KIND_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    RENAMED_TO_FIELD_NUMBER: _ClassVar[int]
    kind: FsEventKind
    path: str
    renamed_to: str
    def __init__(self, kind: _Optional[_Union[FsEventKind, str]] = ..., path: _Optional[str] = ..., renamed_to: _Optional[str] = ...) -> None: ...

class WatchDirResponse(_message.Message):
    __slots__ = ("event", "keep_alive")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_FIELD_NUMBER: _ClassVar[int]
    event: FsEvent
    keep_alive: _sandbox_pb2.KeepAlive
    def __init__(self, event: _Optional[_Union[FsEvent, _Mapping]] = ..., keep_alive: _Optional[_Union[_sandbox_pb2.KeepAlive, _Mapping]] = ...) -> None: ...
