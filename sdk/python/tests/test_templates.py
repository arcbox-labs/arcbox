"""Template catalog against a mock daemon: Template.build()/get()/list()/
delete_reference(), instance publish()/delete(), and Sandbox creation from
a Template instance.

The contracts under test: build maps exactly one source plus the
defaults/probe presence rules, publish freezes the draft under the
returned version, list auto-paginates, delete addresses the pinned
reference, errors carry the templates.* operation names, and create()
pins a Template instance's reference and carries the no-default flags.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2, message

from arcbox import ArcBox, Connection, Template, TemplateInfo
from arcbox._gen import sandbox_pb2, template_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import NotFoundError

if TYPE_CHECKING:
    from collections.abc import Callable

CREATED = datetime(2026, 8, 11, 8, 0, 0, tzinfo=timezone.utc)


def proto_response(body: message.Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=body.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def connection(handler: Callable[[httpx.Request], httpx.Response]) -> Connection:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Connection(http_client=http)


def template_row(**overrides: object) -> template_pb2.Template:
    row = template_pb2.Template(name="web", digest="sha256:abc", size_bytes=42)
    row.created_at.FromDatetime(CREATED)
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


class TestBuild:
    def test_maps_the_source_defaults_and_probe(self) -> None:
        requests: list[template_pb2.BuildTemplateRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/arcbox.sandbox.v1.TemplateService/Build")
            req = template_pb2.BuildTemplateRequest.FromString(request.content)
            requests.append(req)
            return proto_response(template_row())

        template = Template.build(
            "web",
            image="nginx:alpine",
            vcpus=2,
            cmd=["nginx", "-g", "daemon off;"],
            env={"MODE": "prod"},
            exposed_ports=[80],
            ready_probe_port=80,
            ready_probe_timeout=45,
            labels={"team": "infra"},
            prewarm=True,
            connection=connection(handler),
        )
        req = requests[0]
        assert req.WhichOneof("source") == "docker_ref"
        assert req.docker_ref == "nginx:alpine"
        assert req.defaults.limits.vcpus == 2
        assert req.defaults.limits.memory_mib == 0
        assert list(req.defaults.cmd) == ["nginx", "-g", "daemon off;"]
        assert dict(req.defaults.env) == {"MODE": "prod"}
        assert list(req.defaults.exposed_ports) == [80]
        assert req.defaults.ready_probe.port == 80
        assert req.defaults.ready_probe.timeout_seconds == 45
        assert dict(req.labels) == {"team": "infra"}
        assert req.prewarm is True
        # The result is the catalog draft row.
        assert template.name == "web"
        assert template.version == ""
        assert template.reference == "web"
        assert template.info == TemplateInfo(
            name="web",
            version="",
            digest="sha256:abc",
            size_bytes=42,
            created_at=CREATED,
        )

    def test_command_probe_and_dockerfile_source(self) -> None:
        requests: list[template_pb2.BuildTemplateRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            req = template_pb2.BuildTemplateRequest.FromString(request.content)
            requests.append(req)
            return proto_response(template_row())

        Template.build(
            "web",
            dockerfile="FROM alpine\n",
            ready_probe_command=["curl", "-f", "http://localhost/"],
            connection=connection(handler),
        )
        req = requests[0]
        assert req.WhichOneof("source") == "dockerfile"
        assert req.dockerfile == "FROM alpine\n"
        assert list(req.defaults.ready_probe.command.cmd) == ["curl", "-f", "http://localhost/"]
        assert req.defaults.ready_probe.port == 0

    def test_requires_exactly_one_source(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("no request expected")

        with pytest.raises(ValueError, match="exactly one"):
            Template.build("web", connection=connection(handler))
        with pytest.raises(ValueError, match="exactly one"):
            Template.build(
                "web",
                image="nginx",
                snapshot="snap-1",
                connection=connection(handler),
            )

    def test_rejects_both_probe_forms(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("no request expected")

        with pytest.raises(ValueError, match="mutually exclusive"):
            Template.build(
                "web",
                image="nginx",
                ready_probe_port=80,
                ready_probe_command=["true"],
                connection=connection(handler),
            )


class TestPublishAndDelete:
    def test_publish_freezes_the_draft_as_the_returned_version(self) -> None:
        requests: list[template_pb2.PublishTemplateRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/Build"):
                return proto_response(template_row())
            assert request.url.path.endswith("/Publish")
            req = template_pb2.PublishTemplateRequest.FromString(request.content)
            requests.append(req)
            return proto_response(template_row(version="1.2.0"))

        conn = connection(handler)
        draft = Template.build("web", image="nginx", connection=conn)
        published = draft.publish("1.2.0")
        assert requests[0].name == "web"
        assert requests[0].version == "1.2.0"
        assert published.reference == "web:1.2.0"
        # The draft handle is unchanged; publish returns a new instance.
        assert draft.reference == "web"

    def test_delete_addresses_the_pinned_reference(self) -> None:
        requests: list[template_pb2.DeleteTemplateRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/Get"):
                return proto_response(template_row(version="1.2.0"))
            assert request.url.path.endswith("/Delete")
            requests.append(template_pb2.DeleteTemplateRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())

        conn = connection(handler)
        Template.get("web:1.2.0", connection=conn).delete()
        Template.delete_reference("web", connection=conn)
        assert [req.reference for req in requests] == ["web:1.2.0", "web"]


class TestGetAndList:
    def test_get_resolves_the_reference(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/Get")
            req = template_pb2.GetTemplateRequest.FromString(request.content)
            assert req.reference == "web"
            return proto_response(template_row(version="2.0", warm_snapshot_id="snap-7"))

        template = Template.get("web", connection=connection(handler))
        assert template.reference == "web:2.0"
        assert template.info.warm is True

    def test_context_exit_closes_the_sdk_owned_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No injected http_client: the ConnectClient constructs (and owns)
        # its own httpx client. Route that construction through a recording
        # factory with a mock transport so the closure is observable —
        # with an injected client this test would be vacuous (close() is
        # unconditionally a no-op for caller-owned clients).
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/Get")
            return proto_response(template_row(version="2.0"))

        made: list[httpx.Client] = []
        real_client = httpx.Client

        def recording_client(**kwargs: object) -> httpx.Client:
            client = real_client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
            made.append(client)
            return client

        monkeypatch.setattr("arcbox._sync._client.httpx.Client", recording_client)
        with Template.get("web", connection=Connection(socket_path="/nowhere.sock")):
            pass
        assert len(made) == 1
        assert made[0].is_closed

    def test_a_shared_handle_never_closes_the_owners_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The opposite direction of the ownership contract: a handle that
        # shares another handle's client (here via publish) must NOT close
        # it — only the owning handle may. An unconditional close() would
        # pass the owning-direction test above and fail exactly here.
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/Get"):
                return proto_response(template_row())
            return proto_response(template_row(version="1.0"))

        made: list[httpx.Client] = []
        real_client = httpx.Client

        def recording_client(**kwargs: object) -> httpx.Client:
            client = real_client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
            made.append(client)
            return client

        monkeypatch.setattr("arcbox._sync._client.httpx.Client", recording_client)
        draft = Template.get("web", connection=Connection(socket_path="/nowhere.sock"))
        with draft.publish("1.0"):
            pass
        # One client total pins the premise: publish shares the draft's
        # client rather than minting an owning one of its own.
        assert len(made) == 1
        assert not made[0].is_closed
        draft.close()
        assert made[0].is_closed

    def test_get_wraps_a_miss_naming_the_operation(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps({"code": "not_found", "message": "template not found: web"}).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError) as exc_info:
            Template.get("web", connection=connection(handler))
        assert exc_info.value.operation == "templates.get"

    def test_list_auto_paginates_and_maps_rows(self) -> None:
        requests: list[template_pb2.ListTemplatesRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/List")
            req = template_pb2.ListTemplatesRequest.FromString(request.content)
            requests.append(req)
            if req.page_token == "":
                return proto_response(
                    template_pb2.ListTemplatesResponse(
                        templates=[template_row(version="1.0")],
                        next_page_token="page-2",
                    )
                )
            return proto_response(template_pb2.ListTemplatesResponse(templates=[template_row()]))

        rows = list(Template.list(labels={"team": "infra"}, connection=connection(handler)))
        assert [row.version for row in rows] == ["1.0", ""]
        assert rows[0] == TemplateInfo(
            name="web",
            version="1.0",
            digest="sha256:abc",
            size_bytes=42,
            created_at=CREATED,
        )
        assert [req.page_token for req in requests] == ["", "page-2"]
        assert dict(requests[0].labels) == {"team": "infra"}


class TestCreateFromTemplate:
    def test_pins_the_reference_and_carries_the_no_default_flags(self) -> None:
        requests: list[sandbox_pb2.CreateSandboxRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/arcbox.sandbox.v1.SandboxService/Create")
            req = sandbox_pb2.CreateSandboxRequest.FromString(request.content)
            requests.append(req)
            return proto_response(sandbox_pb2.CreateSandboxResponse(id=req.id))

        conn = connection(handler)
        template = Template(
            ConnectClient(conn),
            TemplateInfo(name="web", version="1.2.0", digest="sha256:abc"),
        )
        ArcBox(conn).create(
            template,
            no_default_cmd=True,
            no_default_env=True,
            wait_until_ready=False,
        )
        req = requests[0]
        assert req.template == "web:1.2.0"
        assert req.no_default_cmd is True
        assert req.no_default_env is True
        # No geometry flags: limits stays ABSENT so the template's default
        # limits are inherited (a present zero would replace them).
        assert not req.HasField("limits")
