"""Regenerate `arcbox/_gen` from the repo's sandbox protos.

Runs the protoc bundled with grpcio-tools over
`rpc/arcbox-protocol/proto/arcbox/sandbox/v1`, then flattens the output
package and rewrites the intra-package imports to relative ones so the
generated modules are location-independent under `arcbox._gen`.

Usage: uv run python scripts/gen_proto.py
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

from grpc_tools import protoc

SDK_ROOT = Path(__file__).resolve().parent.parent
REPO_PROTO_DIR = SDK_ROOT.parent.parent / "rpc" / "arcbox-protocol" / "proto"
PROTO_PACKAGE_DIR = "arcbox/sandbox/v1"
GEN_DIR = SDK_ROOT / "src" / "arcbox" / "_gen"

GEN_INIT = '"""Generated wire types (protoc). Private — never exported."""\n'

# protoc emits absolute imports following the proto package path; the
# flattened modules live side by side, so both styles become relative.
IMPORT_REWRITES = [
    (re.compile(r"^from arcbox\.sandbox\.v1 import "), "from . import "),
    (re.compile(r"^import arcbox\.sandbox\.v1\."), "from . import "),
]


def well_known_include() -> str:
    """grpcio-tools bundles the well-known protos next to its package."""
    return str(Path(protoc.__file__).parent / "_proto")


def rewrite_imports(text: str) -> str:
    lines = []
    for line in text.splitlines(keepends=True):
        for pattern, replacement in IMPORT_REWRITES:
            line = pattern.sub(replacement, line)
        lines.append(line)
    return "".join(lines)


def main() -> int:
    protos = sorted((REPO_PROTO_DIR / PROTO_PACKAGE_DIR).glob("*.proto"))
    if not protos:
        print(f"no protos found under {REPO_PROTO_DIR / PROTO_PACKAGE_DIR}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        args = [
            "protoc",
            f"--proto_path={REPO_PROTO_DIR}",
            f"--proto_path={well_known_include()}",
            f"--python_out={tmp}",
            f"--pyi_out={tmp}",
            *(str(p) for p in protos),
        ]
        if (code := protoc.main(args)) != 0:
            return code

        if GEN_DIR.exists():
            shutil.rmtree(GEN_DIR)
        GEN_DIR.mkdir(parents=True)
        (GEN_DIR / "__init__.py").write_text(GEN_INIT)

        for generated in sorted((Path(tmp) / PROTO_PACKAGE_DIR).iterdir()):
            (GEN_DIR / generated.name).write_text(
                rewrite_imports(generated.read_text())
            )

    print(f"regenerated {GEN_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
