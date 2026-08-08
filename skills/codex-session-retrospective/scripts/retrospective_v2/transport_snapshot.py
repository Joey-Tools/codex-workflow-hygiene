"""Owner-private executable snapshots for source transport workers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import pathlib
import zlib
from typing import Callable, Mapping, Sequence

try:
    from .contracts import JsonValue, canonical_json_bytes, strict_json_loads
    from .transport_contracts import TransportValidationError
except (ImportError, ModuleNotFoundError):
    from contracts import (  # type: ignore[no-redef]
        JsonValue,
        canonical_json_bytes,
        strict_json_loads,
    )
    from transport_contracts import (  # type: ignore[no-redef]
        TransportValidationError,
    )


_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_SOURCE = "\n".join(
    (
        "import base64,hashlib,importlib.abc,importlib.util,json,os,sys,zlib",
        "marker,digest,snapshot_path=sys.argv[1:4]\nwith open(snapshot_path,'rb') as handle: payload=handle.read(4194305)",
        "if marker!='source_transport_worker_snapshot_v1' or 'sha256:'+hashlib.sha256(payload).hexdigest()!=digest: raise SystemExit('source transport snapshot authentication failed')\nif len(payload)>4194304: raise SystemExit('source transport snapshot exceeds its bound')",
        "snapshot=json.loads(zlib.decompress(payload))\nruntime=snapshot['python_runtime']",
        "path=os.path.realpath(sys.executable)\nwith open(path,'rb') as handle: executable=handle.read(67108865)",
        "component={'content_commitment':'sha256:'+hashlib.sha256(executable).hexdigest(),'path':path,'role':'python_interpreter','state':'present'}\nactual={'component':component,'executable':sys.executable,'implementation':sys.implementation.name,'schema':'source_transport_python_runtime_v1','version':list(sys.version_info)}",
        "if len(executable)>67108864 or actual!=runtime: raise SystemExit('source transport Python authority changed')",
        "sources={name.removesuffix('.py'):base64.b64decode(content,validate=True) for name,content in snapshot['modules'].items()}\npaths={name.removesuffix('.py'):snapshot['package_dir']+'/'+name for name in snapshot['modules']}",
        "class _Loader(importlib.abc.Loader):\n def __init__(self,name): self.name=name\n def create_module(self,spec): return None\n def exec_module(self,module): module.__file__=paths[self.name]; exec(compile(sources[self.name],paths[self.name],'exec'),module.__dict__)",
        "class _Finder(importlib.abc.MetaPathFinder):\n def find_spec(self,fullname,path=None,target=None): return importlib.util.spec_from_loader(fullname,_Loader(fullname)) if fullname in sources else None",
        "sys.meta_path.insert(0,_Finder())\nsys.argv=[sys.argv[4],*sys.argv[5:]]",
        "sys._retrospective_v2_transport_snapshot=digest\nglobals()['__file__']=paths['transport_worker']\nexec(compile(sources['transport_worker'],paths['transport_worker'],'exec'),globals())",
    )
)
_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64 = base64.b64encode(
    _SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_SOURCE.encode("utf-8")
).decode("ascii")
SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP = (
    "import base64;exec(compile(base64.b64decode("
    + repr(_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64)
    + "),'<source-transport-snapshot>','exec'))"
)


def _source_transport_snapshot_path(cache: pathlib.Path, digest: str) -> pathlib.Path:
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise TransportValidationError("source transport snapshot digest is invalid")
    return cache / f"{value}.snapshot"


def _source_transport_snapshot_flags(
    *,
    package_dir: pathlib.Path,
    components: Sequence[Mapping[str, JsonValue]],
    module_manifest: Sequence[str],
    python_runtime: Mapping[str, JsonValue],
    base_flags: Sequence[str],
    schema: str,
    cache: pathlib.Path,
    maximum_bytes: int,
) -> tuple[str, ...]:
    try:
        from . import safe_io as snapshot_io
    except ImportError:
        import safe_io as snapshot_io  # type: ignore[no-redef]

    snapshot = {
        "modules": {
            name: str(component["content_b64"])
            for name, component in zip(module_manifest, components, strict=True)
        },
        "package_dir": str(package_dir),
        "python_runtime": dict(python_runtime),
        "schema": schema,
    }
    payload = zlib.compress(canonical_json_bytes(snapshot), level=9)
    if not payload or len(payload) > maximum_bytes:
        raise TransportValidationError("source transport program snapshot is too large")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    snapshot_path = _source_transport_snapshot_path(cache, digest)
    snapshot_io.ensure_owner_only_directory(snapshot_path.parent)
    try:
        snapshot_io.atomic_create_bytes(
            snapshot_path,
            payload,
            create_parents=False,
        )
    except FileExistsError:
        try:
            existing = snapshot_io.read_bounded_bytes(
                snapshot_path,
                max_bytes=maximum_bytes,
                require_owner_only=True,
            )
        except (OSError, snapshot_io.UnsafePathError) as exc:
            raise TransportValidationError(
                "source transport program snapshot is invalid"
            ) from exc
        if not hmac.compare_digest(existing, payload):
            raise TransportValidationError(
                "source transport program snapshot digest changed"
            )
    return (
        *base_flags,
        "-c",
        SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP,
        schema,
        digest,
        str(snapshot_path),
    )


def _source_transport_decode_snapshot(
    argv: tuple[str, ...],
    *,
    prefix: tuple[str, ...],
    cache: pathlib.Path,
    maximum_bytes: int,
    component_reader: Callable[..., Mapping[str, JsonValue]],
) -> tuple[dict[str, JsonValue], int, str]:
    try:
        from . import safe_io as snapshot_io
    except ImportError:
        import safe_io as snapshot_io  # type: ignore[no-redef]

    if argv[: len(prefix)] != prefix or len(argv) < len(prefix) + 4:
        raise TransportValidationError("source transport command is incomplete")
    digest = argv[len(prefix)]
    snapshot_path = pathlib.Path(argv[len(prefix) + 1])
    if snapshot_path != _source_transport_snapshot_path(cache, digest):
        raise TransportValidationError("source transport snapshot path is invalid")
    try:
        snapshot_io.recover_atomic_create(snapshot_path)
        component = component_reader(
            snapshot_path,
            role="program_snapshot",
            allow_missing=False,
            maximum_bytes=maximum_bytes,
            include_content=True,
        )
        payload = base64.b64decode(str(component["content_b64"]), validate=True)
        snapshot = strict_json_loads(zlib.decompress(payload))
    except (OSError, ValueError, zlib.error, snapshot_io.UnsafePathError) as exc:
        raise TransportValidationError("source transport snapshot is invalid") from exc
    if digest != "sha256:" + hashlib.sha256(payload).hexdigest() or not isinstance(
        snapshot, dict
    ):
        raise TransportValidationError("source transport snapshot digest changed")
    return snapshot, len(prefix) + 2, digest
