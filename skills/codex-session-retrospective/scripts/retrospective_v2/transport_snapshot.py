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
        "import base64,hashlib,importlib.abc,importlib.util,json,os,stat,sys,zlib",
        "if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode: raise SystemExit('source transport Python isolation failed')",
        "identity=lambda meta:(meta.st_dev,meta.st_ino,meta.st_uid,meta.st_gid,meta.st_mode,meta.st_nlink,meta.st_size)",
        "def _read(path,limit,p,label):\n flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK\n fd=os.open(path,flags)\n try:\n  before=os.fstat(fd); named_before=os.stat(path,follow_symlinks=False); mode=stat.S_IMODE(before.st_mode)\n  policy=stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,os.geteuid()) and not mode&0o022\n  if p: policy=policy and before.st_uid==os.geteuid() and mode==0o600\n  if not policy or identity(named_before)!=identity(before): raise SystemExit(label+' authentication failed')\n  remaining=limit+1; chunks=[]\n  while remaining:\n   chunk=os.read(fd,min(65536,remaining))\n   if not chunk: break\n   chunks.append(chunk); remaining-=len(chunk)\n  data=b''.join(chunks); after=os.fstat(fd); named_after=os.stat(path,follow_symlinks=False)\n  if identity(after)!=identity(before) or identity(named_after)!=identity(before) or len(data)!=after.st_size or len(data)>limit: raise SystemExit(label+' authentication failed')\n  return data\n finally:\n  os.close(fd)",
        "marker,digest,snapshot_path=sys.argv[1:4]\npayload=_read(snapshot_path,4194304,True,'source transport snapshot')",
        "if marker!='source_transport_worker_snapshot_v1' or 'sha256:'+hashlib.sha256(payload).hexdigest()!=digest: raise SystemExit('source transport snapshot authentication failed')",
        "snapshot=json.loads(zlib.decompress(payload))\nruntime=snapshot['python_runtime']",
        "path=os.path.realpath(sys.executable)\nexecutable=_read(path,67108864,False,'source transport Python authority')",
        "component={'content_commitment':'sha256:'+hashlib.sha256(executable).hexdigest(),'path':path,'role':'python_interpreter','state':'present'}\nactual={'component':component,'executable':path,'implementation':sys.implementation.name,'schema':'source_transport_python_runtime_v1','version':list(sys.version_info)}",
        "if actual!=runtime: raise SystemExit('source transport Python authority changed')",
        "sources={name.removesuffix('.py'):base64.b64decode(content,validate=True) for name,content in snapshot['modules'].items()}\npaths={name.removesuffix('.py'):snapshot['package_dir']+'/'+name for name in snapshot['modules']}",
        "class _Loader(importlib.abc.Loader):\n def __init__(self,name): self.name=name\n def create_module(self,spec): return None\n def exec_module(self,module): module.__file__=paths[self.name]; exec(compile(sources[self.name],paths[self.name],'exec'),module.__dict__)",
        "class _Finder(importlib.abc.MetaPathFinder):\n def find_spec(self,fullname,path=None,target=None): return importlib.util.spec_from_loader(fullname,_Loader(fullname)) if fullname in sources else None",
        "sys.meta_path.insert(0,_Finder())\nsys.argv=[sys.argv[4],*sys.argv[5:]]",
        "sys._retrospective_v2_transport_snapshot=digest\nglobals()['__file__']=paths['transport_worker']\nexec(compile(sources['transport_worker'],paths['transport_worker'],'exec'),globals())",
    )
)
_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64 = base64.b64encode(
    zlib.compress(_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_SOURCE.encode("utf-8"), level=9)
).decode("ascii")
SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP = (
    "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("
    + repr(_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64)
    + ")),'<source-transport-snapshot>','exec'))"
)

_REMOTE_HELPER_BOOTSTRAP_SOURCE = "\n".join(
    (
        "import hashlib,os,stat,sys",
        "if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode: raise SystemExit('remote helper Python isolation failed')",
        "schema,digest,path=sys.argv[1:4]",
        "flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK\nfd=os.open(path,flags)",
        "try:\n before=os.fstat(fd); named_before=os.stat(path,follow_symlinks=False)\n remaining=4194305\n chunks=[]\n while remaining:\n  chunk=os.read(fd,min(65536,remaining))\n  if not chunk: break\n  chunks.append(chunk); remaining-=len(chunk)\n data=b''.join(chunks)\n after=os.fstat(fd); named_after=os.stat(path,follow_symlinks=False)\nfinally:\n os.close(fd)",
        "policy=lambda meta: stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o600 and meta.st_nlink==1\nidentity=lambda meta:(meta.st_dev,meta.st_ino,meta.st_uid,meta.st_gid,meta.st_mode,meta.st_nlink,meta.st_size)\nvalid=policy(before) and policy(after) and identity(before)==identity(after)==identity(named_before)==identity(named_after) and len(data)==after.st_size and len(data)<=4194304",
        "if schema!='remote_host_context_helper_snapshot_v1' or not valid or 'sha256:'+hashlib.sha256(data).hexdigest()!=digest: raise SystemExit('remote helper snapshot authentication failed')",
        "sys.argv=[path,*sys.argv[4:]]\nglobals()['__file__']=path",
        "exec(compile(data,path,'exec'),globals())",
    )
)
REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP = (
    "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("
    + repr(
        base64.b64encode(
            zlib.compress(_REMOTE_HELPER_BOOTSTRAP_SOURCE.encode("utf-8"), level=9)
        ).decode("ascii")
    )
    + ")),'<remote-helper-snapshot>','exec'))"
)
REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA = "remote_host_context_helper_snapshot_v1"


def _source_transport_snapshot_path(cache: pathlib.Path, digest: str) -> pathlib.Path:
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise TransportValidationError("source transport snapshot digest is invalid")
    return cache / f"{value}.snapshot"


def _source_transport_external_snapshot_path(
    cache: pathlib.Path,
    digest: str,
) -> pathlib.Path:
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise TransportValidationError(
            "source transport external snapshot digest is invalid"
        )
    return cache / f"remote-helper-{value}.py"


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
    stage_file: Callable[[pathlib.Path, bytes], None] | None = None,
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
    if stage_file is not None:
        stage_file(snapshot_path, payload)
    else:
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
    prepared_files: Mapping[pathlib.Path, bytes] | None = None,
    recover: bool = True,
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
    prepared = None if prepared_files is None else prepared_files.get(snapshot_path)
    try:
        if prepared is None:
            if recover:
                snapshot_io.recover_atomic_create(snapshot_path)
            component = component_reader(
                snapshot_path,
                role="program_snapshot",
                allow_missing=False,
                maximum_bytes=maximum_bytes,
                include_content=True,
            )
            payload = base64.b64decode(str(component["content_b64"]), validate=True)
        else:
            if not isinstance(prepared, bytes) or len(prepared) > maximum_bytes:
                raise ValueError("prepared source transport snapshot is invalid")
            payload = prepared
        snapshot = strict_json_loads(zlib.decompress(payload))
    except (
        OSError,
        TypeError,
        ValueError,
        zlib.error,
        snapshot_io.UnsafePathError,
    ) as exc:
        raise TransportValidationError("source transport snapshot is invalid") from exc
    if digest != "sha256:" + hashlib.sha256(payload).hexdigest() or not isinstance(
        snapshot, dict
    ):
        raise TransportValidationError("source transport snapshot digest changed")
    return snapshot, len(prefix) + 2, digest
