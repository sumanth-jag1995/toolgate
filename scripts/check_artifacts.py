"""Verify built distributions: file list equals the manifest and no secrets inside."""

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

KINDS = ("wheel", "sdist")


class ArtifactCheckError(Exception):
    """Tooling or input problem (not a finding)."""


def _safe_relative(name: str, strip_first: bool = False) -> str | None:
    """Return a normalized relative path, raising on traversal; None for directories."""
    posix = name.replace("\\", "/")
    path = PurePosixPath(posix)
    if path.is_absolute() or ".." in path.parts or (len(posix) > 1 and posix[1] == ":"):
        raise ArtifactCheckError(f"unsafe archive member: {name}")
    parts = path.parts[1:] if strip_first else path.parts
    if not parts or posix.endswith("/"):
        return None
    return "/".join(parts)


def _write(dest: Path, rel: str, data: bytes) -> None:
    target = dest / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def unpack_dist(dist_dir: Path, dest: Path) -> dict[str, list[str]]:
    """Extract the wheel and sdist in dist_dir into dest/<kind>/; return sorted file lists."""
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ArtifactCheckError(
            f"expected exactly one wheel and one sdist in {dist_dir}, "
            f"found {len(wheels)} and {len(sdists)}"
        )
    found: dict[str, list[str]] = {"wheel": [], "sdist": []}
    with zipfile.ZipFile(wheels[0]) as zf:
        for info in zf.infolist():
            rel = _safe_relative(info.filename)
            if rel is None:
                continue
            _write(dest / "wheel", rel, zf.read(info))
            found["wheel"].append(rel)
    with tarfile.open(sdists[0], "r:gz") as tf:
        for member in tf.getmembers():
            if member.isdir():
                continue
            if not member.isfile():
                raise ArtifactCheckError(f"unsafe archive member: {member.name}")
            rel = _safe_relative(member.name, strip_first=True)
            if rel is None:
                continue
            fileobj = tf.extractfile(member)
            if fileobj is None:
                continue
            _write(dest / "sdist", rel, fileobj.read())
            found["sdist"].append(rel)
    return {kind: sorted(files) for kind, files in found.items()}


def stray_files(dist_dir: Path) -> list[str]:
    """Findings for non-hidden entries other than the one wheel and one sdist."""
    return sorted(
        f"unexpected file in {dist_dir.name}: {entry.name}"
        for entry in dist_dir.iterdir()
        if not entry.name.startswith(".")
        and not (entry.is_file() and entry.name.endswith((".whl", ".tar.gz")))
    )


def read_manifest(path: Path) -> dict[str, set[str]]:
    """Parse `wheel: <path>` / `sdist: <path>` lines; `#` starts a comment."""
    expected: dict[str, set[str]] = {kind: set() for kind in KINDS}
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind, sep, rel = line.partition(":")
        kind, rel = kind.strip(), rel.strip()
        if not sep or kind not in KINDS or not rel:
            raise ArtifactCheckError(f"{path}:{number}: bad manifest line: {raw!r}")
        expected[kind].add(rel)
    return expected


def compare_manifest(
    found: dict[str, list[str]], expected: dict[str, set[str]]
) -> list[str]:
    """Return sorted messages for files that are unexpected or missing."""
    problems = []
    for kind in KINDS:
        names = found.get(kind, [])
        have = set(names)
        problems += [
            f"duplicate {kind} file: {name}"
            for name, count in Counter(names).items()
            if count > 1
        ]
        want = expected.get(kind, set())
        problems += [f"unexpected {kind} file: {name}" for name in have - want]
        problems += [f"missing {kind} file: {name}" for name in want - have]
    return sorted(problems)


def scan_secrets(root: Path, gitleaks: str = "gitleaks") -> list[str]:
    """Run gitleaks over root (no git); return one line per finding."""
    command = [
        gitleaks,
        "detect",
        "--no-git",
        "--source",
        str(root),
        "--redact",
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ArtifactCheckError(f"{gitleaks} not found; install gitleaks") from exc
    if result.returncode == 0:
        return []
    if result.returncode != 1:
        raise ArtifactCheckError(
            f"gitleaks failed ({result.returncode}): {result.stderr.strip()}"
        )
    unparseable = [
        "gitleaks reported findings (exit 1) but the report could not be parsed"
    ]
    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError:
        return unparseable
    if not isinstance(findings, list) or not findings:
        return unparseable
    return [
        f"secret finding {item.get('RuleID', '?')} in {item.get('File', '?')}:"
        f"{item.get('StartLine', '?')}"
        if isinstance(item, dict)
        else "secret finding (unparseable entry)"
        for item in findings
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--skip-gitleaks", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not args.dist_dir.is_dir():
            raise ArtifactCheckError(f"dist directory not found: {args.dist_dir}")
        expected = read_manifest(args.manifest)
        with tempfile.TemporaryDirectory(prefix="toolgate-artifacts-") as tmp:
            root = Path(tmp)
            found = unpack_dist(args.dist_dir, root)
            problems = compare_manifest(found, expected) + stray_files(args.dist_dir)
            if not args.skip_gitleaks:
                problems += scan_secrets(root)
    except (ArtifactCheckError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("Artifact check failed:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("Artifact check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
