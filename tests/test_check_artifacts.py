import io
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.check_artifacts import (
    ArtifactCheckError,
    compare_manifest,
    main,
    read_manifest,
    scan_secrets,
    unpack_dist,
)


def _make_dist(
    dist: Path, wheel_files: dict[str, bytes], sdist_files: dict[str, bytes]
) -> None:
    dist.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dist / "pkg-0.1.0-py3-none-any.whl", "w") as zf:
        for name, data in wheel_files.items():
            zf.writestr(name, data)
    with tarfile.open(dist / "pkg-0.1.0.tar.gz", "w:gz") as tf:
        for name, data in sdist_files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def test_compare_reports_unexpected_and_missing():
    found = {
        "wheel": ["toolgate_pin/__init__.py", "tests/test_x.py"],
        "sdist": ["README.md"],
    }
    expected = {
        "wheel": {"toolgate_pin/__init__.py", "toolgate_pin/py.typed"},
        "sdist": {"README.md"},
    }
    assert compare_manifest(found, expected) == [
        "missing wheel file: toolgate_pin/py.typed",
        "unexpected wheel file: tests/test_x.py",
    ]


def test_unpack_dist_reads_wheel_and_sdist(tmp_path):
    dist = tmp_path / "dist"
    _make_dist(
        dist,
        {"toolgate_pin/__init__.py": b"x = 1\n"},
        {"pkg-0.1.0/README.md": b"hi\n", "pkg-0.1.0/PKG-INFO": b"Name: pkg\n"},
    )
    dest = tmp_path / "out"
    found = unpack_dist(dist, dest)
    assert found["wheel"] == ["toolgate_pin/__init__.py"]
    assert found["sdist"] == ["PKG-INFO", "README.md"]
    assert (dest / "wheel" / "toolgate_pin" / "__init__.py").read_text() == "x = 1\n"
    assert (dest / "sdist" / "README.md").exists()


def test_unpack_rejects_path_traversal(tmp_path):
    dist = tmp_path / "dist"
    _make_dist(dist, {"../evil.py": b"x"}, {"pkg-0.1.0/README.md": b"hi"})
    with pytest.raises(ArtifactCheckError, match="unsafe"):
        unpack_dist(dist, tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


def test_read_manifest_ignores_comments(tmp_path):
    path = tmp_path / "manifest.txt"
    path.write_text(
        "# header\n\nwheel: toolgate_pin/__init__.py\nsdist: README.md  \n# tail\n",
        encoding="utf-8",
    )
    assert read_manifest(path) == {
        "wheel": {"toolgate_pin/__init__.py"},
        "sdist": {"README.md"},
    }


def test_cli_fails_on_stray_env_file(tmp_path, capsys):
    dist = tmp_path / "dist"
    _make_dist(
        dist,
        {"toolgate_pin/__init__.py": b"", ".env": b"X=1\n"},
        {"pkg-0.1.0/README.md": b"hi"},
    )
    manifest = tmp_path / "manifest.txt"
    manifest.write_text(
        "wheel: toolgate_pin/__init__.py\nsdist: README.md\n", encoding="utf-8"
    )
    assert main([str(dist), "--manifest", str(manifest), "--skip-gitleaks"]) == 1
    assert ".env" in capsys.readouterr().out


def test_cli_clean_passes(tmp_path):
    dist = tmp_path / "dist"
    _make_dist(dist, {"toolgate_pin/__init__.py": b""}, {"pkg-0.1.0/README.md": b"hi"})
    manifest = tmp_path / "manifest.txt"
    manifest.write_text(
        "wheel: toolgate_pin/__init__.py\nsdist: README.md\n", encoding="utf-8"
    )
    assert main([str(dist), "--manifest", str(manifest), "--skip-gitleaks"]) == 0


def test_cli_missing_dist_is_usage_error(tmp_path):
    manifest = tmp_path / "manifest.txt"
    manifest.write_text("", encoding="utf-8")
    assert (
        main([str(tmp_path / "nope"), "--manifest", str(manifest), "--skip-gitleaks"])
        == 2
    )


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_scan_secrets_flags_canary(tmp_path):
    # Assembled at runtime so the source never holds a literal key-shaped string.
    canary = "AKIA" + "QYLPMN5HHHFPZAM2"
    (tmp_path / "leak.txt").write_text(
        f"aws_access_key_id = {canary}\n", encoding="utf-8"
    )
    findings = scan_secrets(tmp_path)
    assert findings
    assert canary not in "\n".join(findings)


def test_scan_secrets_missing_binary_is_tooling_error(tmp_path):
    with pytest.raises(ArtifactCheckError, match="not found"):
        scan_secrets(tmp_path, gitleaks="gitleaks-definitely-not-installed")


def test_compare_reports_duplicates():
    found = {"wheel": ["a.py", "a.py"], "sdist": []}
    expected = {"wheel": {"a.py"}, "sdist": set()}
    assert compare_manifest(found, expected) == ["duplicate wheel file: a.py"]


def test_unpack_reports_duplicate_members(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    with zipfile.ZipFile(dist / "pkg-0.1.0-py3-none-any.whl", "w") as zf:
        zf.writestr("a.py", b"1")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("a.py", b"2")
    with tarfile.open(dist / "pkg-0.1.0.tar.gz", "w:gz") as tf:
        info = tarfile.TarInfo("pkg-0.1.0/README.md")
        info.size = 0
        tf.addfile(info, io.BytesIO(b""))
    found = unpack_dist(dist, tmp_path / "out")
    assert found["wheel"] == ["a.py", "a.py"]


@pytest.mark.parametrize("name", ["/abs.py", "C:/abs.py", "a/../../evil.py"])
def test_wheel_unsafe_names_rejected(tmp_path, name):
    dist = tmp_path / "dist"
    _make_dist(dist, {name: b"x"}, {"pkg-0.1.0/README.md": b"hi"})
    with pytest.raises(ArtifactCheckError, match="unsafe"):
        unpack_dist(dist, tmp_path / "out")


def _tar_with(dist: Path, member: tarfile.TarInfo, data: bytes = b"") -> None:
    dist.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dist / "pkg-0.1.0-py3-none-any.whl", "w") as zf:
        zf.writestr("a.py", b"")
    with tarfile.open(dist / "pkg-0.1.0.tar.gz", "w:gz") as tf:
        tf.addfile(member, io.BytesIO(data))


def _regular(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = 1
    return info


def _symlink(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    return info


@pytest.mark.parametrize(
    "member",
    [
        _regular("/abs.py"),
        _regular("pkg-0.1.0/../../evil.py"),
        _symlink("pkg-0.1.0/link"),
    ],
    ids=["absolute", "dotdot", "symlink"],
)
def test_sdist_unsafe_members_rejected(tmp_path, member):
    _tar_with(tmp_path / "dist", member, b"x" if member.isfile() else b"")
    with pytest.raises(ArtifactCheckError, match="unsafe"):
        unpack_dist(tmp_path / "dist", tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


class _Result:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.mark.parametrize("stdout", ["", "null", "[]", "not json", "{}"])
def test_scan_secrets_exit_1_without_parseable_findings_fails(
    tmp_path, monkeypatch, stdout
):
    monkeypatch.setattr(
        "scripts.check_artifacts.subprocess.run",
        lambda *a, **k: _Result(1, stdout=stdout),
    )
    findings = scan_secrets(tmp_path)
    assert findings
    assert "could not be parsed" in findings[0]


def test_cli_missing_gitleaks_is_tooling_error(tmp_path, monkeypatch, capsys):
    dist = tmp_path / "dist"
    _make_dist(dist, {"a.py": b""}, {"pkg-0.1.0/README.md": b"hi"})
    manifest = tmp_path / "manifest.txt"
    manifest.write_text("wheel: a.py\nsdist: README.md\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert main([str(dist), "--manifest", str(manifest)]) == 2
    assert "not found" in capsys.readouterr().err
