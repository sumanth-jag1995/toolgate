import io
import urllib.error

from scripts import check_pypi_name
from scripts.check_pypi_name import main, pypi_status


class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(status: int):
    def opener(url, timeout=10):
        assert url.startswith("https://pypi.org/pypi/")
        assert url.endswith("/json")
        if status == 200:
            return _Resp(200)
        raise urllib.error.HTTPError(url, status, "x", {}, io.BytesIO(b""))

    return opener


def test_404_is_free():
    assert pypi_status("a-name", _opener(404)) == "free"


def test_200_is_taken():
    assert pypi_status("a-name", _opener(200)) == "taken"


def test_url_error_is_error():
    def opener(url, timeout=10):
        raise urllib.error.URLError("offline")

    assert pypi_status("a-name", opener) == "error"


def test_server_error_is_error():
    assert pypi_status("a-name", _opener(500)) == "error"


def test_cli_exit_codes(monkeypatch, capsys):
    results = {"a": "taken", "b": "free"}
    monkeypatch.setattr(check_pypi_name, "pypi_status", lambda n, *a: results[n])
    assert main(["a", "b"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["a: taken", "b: free"]
    assert main(["a"]) == 1


def test_cli_error_is_not_free(monkeypatch):
    monkeypatch.setattr(check_pypi_name, "pypi_status", lambda n, *a: "error")
    assert main(["a"]) == 1
