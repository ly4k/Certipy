import base64
from pathlib import Path

import pytest

from certipy.lib.files import try_to_save_file


def test_saves_bytes(tmp_cwd: Path):
    assert try_to_save_file(b"\x00\x01", "out.bin") == "out.bin"
    assert (tmp_cwd / "out.bin").read_bytes() == b"\x00\x01"


def test_saves_text(tmp_cwd: Path):
    try_to_save_file("hello", "out.txt")
    assert (tmp_cwd / "out.txt").read_text() == "hello"


def test_sanitizes_colon_in_filename_only(tmp_cwd: Path):
    (tmp_cwd / "dir").mkdir()
    assert try_to_save_file(b"x", "dir/a:b.pfx") == "dir/a_b.pfx"


def test_existing_file_overwritten_on_yes(
    tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_cwd / "out.txt").write_text("old")
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert try_to_save_file("new", "out.txt") == "out.txt"
    assert (tmp_cwd / "out.txt").read_text() == "new"


def test_existing_file_gets_unique_name_on_no(
    tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_cwd / "out.txt").write_text("old")
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    path = try_to_save_file("new", "out.txt")
    assert path != "out.txt"
    assert path.startswith("out_") and path.endswith(".txt")
    assert (tmp_cwd / "out.txt").read_text() == "old"
    assert (tmp_cwd / path).read_text() == "new"


def test_write_failure_falls_back_to_stdout_as_base64(
    tmp_cwd: Path, capsys: pytest.CaptureFixture[str]
):
    assert try_to_save_file(b"\xff", "missing_dir/out.bin") == "stdout"
    assert base64.b64encode(b"\xff").decode() in capsys.readouterr().out


def test_write_failure_raises_when_abort_on_fail(tmp_cwd: Path):
    with pytest.raises(OSError):
        try_to_save_file(b"x", "missing_dir/out.bin", abort_on_fail=True)
