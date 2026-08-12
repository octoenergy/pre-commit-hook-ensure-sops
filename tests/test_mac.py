import subprocess

import pytest

from pre_commit_hook_ensure_sops.mac import check_file, main

ENC = "ENC[AES256_GCM,data:{},iv:iv,tag:tag,type:str]"

FILENAME = "values.encrypted.yaml"


def sops_file(
    values: str, mac: str = "mac-one", lastmodified: str = "2026-01-01"
) -> str:
    return f"""\
{values}
sops:
    kms: []
    lastmodified: "{lastmodified}"
    mac: {ENC.format(mac)}
    version: 3.13.3
"""


ORIGINAL = sops_file(
    f"""\
env:
    API_URL: {ENC.format("url")}
    API_TOKEN: {ENC.format("token")}"""
)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A git repo, checked out at a commit containing an encrypted file."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_AUTHOR_NAME", "test")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "test")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "test@example.com")
    subprocess.run(["git", "init", "--quiet"], check=True)
    (tmp_path / FILENAME).write_text(ORIGINAL)
    subprocess.run(["git", "add", FILENAME], check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "Add secrets"], check=True)
    return tmp_path


def test_value_removed_without_sops(repo):
    """The failure mode that breaks CD: a line deleted by hand."""
    (repo / FILENAME).write_text(
        sops_file(f"""\
env:
    API_URL: {ENC.format("url")}""")
    )

    is_valid, message = check_file(FILENAME)

    assert is_valid is False
    assert "sops MAC did not" in message
    assert "re-apply it with sops" in message


def test_key_renamed_without_sops(repo):
    """Renaming a key keeps the value encrypted but breaks decryption, because
    sops authenticates each value against its key path."""
    (repo / FILENAME).write_text(
        sops_file(f"""\
env:
    API_URL: {ENC.format("url")}
    RENAMED_API_TOKEN: {ENC.format("token")}""")
    )

    is_valid, _ = check_file(FILENAME)

    assert is_valid is False


def test_value_added_without_sops(repo):
    (repo / FILENAME).write_text(
        sops_file(f"""\
env:
    API_URL: {ENC.format("url")}
    API_TOKEN: {ENC.format("token")}
    NEW_TOKEN: {ENC.format("new")}""")
    )

    is_valid, _ = check_file(FILENAME)

    assert is_valid is False


def test_edited_with_sops(repo):
    """sops rewrites the MAC and lastmodified on every edit, and only
    re-encrypts the values that actually changed."""
    (repo / FILENAME).write_text(
        sops_file(
            f"""\
env:
    API_URL: {ENC.format("url")}
    API_TOKEN: {ENC.format("rotated-token")}""",
            mac="mac-two",
            lastmodified="2026-02-02",
        )
    )

    is_valid, _ = check_file(FILENAME)

    assert is_valid is True


def test_unchanged_file(repo):
    is_valid, _ = check_file(FILENAME)

    assert is_valid is True


def test_reformatted_file(repo):
    """A formatter rewriting quoting or indentation does not affect
    decryption, so it must not be reported."""
    (repo / FILENAME).write_text(
        sops_file(f"""\
env:
  "API_URL": "{ENC.format("url")}"
  "API_TOKEN": "{ENC.format("token")}"
""")
    )

    is_valid, _ = check_file(FILENAME)

    assert is_valid is True


def test_metadata_only_change(repo):
    """`sops updatekeys` rewrites the metadata block without touching values."""
    (repo / FILENAME).write_text(
        ORIGINAL.replace("kms: []", "kms:\n    - arn: arn:aws:kms:eu-west-1:1:key/abc")
    )

    is_valid, _ = check_file(FILENAME)

    assert is_valid is True


def test_newly_added_file(repo):
    """Nothing to compare against; `sops-encryption` covers new files."""
    (repo / "new.encrypted.yaml").write_text(ORIGINAL)

    is_valid, _ = check_file("new.encrypted.yaml")

    assert is_valid is True


def test_unencrypted_file(repo):
    """Whether a file is encrypted at all is `sops-encryption`'s job."""
    (repo / "plain.yaml").write_text("env:\n    API_TOKEN: hunter2\n")
    subprocess.run(["git", "add", "plain.yaml"], check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "Add plaintext"], check=True)
    (repo / "plain.yaml").write_text("env:\n    API_TOKEN: hunter3\n")

    is_valid, _ = check_file("plain.yaml")

    assert is_valid is True


def test_unparseable_file(repo):
    (repo / FILENAME).write_text("{{ not yaml")

    is_valid, _ = check_file(FILENAME)

    assert is_valid is True


def test_main_reports_every_failure(repo, capsys, monkeypatch):
    (repo / "other.encrypted.yaml").write_text(ORIGINAL)
    subprocess.run(["git", "add", "other.encrypted.yaml"], check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "Add more secrets"], check=True)
    hand_edited = sops_file("env: {}")
    (repo / FILENAME).write_text(hand_edited)
    (repo / "other.encrypted.yaml").write_text(hand_edited)
    monkeypatch.setattr("sys.argv", ["hook", FILENAME, "other.encrypted.yaml"])

    assert main() == 1

    output = capsys.readouterr().out
    assert FILENAME in output
    assert "other.encrypted.yaml" in output


def test_main_passes_valid_files(repo, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["hook", FILENAME])

    assert main() == 0
    assert capsys.readouterr().out == ""
