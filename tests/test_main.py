import re

from pre_commit_hook_ensure_sops.hook import check_file, validate_enc

ENC = "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]"


def write_doc(tmp_path, sops_metadata, **values):
    lines = [f"{key}: {value}" for key, value in values.items()]
    lines.append("sops:")
    lines.append("    version: 3.13.2")
    lines.extend(f"    {key}: {value}" for key, value in sops_metadata.items())
    path = tmp_path / "secret.yaml"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_validate_enc_string():
    assert (
        validate_enc("token", "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]")
        is True
    )
    assert validate_enc("token", "abc123") is False
    assert validate_enc("token", "") is True
    assert validate_enc("token_unencrypted", "abc123") is True


def test_validate_enc_list():
    assert (
        validate_enc(
            "tokens",
            [
                "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            ],
        )
        is True
    )
    assert (
        validate_enc(
            "tokens", ["ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]", "abc123"]
        )
        is False
    )
    assert validate_enc("tokens", []) is True


def test_validate_enc_dict():
    assert (
        validate_enc(
            "secrets",
            {
                "token1": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                "token2": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            },
        )
        is True
    )
    assert (
        validate_enc(
            "secrets",
            {
                "token1": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                "token2": "abc123",
            },
        )
        is False
    )
    assert validate_enc("secrets", {}) is True


def test_validate_enc_no_key():
    assert (
        validate_enc(None, "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]") is True
    )
    assert validate_enc(None, "abc123") is False
    assert (
        validate_enc(
            None,
            [
                "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            ],
        )
        is True
    )
    assert (
        validate_enc(
            None,
            {
                "token1": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                "token2": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            },
        )
        is True
    )


def test_validate_enc_unencrypted_regex():
    unencrypted_regex = re.compile(r"^username$")
    assert (
        validate_enc(
            "username",
            "abc123",
            unencrypted_regex=unencrypted_regex,
        )
        is True
    )
    assert (
        validate_enc(
            "username",
            "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            unencrypted_regex=unencrypted_regex,
        )
        is True
    )
    assert (
        validate_enc(
            "username",
            "",
            unencrypted_regex=unencrypted_regex,
        )
        is True
    )
    assert (
        validate_enc(
            "password",
            "abc123",
            unencrypted_regex=unencrypted_regex,
        )
        is False
    )
    assert (
        validate_enc(
            "extraObjects",
            [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "secret"},
                    "stringData": {
                        "token": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
                    },
                },
            ],
            unencrypted_regex=re.compile(r"^(apiVersion|kind|metadata|type)$"),
        )
        is True
    )


def test_validate_enc_unencrypted_regex_and_suffix():
    unencrypted_regex = re.compile(r"^username$")
    assert (
        validate_enc(
            "username_unencrypted",
            "abc123",
            unencrypted_regex=unencrypted_regex,
            unencrypted_suffix=None,
        )
        is False
    )


def test_validate_enc_custom_suffix():
    assert validate_enc("item_plain", "abc123", unencrypted_suffix="_plain") is True


def test_check_file_default_suffix(tmp_path):
    # sops records the default suffix, but older versions may not.
    for metadata in ({"unencrypted_suffix": "_unencrypted"}, {}):
        path = write_doc(tmp_path, metadata, password=ENC, item_unencrypted="abc123")
        assert check_file(path)[0] is True


def test_check_file_unencrypted_regex(tmp_path):
    path = write_doc(
        tmp_path, {"unencrypted_regex": "^(username)$"}, password=ENC, username="bob"
    )
    assert check_file(path)[0] is True


def test_check_file_unencrypted_regex_ignores_suffix(tmp_path):
    # sops encrypts `_unencrypted` keys when a regex is in effect
    path = write_doc(
        tmp_path,
        {"unencrypted_regex": "^(username)$"},
        password=ENC,
        item_unencrypted="abc123",
    )
    is_valid, message = check_file(path)
    assert is_valid is False
    assert "item_unencrypted" in message


def test_check_file_custom_unencrypted_suffix(tmp_path):
    path = write_doc(
        tmp_path,
        {"unencrypted_suffix": "_plain"},
        password=ENC,
        op_item_plain="abc123",
        item_unencrypted=ENC,
    )
    assert check_file(path)[0] is True


def test_check_file_multiple_modes(tmp_path):
    path = write_doc(
        tmp_path,
        {"unencrypted_suffix": "_unencrypted", "unencrypted_regex": "^(username)$"},
        password=ENC,
    )
    is_valid, _ = check_file(path)
    assert is_valid is False


def test_check_file_unsupported_mode(tmp_path):
    for mode in (
        "encrypted_suffix",
        "encrypted_regex",
        "unencrypted_comment_regex",
        "encrypted_comment_regex",
    ):
        path = write_doc(tmp_path, {mode: "_enc"}, password=ENC, username="bob")
        is_valid, _ = check_file(path)
        assert is_valid is False
