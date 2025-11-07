from pre_commit_hook_ensure_sops.hook import validate_enc


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
