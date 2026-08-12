"""
Ensure sops-encrypted files are only ever modified through sops.

sops recomputes `sops.mac` (a MAC over the plaintext values) every time it
writes a file. A hand edit — deleting a line, renaming a key, pasting a value
copied from another file — changes the encrypted payload but leaves the MAC
untouched. Such a file still *looks* encrypted, so an encryption check cannot
see the problem; it only surfaces later at decrypt time as a `MAC mismatch`,
typically when a CD tool tries to sync it, long after the pull request merged.

Comparing the staged file against the version in HEAD catches this locally: if
the encrypted payload changed while the MAC did not, sops did not write it.
No decryption keys are needed.
"""

from argparse import ArgumentParser
from subprocess import run
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

yaml = YAML(typ="safe")

REMEDY = (
    "Discard the change and re-apply it with sops (`sops <file>`, `sops set`, "
    "`sops unset`) — sops files must never be edited with a text editor."
)


def parse(contents: str) -> dict[str, Any] | None:
    """
    Parse a sops document, or return None if it is not a YAML/JSON mapping.

    Whether a file is encrypted at all is the `sops-encryption` hook's job, so
    anything unparseable is simply not comparable here.
    """
    try:
        doc = yaml.load(contents)
    except YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def get_mac(doc: dict[str, Any]) -> str | None:
    """Return the MAC from a document's sops metadata block, if it has one."""
    metadata = doc.get("sops")
    if not isinstance(metadata, dict):
        return None
    mac = metadata.get("mac")
    return mac if isinstance(mac, str) else None


def encrypted_payload(doc: dict[str, Any]) -> dict[str, Any]:
    """Return the document without the `sops` metadata block, which sops itself
    leaves unencrypted and rewrites on every edit."""
    return {key: value for key, value in doc.items() if key != "sops"}


def get_committed_version(filename: str) -> dict[str, Any] | None:
    """
    Load filename as committed in HEAD.

    Returns None when there is nothing to compare against: the file is newly
    added, the repository has no commits yet, or the committed version is not
    parseable.
    """
    committed = run(
        ["git", "show", f"HEAD:./{filename}"], capture_output=True, text=True
    )
    if committed.returncode != 0:
        return None
    return parse(committed.stdout)


def check_file(filename):
    """
    Check that any change to a sops encrypted file was made by sops.

    Returns a boolean indicating whether the given file is valid or not, as well
    as a string with a human readable success / failure message.
    """
    with open(filename) as f:
        staged = parse(f.read())

    committed = get_committed_version(filename)
    if staged is None or committed is None:
        return True, f"{filename}: no comparable committed version, skipped"

    mac, committed_mac = get_mac(staged), get_mac(committed)
    if mac is None or committed_mac is None:
        return True, f"{filename}: no sops MAC to compare, skipped"

    if encrypted_payload(staged) == encrypted_payload(committed):
        # Only the sops metadata changed (a re-encrypt, `sops updatekeys`), or
        # nothing but formatting did. Neither affects decryption.
        return True, f"{filename}: encrypted values unchanged"

    if mac == committed_mac:
        return (
            False,
            f"{filename}: encrypted values changed but the sops MAC did not, so "
            f"this file was not written by sops and will fail to decrypt with a "
            f"MAC mismatch. {REMEDY}",
        )

    return True, f"{filename}: re-encrypted by sops"


def main():
    argparser = ArgumentParser()
    argparser.add_argument("filenames", nargs="+")

    args = argparser.parse_args()

    failed_messages = []

    for f in args.filenames:
        is_valid, message = check_file(f)

        if not is_valid:
            failed_messages.append(message)

    if failed_messages:
        print("\n".join(failed_messages))
        return 1

    return 0
