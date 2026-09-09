import re
from argparse import ArgumentParser
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.parser import ParserError

yaml = YAML(typ="safe")

# The default suffix used for sops unencrypted values, unless otherwise specified
# in metadata
DEFAULT_UNENCRYPTED_SUFFIX = "_unencrypted"

# sops supports a few modes for marking values as unencrypted
# For more information, see https://sops.pages.dev/#encrypting-only-parts-of-a-file
UNENCRYPTED_SUFFIX = "unencrypted_suffix"
UNENCRYPTED_REGEX = "unencrypted_regex"
SOPS_MODES = (
    UNENCRYPTED_SUFFIX,
    UNENCRYPTED_REGEX,
    "encrypted_suffix",
    "encrypted_regex",
    "unencrypted_comment_regex",
    "encrypted_comment_regex",
)


def validate_enc(
    key: str | None,
    item: Any,
    unencrypted_regex: re.Pattern | None = None,
    unencrypted_suffix: str | None = DEFAULT_UNENCRYPTED_SUFFIX,
) -> bool:
    """
    Validate given item is encrypted.

    All leaf values in a sops encrypted file must be strings that
    start with ENC[. We iterate through lists and dicts, checking
    only for leaf strings. Presence of any other data type (like
    bool, number, etc) also makes the file invalid.

    Sops also supports marking values as unencrypted, either by suffixing the
    key with `unencrypted_suffix` (default: "_unencrypted") or by matching the
    key against `unencrypted_regex`. Matching keys are ignored, along with
    anything nested under them. Only ever one of the two applies to a given
    file, so pass the one that file's metadata asks for and leave the other
    as None.
    """
    if isinstance(key, str) and unencrypted_suffix and key.endswith(unencrypted_suffix):
        return True
    elif isinstance(key, str) and unencrypted_regex and unencrypted_regex.search(key):
        return True
    elif isinstance(item, str):
        return item.startswith("ENC[") or item == ""
    elif isinstance(item, list):
        return all(
            validate_enc(
                None,
                i,
                unencrypted_regex=unencrypted_regex,
                unencrypted_suffix=unencrypted_suffix,
            )
            for i in item
        )
    elif isinstance(item, dict):
        return all(
            validate_enc(
                k,
                val,
                unencrypted_regex=unencrypted_regex,
                unencrypted_suffix=unencrypted_suffix,
            )
            for k, val in item.items()
        )
    else:
        return False


def check_file(filename):
    """
    Check if a file has been encrypted properly with sops.

    Returns a boolean indicating wether given file is valid or not, as well as
    a string with a human readable success / failure message.
    """
    loader_func = yaml.load
    # sops doesn't have a --verify (https://github.com/mozilla/sops/issues/437)
    # so we implement some heuristics, primarily to guard against unencrypted
    # files being checked in.
    with open(filename) as f:
        try:
            doc = loader_func(f)
        except ParserError:
            # All sops encrypted files are valid JSON or YAML
            return (
                False,
                f"{filename}: Not valid JSON or YAML, is not properly encrypted",
            )

    if "sops" not in doc:
        # sops puts a `sops` key in the encrypted output. If it is not
        # present, very likely the file is not encrypted.
        return (
            False,
            f"{filename}: sops metadata key not found in file, is not properly encrypted",
        )

    modes = [key for key in SOPS_MODES if key in doc["sops"]]
    if len(modes) > 1:
        # The options are mutually exclusive so this situation is impossible
        return (
            False,
            (
                f"{filename}: sops metadata includes multiple modes"
                f"({','.join(modes)}) which are supposed to be mutually exclusive"
            ),
        )

    mode = modes[0] if modes else None
    unencrypted_regex = None

    unencrypted_suffix = DEFAULT_UNENCRYPTED_SUFFIX

    if mode == UNENCRYPTED_REGEX:
        unencrypted_suffix = None
        unencrypted_regex = re.compile(doc["sops"][UNENCRYPTED_REGEX])
    elif mode == UNENCRYPTED_SUFFIX:
        unencrypted_suffix = doc["sops"][UNENCRYPTED_SUFFIX]
    elif mode is not None:
        return (False, f"{filename}: sops {mode} is not currently supported")

    invalid_keys = []
    for k in doc:
        # Values under the `sops` key are not encrypted.
        if k != "sops" and not validate_enc(
            k,
            doc[k],
            unencrypted_regex=unencrypted_regex,
            unencrypted_suffix=unencrypted_suffix,
        ):
            # Collect all invalid keys so we can provide useful error message
            invalid_keys.append(k)

    if invalid_keys:
        return (
            False,
            f"{filename}: Unencrypted values found nested under keys: {','.join(invalid_keys)}",
        )

    return True, f"{filename}: Valid encryption"


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
