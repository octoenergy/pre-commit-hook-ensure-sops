# pre-commit-hook-ensure-sops

[pre-commit](https://pre-commit.com/) hooks for repositories that use
[sops](https://github.com/getsops/sops) to store encrypted secrets. Between
them the two hooks catch the two ways a sops file gets broken by hand: checking
in a file that was never encrypted, and editing an encrypted file without sops.

## `sops-encryption` — is the file encrypted?

Ensures that users don't accidentally check-in unencrypted files.

By default, any file with the word `secret` in its path is required to
be encrypted with `sops`. This means any files under a directory
named `secret` are also required to be encrypted. If you want to exempt
specific files or directories from this requirement in your repository,
use the `exclude` option in your `.pre-commit-config.yaml`. When pushing
secrets to a repo, better safe than sorry :)

## `sops-mac-updated` — was the file edited with sops?

Ensures that changes to an already-encrypted file were made by sops.

`sops-encryption` only looks at whether values are encrypted, so it cannot see
a file that was edited in a text editor: deleting a line, renaming a key or
pasting a value copied from another file leaves every value looking like
`ENC[...]` while invalidating the MAC that sops keeps over the plaintext. Such
a file only fails when something tries to decrypt it — in a GitOps repository
that is a CD sync error (`MAC mismatch`) discovered long after the pull request
merged, which blocks every subsequent rollout.

sops rewrites `sops.mac` on every write, so the hook compares the staged file
against the version in `HEAD`: if the encrypted values changed but the MAC did
not, sops did not write the file. No decryption keys are needed, so the check
works for everyone and in CI.

The hook deliberately says nothing about files that are newly added, not
parseable or missing sops metadata — that is `sops-encryption`'s job. Changes
that only rewrite the `sops` metadata block (`sops updatekeys`) or the file's
formatting are not reported, because neither affects decryption.

## Installation

Add this to your `.pre-commit-config.yaml`:

```yaml
  - repo: https://github.com/octoenergy/pre-commit-hook-ensure-sops
    rev: v1.0
    hooks:
      - id: sops-encryption
        # Uncomment to exclude all markdown files from encryption
        # exclude: *.\.md
      - id: sops-mac-updated
```

Both hooks default to matching any path containing `secret`. Repositories that
name their encrypted files differently should set `files` explicitly, and make
sure the pattern covers *every* encrypted file — a file the pattern misses is a
file neither hook protects:

```yaml
      - id: sops-encryption
        files: \.(encrypted\.yaml|yaml\.encrypted)$
      - id: sops-mac-updated
        files: \.(encrypted\.yaml|yaml\.encrypted)$
```
