# Release signing

## Decision

Official LYNE releases are signed with a **dedicated SSH signing key** of the Protocol Steward. The key is used only to
sign official tags and releases of this repository. It is never used for logging in or deploying, and an existing
operational or personal key is never reused for it.

Each release tag (`lp-0.1`, `lp-0.2-candidate-4`, …) is an **annotated, signed tag**. GitHub shows it as
**Verified**. The release assets `manifest.json` and `SHA256SUMS` are those of the tagged tree.

## The release key

| | |
|---|---|
| **Holder** | the Protocol Steward (`GOVERNANCE.md`) |
| **Type** | SSH, Ed25519, passphrase-protected |
| **Fingerprint** | `SHA256:fxb/c5VYFg5Gozn0txYSK7+Ddp9tVB+AP6+3I8awh5Y` |
| **Active since** | 2026-10-07 |
| **Public key** | [`allowed_signers`](allowed_signers), principal `lyne-protocol-steward`, namespace `git` |
| **Private key** | only on the Steward's own device (and its offline backup). Never in this repository, a log, a prompt, an artifact or a release |

## How a reader verifies an official release

1. **Check the tag.** On GitHub, it must show **Verified**.
2. **Or check it locally, deterministically,** against the canonical files of this directory:

   ```
   git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=release/allowed_signers \
       -c gpg.ssh.revocationFile=release/revoked_signers tag -v lp-0.1
   ```

   The output must say `Good "git" signature for lyne-protocol-steward`.
3. **Check the tree.** In the tagged tree, `python tests/verify_package.py` must print `LYNE-PROTOCOL PACKAGE: PASS`.

A tag that does not verify against `allowed_signers` is not an official LYNE release (`GOVERNANCE.md`).

## Key lifecycle

The whole system is two plain text files in this directory, `allowed_signers` and `revoked_signers`, interpreted by
OpenSSH (`ssh-keygen -Y verify`, through git). There is no certificate authority and no other PKI.

| event | what is done | effect |
|---|---|---|
| **Active key** | one line in `allowed_signers`: principal `lyne-protocol-steward`, `namespaces="git"`, `valid-after` = the day it became active | tags signed with it from that day verify |
| **Rotation** (planned) | the Steward creates a successor key. Its line is added with `valid-after` = the rotation day; the old line gets `valid-before` = the same day. Both changes are recorded decisions | old releases keep verifying under the old key (git checks the key against the tag's own time); new releases need the successor |
| **Revocation** (key compromised) | the old key's PUBLIC key is added to `revoked_signers`, and a successor key is created as in a rotation | every signature by the revoked key fails, old ones included. Releases that must stay valid are re-issued under **new** version tags signed by the successor; published tags are never moved (`GOVERNANCE.md`, Immutability) |
| **Lost key** (not compromised) | treated as a rotation: `valid-before` = the loss date, successor key, recorded decision | releases signed before the loss still verify |
| **Successor key** | announced by a release of this file **signed with the previous key** while it is still valid. After a compromise: by a recorded decision of the Steward, published through the repository's verified owner account and signed with the successor | a reader can follow the chain of keys |
| **Old releases later** | verify with the `allowed_signers` of the **current** release: it still lists every earlier key with its validity period (never deleted, only bounded or revoked) | one file verifies the whole history |

## Status

- **2026-10-07.** The Protocol Steward created the dedicated release key and registered it on GitHub as a signing key.
- **2026-10-08.**
  - Its public key is in `allowed_signers`.
  - The signing and verification mechanism is proven locally with an ephemeral test key in a throwaway repository: a valid tag, a wrong key, an unsigned tag, a revoked key, rotation and a tampered tag.
  - A signature with the release key itself needs the Steward's passphrase; that is the Steward's own step.
- **Releases.** A release signed with this key is a signed tag of this repository; `git tag -v` (above) is the check.
