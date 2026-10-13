# Security model

This page separates what the **protocol** guarantees from what an **implementation** chooses. Each guarantee cites
its source. "LP 0.1" rules are part of the immutable baseline. "LP 0.2 c4" rules come from the experimental
candidate `lp02-private-candidate-4` and bind only implementations that negotiate that module.

## Protocol guarantees

| property | rule | source |
|---|---|---|
| **No universal address** | A party is reached through a Thing it holds a Grant for, never through a personal address. LP 0.1 defines no inbox, message object, conversation history or contact form. | LP 0.1 §12 item 1 |
| **Capability-based authority** | Every Live Line runs under a Provider-signed Grant with a purpose, channels, a time window and a number of uses, enforced by the Provider. | LP 0.1 §5, §11 item 1 |
| **Bounded bearer phase** | A link is authority only during a bearer phase of at most 15 minutes and only until the first Redemption. Afterwards authority is bound to one Thing-key and the link secret is deleted. The secret travels in the URL fragment and is removed from the address bar. | LP 0.1 §5.4, §6, §11 item 2 |
| **Temporary Line authority** | A Line opens only under a valid Grant, consumes one use, and ends at `exp` or on revocation; the line keys are deleted at expiry. | LP 0.1 §8.2, §10 items 1–2 |
| **End-to-end media** | DTLS-SRTP with fingerprints authenticated by LYNE signatures; runtime components (rendezvous, TURN) cannot insert themselves or read content. | LP 0.1 §7.4, §8.1, §11 item 3 |
| **Content is not the record** | Line content MUST NOT be persisted by any party; the persistent data are Thing, State, Result and content-free audit records. | LP 0.1 §8.5, §11 item 4 |
| **Authority revocation** | The Provider may revoke a Grant (immediate for Redemption and new Lines; an active Line is closed by a signed `bye`), bump the epoch (all older Grants revoked), revoke a Binding (requests by the old Thing-key are refused with `KEY_MISMATCH`), or close the Thing (all Grants revoked). | LP 0.1 §10 items 2–5 |
| **Replay resistance** | Single compare-and-set redemption, single-use challenge, per-direction nonce sets, RFC 9421 `created` and replay cache, `version` and `prev_state_hash`, one Result per (`grant_id`, `line_seq`). | LP 0.1 §10 item 7 |
| **Admission before relationship** | A relationship starts only from an admitted OPEN: a signed request to a published Open Point, checked against the point's admission policy (one-time code or trusted referral) in a fixed order, first failure wins. There is no channel to reach a party that has not admitted the request. | LP 0.2 c4 §4 |
| **Device move** | A relationship moves to a new device only through a Recovery Grant signed by the Thing's provider key. The move bumps the epoch, revokes the old Thing-key and binds the new one; a used or revoked Recovery Grant is refused. | LP 0.2 c4 §14 |
| **Version negotiation, no silent downgrade** | Parties negotiate the highest common `lp` version and module versions from signed federation documents. An older document than one already accepted is refused (`FED_DOWNGRADE`). A required module that is absent is refused (`MODULE_UNSUPPORTED`); it is never imitated by an LP 0.1 behaviour. A party without a federation document is treated as LP 0.1 with no modules. | LP 0.2 c4 §3.2 |
| **Delegation is attenuating** | A delegated authority can only narrow its parent (scope, time, uses, depth); widening, cycles, stale epochs and revoked links are refused. | LP 0.2 c4 §13 |

## Residual risks the protocol does not remove

These are stated in LP 0.1 §11 item 6 and `lp-0.1/Threat_model.md`:

- phishing at first contact;
- a compromised provider key (LP 0.1 has no key rotation; affected relationships are frozen and a new Thing is
  needed, §10 item 8);
- recording by a participant by external means;
- network metadata visible to runtime operators.

## Implementation choices (not guaranteed by the protocol)

The following are choices an implementation makes and an auditor checks per implementation:

- how a Grant link is delivered;
- where keys are stored, within LP 0.1 §6.1 (the private Thing-key never leaves the endpoint; a browser endpoint
  MUST create it as a non-extractable Web Cryptography key);
- the retention period of closed Things;
- rate limits;
- the access control in front of a provider's console;
- whether TURN is offered.

## Reporting a vulnerability

Report a vulnerability privately through GitHub's private vulnerability reporting for this repository: the
**Security** tab → **Report a vulnerability**. Please do not open public issues for vulnerabilities.
