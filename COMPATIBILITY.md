# Compatibility

## LP 0.1 and the LP 0.2 candidate

LP 0.2 candidate-4 is the LP 0.1 core **unchanged** plus negotiated optional modules (candidate SPEC §1).

- **Core objects.** Thing, State, Grant, Redemption, Binding, Line and Result keep `"lp_version": "0.1"`. The
  candidate adds no member to them and changes no rule of them.
- **An LP 0.1 party stays fully valid.** A party with no federation document is treated as `lp` = `"0.1"` with no
  modules: every LP 0.1 operation works with it, and nothing of LP 0.2 is sent to it (§3.2).
- **Modules are used only after negotiation.** Both parties publish signed federation documents. The negotiation
  picks the highest common `lp` version and, per module, the highest common version. A module either side lacks is
  absent (§3.2).

## No silent downgrade

| situation | outcome | code |
|---|---|---|
| no common `lp` version | refused | `VERSION_UNSUPPORTED` (409) |
| a module the caller requires is absent | refused, naming the first missing module | `MODULE_UNSUPPORTED` (409) |
| a document's module at a version the reader does not know | refused | `MODULE_VERSION_UNSUPPORTED` (400) |
| a federation document older than one already accepted from the same origin and key | refused (ratchet) | `FED_DOWNGRADE` (409) |
| a provider operation that needs a client-side module the client did not declare | refused | `MODULE_NOT_NEGOTIATED` (409) |
| an absent module | **never imitated** by an LP 0.1 behaviour (for example a WAITING State whose next action reads like a question) | — |

A peer MAY sign a newer document that lists fewer modules: that is its own signed decision, not a third party's
downgrade.

## The compatibility matrix

The candidate was exercised as a matrix of client and runtime versions (LP 0.1 and LP 0.2 clients against LP 0.1 and
LP 0.2 runtimes, per operation): 128 cells, each observed as SUPPORTED, NEGOTIATED or REFUSED and compared with the
class the rules require — 0 failed (`evidence/README.md`). The candidate's own rules, including candidate-3 ↔ candidate-4,
are in [`lp-0.2-candidate-4/COMPATIBILITY.md`](lp-0.2-candidate-4/COMPATIBILITY.md).

## Live Lines

LP 0.1 §8.3 names a Live Line's data channels by their labels, `lyne-control` and `lyne-data`, and does not fix how they
are created. Between parties that negotiate `lp02.liveline` /1, the candidate fixes it (SPEC §20): negotiated channels,
`lyne-control` id 0 and `lyne-data` id 1 (only with DATA in the Grant), ordered, fully reliable, protocol `""`. Without
that negotiation a Line follows LP 0.1 §8.3 alone, and the profile is never imitated. The labels are labels — not
subprotocols, IANA names, identities or authority; no registration is needed.

## Future versions

Compatibility between versions is always explicit, through negotiation, never assumed (`VERSIONING.md`).
