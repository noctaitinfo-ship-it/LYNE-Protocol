# Examples — LP 0.2 candidate-4

> PRIVATE · EXPERIMENTAL · NOT LP 0.1. Each file is ONE valid object taken from a conformance vector
> (`from_vector`), with the clock and context it verifies under. Keys are the published TEST keys of the vectors.

| file | object | vector |
|---|---|---|
| `examples/federation-document.json` | a provider's signed federation document (SPEC §3.1) | `F-ok` |
| `examples/client-modules.json` | a client endpoint's module declaration (SPEC §3.3) | `CM-ok` |
| `examples/descriptor.json` | a discovery descriptor of Open Points (SPEC §4.1) | `D-ok` |
| `examples/open-request.json` | an OPEN request, signed by a one-time key (SPEC §4.1) | `O-ok` |
| `examples/referral.json` | a federated referral inside an OPEN (SPEC §8) | `R-ok` |
| `examples/thing-key-request.json` | a request signed with a Thing-key, RFC 9421 + content-digest (SPEC §2.3) | `H-digest-ok` |
| `examples/nonce-request.json` | a request with an lp02.nonce (SPEC §16) | `NC-valid-post` |
| `examples/delegation-chain.json` | a delegation chain root → A → B → C (SPEC §13) | `AD-chain` |
| `examples/async-result.json` | an async Result with the client's signed answer (SPEC §12) | `AR-valid` |
| `examples/agreement-result.json` | a multi-actor Result (SPEC §17) | `AG-valid-all` |
| `examples/result-proof.json` | a portable Result proof, request-answer basis (SPEC §15) | `PF-valid-request-answer` |
| `examples/result-proof-agreement.json` | a portable Result proof, agreement basis (SPEC §15, §17) | `PF-agreement` |
| `examples/introduction.json` | an introduction by context (SPEC §18.2) | `IN-valid` |
| `examples/endpoint-offer.json` | an endpoint offer by adapter bindings (SPEC §19.1); its expected result shows the minted references | `C2-one-thing-three-channels` |
| `examples/delivery-request.json` | a delivery request (SPEC §19.2) | `C2-one-thing-three-channels` |
| `examples/delivery-attempt.json` | an attempt over a minted reference (SPEC §19.3) | `C2-one-thing-three-channels` |
| `examples/delivery-receipt.json` | a recipient's receipt (SPEC §19.4) | `C2-one-thing-three-channels` |
| `examples/federation-negotiated.json` | a candidate-4 federation document listing lp02.channel version 2 and lp02.liveline version 1 (SPEC §3, §19, §20) | `C4N-c4-c4` |
| `examples/liveline-profile-frame.json` | the lp02.liveline/1 profile frame request: its expected result is the frame a compliant endpoint sends first on lyne-control (SPEC §20.4) | `LL-make-control-and-data` |
| `examples/liveline-channels.json` | the channel descriptors of a compliant endpoint with DATA (SPEC §20.3, §20.4) | `LL-local-ok-data` |
