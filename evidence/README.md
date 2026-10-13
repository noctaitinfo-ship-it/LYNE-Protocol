# Independent implementation evidence

What exists, measured. The machine-readable record is [`implementations.json`](implementations.json). Nothing more
is claimed.

## Implementations of LP 0.2 candidate-4

| | language | origin | written from | profile | conformance (candidate-4 profile, all four vector sets) |
|---|---|---|---|---|---|
| **A** | JavaScript (Node.js) | the LYNE product runtime | developed together with the candidate | all modules | 1170 / 1170 steps, 632 vectors |
| **B** | Python (standard library + `cryptography`) | an independently written peer | the specification text | all modules | 1170 / 1170 steps, 632 vectors |
| **C** | C# (.NET base library only) | a third implementation | the specification text alone | 7 modules + the common rules, the RFC 9421 profile and the Result-proof format (verifier, federating provider, delegation, multi-actor profiles), + `lp02.channel` /2 + `lp02.liveline` /1 | 768 / 768 steps, 457 vectors |

**Independence.** Automated checks show:

- B imports nothing of A or C.
- C uses only the .NET base library, references neither A nor B, and uses no package, file or network access.
- C builds from this package and its own source files only (an isolated build directory with nothing else).

## Cross-implementation verification

| check | result |
|---|---|
| pairwise differential on the full result (A / B, A / C, B / C) | 0 / 0 / 0 disagreements |
| differential fuzzing A / B (candidate-1's modules) | 6888 mutated vectors, 0 disagreements |
| differential fuzzing A / B / C (candidate-1's modules) | 4836 mutated vectors, 0 disagreements |
| `lp02.channel` /2: mutation fuzzing A / B / C; cross-signing | 1368 mutants, 0 disagreements; objects signed by each verify in both others |
| `lp02.liveline` /1: mutation fuzzing A / B / C | 616 mutants, 0 disagreements |
| `lp02.liveline` /1: real-browser interoperability | 49 / 49 — two independently written browser peers (the product's and one written from the SPEC) in Chrome: both directions, with and without DATA; 14 incompatible configurations each refused explicitly with the SPEC's code, with both peers as verifier; a duplicate stream id; a fresh Line; a reload |
| compatibility matrix (LP 0.1 / LP 0.2 clients × runtimes, per operation) | 128 cells: 16 SUPPORTED, 28 NEGOTIATED, 84 REFUSED as required; 0 failed |

## What this is not

- **Not adoption.** No party outside the author's project is known to implement LYNE.
- **Not a standard.** LP 0.2 candidate-4 is an experimental candidate.
- **Not third-party review.** All implementations were produced within the author's project. B, C and the second
  browser peer were written from the specification text in separate code bases, under the independence checks above.
- **Not included here.** This repository contains none of these implementations. They are evidence; the vectors and
  the runner (`CONFORMANCE.md`) are what an outside implementer uses.
