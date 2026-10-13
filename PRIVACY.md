# Privacy model

As in `SECURITY.md`:

- "LP 0.1" marks the immutable baseline.
- "LP 0.2 c4" marks the experimental candidate.
- Implementation choices are listed separately.

## Protocol properties

| property | rule | source |
|---|---|---|
| **No universal LYNE address** | The protocol defines no identifier for a person and no address at which a person can be reached. | LP 0.1 §6.6, §12 |
| **No global person directory** | Discovery finds a provider's Open Points: purposes, not people. There is nothing to search for a person. | LP 0.2 c4 §4 |
| **No inbox by default** | LP 0.1 defines no inbox, message object or conversation history. Asynchronous questions in LP 0.2 c4 are structured requests on a Thing (a question with answers), not messages. | LP 0.1 §12 item 1; LP 0.2 c4 §5 |
| **Per-Thing client identity** | The Client's key is a Thing-key: one per Thing, created at Redemption, not reused across Things. A provider can relate Things only through its own knowledge. | LP 0.1 §6.1, §6.6, §11 item 5 |
| **Content is not the record** | A Line's media and data are transient and MUST NOT be persisted; the LIVE phase is not recorded in State. | LP 0.1 §8.5 |
| **What persists** | Thing, State chain, Result and content-free audit records. | LP 0.1 §2.5, §11 item 4 |
| **Minimal titles** | A Thing title SHOULD carry no more personal data than the parties need to recognize it. | LP 0.1 §3.2 rule 6 |
| **Leaving** | A customer can leave a Thing (`lp02.exit`). Its wake subscriptions are removed, every Grant that could still open a Line is revoked, and nothing new may wait on the customer (`CLIENT_LEFT`) until a new Redemption. | LP 0.2 c4 §9 |
| **Trust without global identity** | Trust in a provider comes from pinned keys, referrals by providers already trusted, and introductions by context — not from a global identity registry. | LP 0.2 c4 §8, §18 |

## Implementation choices

The protocol does not decide these; an implementation does, and must state them:

- retention periods;
- where audit records live;
- what a provider knows about its customers outside LYNE;
- analytics (an implementation MAY have none);
- hosting location.

## Residual

A participant can always record a Line by external means (LP 0.1 §8.5 item 4, T19). Network metadata is visible to
runtime operators (LP 0.1 §11 item 6).
