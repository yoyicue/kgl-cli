# run-all verification spec (frozen 2026-11-10)

Exit-code semantics — exact, no stronger claims:

- **rc 0 "executing (confirmed)"** — kernel-side execution observed with
  attribution: iopub `execute_input` whose `parent_header.session` is an id
  OUR PAGE's iframe spoke for (CDP sent frames) AND whose code matches this
  notebook's cells AND the post-click sequence is Run-All-shaped (starts at
  the first non-empty code cell; reaches the second as a distinct event, or
  the first is still running on an idle→busy kernel). One-cell notebooks:
  first-cell event alone. A provably-fresh session's busy (session list was
  OK-and-empty pre-click) also confirms.
- **rc 0 "submitted (execution unconfirmed)"** — our page ISSUED
  Run-All-shaped execute_requests (CDP sent frames) but no kernel-side
  evidence arrived within the window. Requests may still be queued; cells
  may have finished before the listener attached. Distinct message, same
  success code (the click DID submit the run).
- **rc 1** — no admissible evidence. Never a guess.

Admissible evidence classes (nothing else counts):

| class | source | proves |
|---|---|---|
| sent execute_request | CDP webSocketFrameSent of OUR iframe | our page submitted |
| iopub execute_input + sent client id | kernel channels + CDP | the kernel EXECUTED, attributed |
| fresh-session busy | sessions list OK+empty pre-click → busy after | execution started (fresh kernel starts idle) |
| idle→busy + attributed first-cell iopub | pre-click kernel snapshot | execution started post-click |

Rejected by design: REST session id as client id (≠ editor client id,
verified empirically); execution_count deltas (unattributable); bare busy on
a pre-existing session (may predate click); draft-blob comparisons (stale).

Known residuals (documented, accepted): a request queued in the same editor
before the click is indistinguishable from our click's requests in every
class; single-cell notebooks accept a lone first-cell event.

Operational guarantees:

- The CDP harvester subscription is confirmed (Network.enable ACK) before
  the click, or the run degrades to rc-1-only signals (never false rc 0).
- A dropped harvester is restarted by the poll loop; `sent_ids`/`sent_reqs`
  are monotonic buffers — late data can only add evidence, never remove it.
- Record-time checks never drop events that a later-arriving fact could
  have validated (verdict-time filtering).
