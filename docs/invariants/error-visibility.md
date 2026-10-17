# Error visibility invariants

Scope: when a handled, non-fatal condition is logged, and at what level.

Each section below is a convention moved verbatim from the repo `CLAUDE.md` (PMS-1437), which keeps a one-line index entry linking here. A new convention adds its full text here and one index line in [`CLAUDE.md`](../../CLAUDE.md).

## 2. A lookup that found nothing is not a failed attempt (PMS-1477)

`log_unresolved_person_names` (`src/utils/unresolved_person.rs`) logs an id whose name lookup came back empty at `INFO`, never `WARN` or `ERROR`: the lookup ran and answered, it just had nothing to return, which is a fact about the data, not a fault in the code that asked for it. A row whose id is `None` has nothing to resolve and is not logged at all; only a row with `Some` id and an empty name is a reportable miss, and the call is batched to one line per response rather than one per row. `WARN`/`ERROR` stay reserved for a lookup that could not run (the dependency it calls is down, the query itself errored), which is the actual tried-and-failed case this section's `INFO` is deliberately distinguished from.

## 4. A client-stated conflict is not a server fault

A `23505` unique-violation that the response already explains in full to the caller is logged at `debug`, not `error`, because the caller is told the exact cause (`"That record already exists"` / `"User is already a member of this team"`) and a second `error`-level line for the same fact would be the server reporting its own normal behavior as a fault. `src/utils/error.rs`'s `From<sqlx::Error> for AppError` applies this at the shared boundary: a `23505` maps to `AppError::Conflict` and a `tracing::debug!`, every other Postgres code falls through to the shared mapping, which logs at `error` and carries the raw cause so a panicking test's `.expect()` and the log line name the same fault. `src/modules/teams/service.rs`'s team-member insert applies the same rule ahead of that shared mapping, because the `UNIQUE(team_id, user_id)` duplicate there is identified before the generic `From` conversion runs: same rule, same reason, two call sites. Any future duplicate-handling call site facing a database constraint whose violation the response already restates in full follows the same split: the response explains the cause, so the log only needs `debug`; a code the response has not already explained is a real fault and logs at `error`.
