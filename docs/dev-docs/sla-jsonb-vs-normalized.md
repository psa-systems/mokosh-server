# SLA business-hours / holiday storage: JSONB vs normalized

PMS-585 (raised in PMS-567 SLA smoke). Decision record for whether
`business_hours.schedule` and `holiday_calendars.holidays` should be normalized
into child tables or stay JSONB.

## Decision

**Keep both as JSONB.** Do not normalize into `business_hour_days` /
`holiday_dates` child tables at this time.

## Context

- `business_hours.schedule` `JSONB` (`migrations/005_tickets.sql:303`): the weekly open/close schedule.
- `holiday_calendars.holidays` `JSONB` (`:318`): an array of `{date, name}` (bare `"YYYY-MM-DD"` also tolerated).
- By contrast `sla_policies` (`:325`) and `sla_targets` (`:339`) are already normalized relational tables (`first_response_hours DECIMAL`, `operational_hours CHECK IN ('business_hours','24x7')`, etc.). The layer that needs relational querying and constraints is already relational; only the nested weekly schedule and the holiday list are JSON.

## How the data is actually used (grounding)

Verified across the SLA module (`src/modules/sla/`):

- **No SQL ever reaches into the JSON.** There is no `->`, `->>`, `@>`, `?`, `jsonb_array_elements`, or json-path `WHERE` against `schedule` or `holidays` anywhere in the codebase. Every read SELECTs the whole column (`service.rs:368`, `:515`, `:744`, `:762`).
- **Parse-whole, compute-in-Rust.** The due-time engine (`clock.rs::due_at`) loads a profile's entire `schedule` blob and the entire `holidays` blob of each referenced calendar, parses them into `BusinessSchedule` (`clock.rs:93`) and a `HashSet<NaiveDate>` (`parse_holidays`, `clock.rs:222`), then walks the week day-by-day in Rust and writes back plain `first_response_due` / `resolution_due` timestamp columns. The SLA worker only compares `now` to those timestamps; it never touches the JSON.
- **Whole-blob writes.** Upserts bind the `serde_json::Value` straight into the column (`service.rs:405/466` schedule, `:544/588` holidays). No partial JSON update (`jsonb_set`, `||`).
- **Bounded + read-mostly.** `schedule` is ~7 weekday entries; `holidays` is a short per-tenant list. No pagination or per-row access into individual days/holidays; pagination is only at the calendar/profile row level.
- **No cross-row JSON needs.** Nothing queries across calendars/days ("which calendars include date X", holiday reporting, etc.). The only cross-row touch is `id = ANY($2)` over `holiday_calendars` by primary key, never by JSON contents.

## Trade-offs

| | JSONB (keep) | Normalized child tables |
| --- | --- | --- |
| Fits the access pattern (load whole, compute in Rust) | Yes - one column, one parse | Worse - join + re-aggregate rows back into the in-memory schedule on every load |
| SQL queryability into days/holidays | No | Yes - but the app needs none today |
| Structural constraints in the DB | No (see gap below) | Yes (per-day CHECKs, FKs, unique dates) |
| Write cost | One bind | Multi-row delete+insert per edit, in a tx |
| Migration / backfill cost | None | New tables + backfill + rewrite reads/writes + rework `src/pages/sla.rs` editors |
| Complexity | Low | Higher for no feature gain |

Normalization buys SQL-level queryability and constraints the application does not use, in exchange for a migration, a backfill, and rewrites of the read path (join/aggregate), the write path (multi-row), and the SPA editors. Net: cost outweighs benefit for a small, bounded, read-mostly structure that is always consumed whole.

## Structure is enforced in Rust, not by the DB (PMS-604)

Keeping JSONB gives up DB-level structure constraints, so the write path enforces them instead. `validate_business_schedule` and `validate_holiday_list` (`src/modules/sla/models.rs:134` and `:244`) hang off the upsert requests as `#[validate(custom(...))]`, so a malformed `schedule` or `holidays` payload is rejected with a 422 keyed onto that field rather than stored and then silently skipped at read time by the tolerant `clock.rs` parser. That was the one real gap this decision left open, and PMS-604 closed it as a *validation* change, not a *storage* one: normalizing was never the cheapest way to get structure enforced.

## Revisit if

- We add holiday/business-hours reporting or queries across tenants/calendars ("which calendars include 2026-12-25").
- We need DB-enforced per-day constraints or to join schedules/holidays in SQL.
- The holiday list grows unbounded or needs per-entry mutation at scale.
