# Binaries and operator subcommands

The crate builds two binaries, and one of them doubles as an operator CLI.

| Binary | Purpose |
| --- | --- |
| `mokosh-server` | Long-running HTTP API (Axum). |
| `mokosh-bootstrap` | One-shot CLI that performs first-run setup of a fresh Infisical instance and writes the resulting Universal Auth credentials into `.env`. |

## Operator subcommands

`mokosh-server` inspects `argv` before binding a port (`src/cli.rs`): when the first token is one of these it runs the task and exits instead of serving.

| Subcommand | Purpose |
| --- | --- |
| `bootstrap-infisical` | First-run setup of a fresh Infisical instance. Driven by `just infisical-bootstrap`; see step 7 of [`quickstart.md`](quickstart.md). |
| `qa-seed` | Load the QA walkthrough dataset into the tenant named by `--tenant <uuid>` or `MOKOSH_QA_TENANT_ID`. |
| `qa-teardown` | Remove that dataset from the same tenant. |
| `showcase-seed` | Create the richer showcase demo dataset in the tenant named by `--tenant <uuid>` or `MOKOSH_SHOWCASE_TENANT_ID`. |
| `showcase-refresh` | Tear the showcase dataset down and re-seed it in one step. |
| `showcase-teardown` | Remove the showcase dataset. |

Both seeds are fail-closed and write nothing unless the target tenant is explicitly marked: `settings.is_qa` for `qa-*`, `settings.is_showcase` for `showcase-*`. That is what keeps them off a production tenant. Each needs a privileged `DATABASE_URL`.

`mokosh-bootstrap` dispatches its own overlapping set (`bootstrap-infisical`, `qa-seed`, `qa-teardown`, plus `normalize-company-industries`); it has no `showcase-*` subcommands. Run `mokosh-bootstrap` with no arguments for its help text.
