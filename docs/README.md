# Mokosh Server documentation

The public documentation set. The repository [`README.md`](../README.md) is deliberately short and points here; anything longer than a paragraph lives on one of these pages.

## Getting the server running

| Page | Purpose |
| --- | --- |
| [`quickstart.md`](quickstart.md) | Get a fresh clone running on a Linux host: toolchain, generating `.env`, booting the stack, verifying it, and the footguns that bite first. |
| [`configuration.md`](configuration.md) | Every environment variable a developer touches and, for each, where the value is actually set. |
| [`recipes.md`](recipes.md) | The task runner, recipe by recipe, grouped the way `just --list` groups them. |
| [`first-run-onboarding.md`](first-run-onboarding.md) | How the very first administrator gets in, in production and in local dev, including with no SMTP configured. |

## How it is built

| Page | Purpose |
| --- | --- |
| [`architecture.md`](architecture.md) | Runtime shape, module layout, repository layout, database migrations, the two Docker images, and how a release is cut. |
| [`binaries.md`](binaries.md) | The two binaries, and the operator subcommands `mokosh-server` dispatches instead of serving. |
| [`postgres-security.md`](postgres-security.md) | How Postgres roles are provisioned, extensions installed, and row-level security enforced, kept in the question-and-answer form the design conversation took. |
| [`rls-per-user-isolation.md`](rls-per-user-isolation.md) | The per-user data isolation reference: schema inventory, the chosen model, and the table classification. |
| [`invoice-lifecycle.md`](invoice-lifecycle.md) | The invoice status model, and what void means here as against cancel. |
| [`e2e.md`](e2e.md) | The end-to-end suite: how it is wired, how to run it, and the failure modes you will actually hit. |

## Internal notes

[`dev-docs/`](dev-docs/README.md) holds the internal working notes: the local-versus-CI check mapping, the architecture seams, decision records, and a frozen audit snapshot. Its index says which of those is maintained and which is a point-in-time record.

Conventions for AI agents working in this repository are in [`CLAUDE.md`](../CLAUDE.md).
