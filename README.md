# Mokosh Server

Professional Services Automation (PSA) platform for MSPs: a REST API server built on Rust, Axum, SQLx and PostgreSQL.

<!--
BUNYIP-587 records the shared Bunyip-to-Mokosh walkthrough GIF. When it lands,
commit a copy at docs/assets/mokosh-walkthrough.gif (a cross-repo relative path
to the Bunyip copy does not render on the mirrors, and hot-linking the raw asset
URL is fragile) and replace this comment with:
![Mokosh walkthrough](docs/assets/mokosh-walkthrough.gif)
-->

## Try it

Live staging: **<https://msp.a8n.systems>**. Sign in through the platform and click through the product; the walkthrough starts in Bunyip and moves into Mokosh.

> Staging shows features **in development**, not a polished demo. State is **wiped on every deploy** - accounts and data are throwaway. Do not reuse a real password.

## Documentation

Everything else is in [`docs/`](docs/README.md), indexed there in full:

- [quickstart.md](docs/quickstart.md) - get a fresh clone running on a Linux host
- [architecture.md](docs/architecture.md) - runtime shape, repository layout, migrations, images
- [binaries.md](docs/binaries.md) - the two binaries and the operator subcommands they dispatch
- [configuration.md](docs/configuration.md) - every environment variable and where its value comes from
- [recipes.md](docs/recipes.md) - the task runner, recipe by recipe

Conventions for AI agents working in this repository are in [CLAUDE.md](CLAUDE.md).

## Development happens on Forgejo

The development home for this repository is <https://dev.a8n.run/psa-systems/mokosh-server>. The [GitHub](https://github.com/psa-systems/mokosh-server) and [Codeberg](https://codeberg.org/psa-systems/mokosh-server) copies are read-only mirrors that exist for visibility only: issues and pull requests are disabled there, and no community support runs on the mirrors. File issues and open pull requests on Forgejo.

## Security

Please do not report a suspected vulnerability through the public issue tracker, on Forgejo or on either mirror: filing it there publishes it. Contact a maintainer privately instead. A published disclosure address and a `SECURITY.md` are being set up and this section will link to them.

## License

Proprietary. See `Cargo.toml`; there is no separate license file.

## Authors and credits

Mokosh Server is built by PSA Systems, and `Cargo.toml` carries the authoritative author and license fields.

Built on [Rust](https://www.rust-lang.org/), [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx), [Tokio](https://tokio.rs/), [PostgreSQL](https://www.postgresql.org/) and [Lettre](https://lettre.rs/), driven by [just](https://github.com/casey/just) and [Nushell](https://www.nushell.sh/), deployed behind [Traefik](https://traefik.io/), and able to keep tenant secrets in [Infisical](https://infisical.com/).
