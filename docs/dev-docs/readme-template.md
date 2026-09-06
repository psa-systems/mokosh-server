# The README template

The structure every repository in this estate settles on, so a reader who has
seen one README can navigate the next. Settled on mokosh-server first; bunyip
and mokosh-apps are brought across to it.

## The rule

A README says what the thing is and where to read more. Detail belongs in
`docs/`. A README that carries the architecture, the binaries, the operator
subcommands and the configuration table becomes the place all four go stale,
because nothing links to a README section and nothing checks one.

## The sections, in order

1. `# Repository name`, then **one line** saying what it is.
2. The demonstration GIF.
3. **Try it**: the live environment, with a warning that its state is wiped on
   every deploy, where such an environment exists.
4. **Documentation**: a link to `docs/README.md`, plus a short list of the
   pages a first-time reader wants.
5. **Development happens on Forgejo**: which host is the development home and
   that the mirrors have issues and pull requests disabled. Dropping this from
   a mirrored repository leaves a reader with nowhere to file.
6. **Security**: how to report a suspected vulnerability privately.
7. **License**.
8. **Authors and credits**: who builds it, and the third-party projects it is
   built on. Organizations and teams, never individuals: the tree is name-free
   by decision, and a README is the easiest place to reverse that by accident.

Nothing else. If a section does not fit one of those eight, it is a `docs/`
page with a link from section 4.

## Three mechanical constraints, each learned the hard way

- **The GIF stays an HTML comment until the asset is committed in-repo.** The
  link checker skips HTML comments but resolves a live `![...](...)` target, so
  uncommenting before the file lands fails the check. A cross-repo relative path
  does not render on the mirrors and a raw asset URL is fragile, so the asset is
  committed into this repository, not linked out of another.
- **Any page that gains a `just <recipe>` span joins the repo's doc-recipe
  guard.** In this repository that is `const DOCS` in
  `scripts/check-doc-recipes.nu`. Moving guarded commands to an unlisted page
  drops them from the guard, and the guard reports success while covering less
  than it did: it can only fail on a doc naming a recipe that does not exist,
  never on a doc leaving its scope.
- **The security section does not invent a disclosure address.** Until a
  private channel is decided and published, the section says not to file a
  vulnerability in the public tracker, says to contact a maintainer privately,
  and says the address and a `SECURITY.md` are being set up. A mailbox nobody
  reads is worse than no mailbox, because it looks like a channel.

## What to check when applying it elsewhere

- Every section cut from the README landed on a `docs/` page, and that page is
  linked from section 4. Diff each cut section against the page that already
  covers it before deleting: much of a first README is a worse copy of the
  quickstart.
- Every claim that survived the move is still true. A README is where stale
  claims accumulate, so treat the pass as a correction pass, not a move.
- The repo's own link check passes over the new pages, which in this repository
  means staging them first: the checker enumerates tracked files, so an
  unstaged new page is invisible to it and the check passes vacuously.
