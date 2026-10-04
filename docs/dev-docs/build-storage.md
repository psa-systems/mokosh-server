# Where builds land, and what they cost in memory (PMS-973)

The shared development machines ran out of memory often enough that the team
coordinated who was allowed to build. Two causes were named at the 2026-08-21
standup: the per-developer Infisical instances, since moved to their own server,
and cargo building "in memory rather than to storage". This page records what is
actually true per path, with numbers, because the second half of that diagnosis
turns out to be two different things and only one of them is about where the
artifacts go.

## Where a build writes

| How it is run | Target directory | Filesystem |
| --- | --- | --- |
| `just check`, `just pre-commit`, `just pre-push`, `just test-integration`, anything in the dev container | `/app/target`, the `dev-mokosh-server-target-${USER}` volume | Docker's storage directory, which on desktop-02 is `/srv/d4/docker-daemon` on one of the drives added in August 2026 |
| `cargo` run directly in a checkout on the host | `<repo>/target` | Whatever the checkout sits on, which on desktop-02 is `/home` |

Both are disk-backed on desktop-02 as of 2026-09-27, and `CARGO_TARGET_DIR` is
set nowhere: not in a shell profile, not in the compose file, not in
`.cargo/config.toml`. So on that host nothing has been building into memory.
What makes it possible is that `/tmp` is a 46 GiB tmpfs, so a target directory
pointed there, by an `export` in one session or by an editor or agent that sets
the variable, is memory. `scripts/check-build-target-storage.nu` (`just
check-build-target-storage`, and a step in `check.yml`) resolves the path cargo
will actually use and fails when its filesystem is tmpfs or ramfs. It is a check
rather than a setting because the variable can come from anywhere, and none of
those places travel with the checkout.

## What the location is worth, measured

Two from-scratch `cargo check --all-targets` runs on desktop-02 (2026-09-27,
32 cores, 91 GiB RAM, swap already fully consumed), identical except for where
the target directory sat. `/proc/meminfo` sampled every two seconds; deltas are
against the first sample of each run.

| | target on `/home` (ext4) | target on `/tmp` (tmpfs) |
| --- | --- | --- |
| Wall clock | 49 s | 49 s |
| Artifacts written | 3.0 GiB | 3.0 GiB |
| `AnonPages` peak delta | +5.0 GiB | +4.5 GiB |
| `Shmem` peak delta | +1 MiB | +2.7 GiB |
| `Dirty` peak delta | +2.0 GiB | +7 MiB |
| `MemAvailable` worst dip | -5.4 GiB | -6.6 GiB |

Three things fall out of that.

**The compilers are the memory cost, and the target directory does not change
them.** About 4.5 to 5 GiB of anonymous memory either way, for a `cargo check`;
a full `cargo build` is higher. Anonymous memory is the kind that cannot be
reclaimed without swapping, and swap on this host is already gone. Several
developers compiling at once is therefore still the way to exhaust memory, and
moving artifacts to disk does not help with it.

**Where the artifacts go decides whether their bytes are reclaimable.** On disk
they land in page cache (`Cached`, +2.7 GiB) plus a transient writeback backlog
(`Dirty`, peaking at 2.0 GiB) that drains by itself, and the kernel can evict all
of it the moment something needs the memory. On tmpfs the same bytes are `Shmem`,
+2.7 GiB, and they stay until somebody deletes the directory. A `cargo check` is
the small case: `<repo>/target` in this workspace holds 190 GiB, so the
difference at the scale a real build reaches is not 2.7 GiB of reclaimable cache
against 2.7 GiB of pinned memory, it is tens of gigabytes.

**Disk costs nothing in speed here.** Identical wall clock, which answers the
question the standup was really worried about.

A caution on reading `free -h` during a build: page cache counts under `used` on
some versions and under `buff/cache` on others, and either way it is not
consumption. `MemAvailable` is the number that answers "can another process get
memory", and `AnonPages` plus `Shmem` is what is actually spoken for.

## Reproducing the measurement

Nushell. `meminfo-mib` is the whole instrument: the five fields that tell the
story, in MiB, because which of them moves is the answer.

```nu
def meminfo-mib [] {
    open --raw /proc/meminfo
    | decode utf-8
    | lines
    | parse --regex '(?<key>[A-Za-z_()]+):\s+(?<kb>\d+)'
    | where key in ["MemAvailable" "Cached" "AnonPages" "Dirty" "Shmem"]
    | reduce --fold {} {|row, acc| $acc | insert $row.key (($row.kb | into int) / 1024 | math round) }
}
```

Run the build with its own throwaway target directory, sampling beside it:

```nu
let target = "/home/long/.cache/build-measure"
rm --recursive --force $target
let sampler = (job spawn {
    mut rows = []
    loop {
        $rows = ($rows | append (meminfo-mib))
        $rows | to json | save --force /tmp/build-measure-samples.json
        sleep 2sec
    }
})
with-env { CARGO_TARGET_DIR: $target, SQLX_OFFLINE: "true" } {
    cargo check --all-targets --locked
}
job kill $sampler
let rows = (open /tmp/build-measure-samples.json)
let base = ($rows | first)
$rows
| columns
| each {|k| {
    field: $k
    start: ($base | get $k)
    peak: ($rows | each {|r| $r | get $k } | math max)
    low: ($rows | each {|r| $r | get $k } | math min)
} }
du --summarize $target
rm --recursive --force $target
```

Measuring the tmpfs case means the same with `$target` under `/tmp`, plus
`MOKOSH_ALLOW_TMPFS_TARGET: "true"` in the `with-env` record so the guard lets it
through rather than failing the run it is there to prevent. Record the numbers on
the issue that prompted them.

## The open item, which needs root

Disk is no longer scarce in general on desktop-02, but it is on `/home`: 87 %
full, 116 GiB left, and 363 GiB of that is two target directories (190 GiB for
mokosh-server, 173 GiB for mokosh-apps). The drive added for this host,
`/srv/d4`, has 1.1 TiB free and is owned by root with no per-user directory, so a
developer cannot point a target there even deliberately. Docker's own storage is
already on it, which is why container builds are fine and host builds are the
ones crowding `/home`.

Closing that needs one directory per user on the drive, on each shared host, and
therefore root. It is PMS-1406, and it is deliberately not in this repository's
scope: the fix belongs to the host profile, not to a checkout.
