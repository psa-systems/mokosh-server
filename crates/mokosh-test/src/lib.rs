//! PMS-1254: one migrated template per migration set, cloned per test.
//!
//! This crate is what `#[mokosh_test]` expands into, and it re-exports the
//! attribute so a test binary names one dependency. The split is forced: a
//! proc-macro crate can export nothing but macros, so the runtime half has to
//! live somewhere else, and a crate rather than another `tests/common`
//! module because nine test files carry no `mod common;` and pulling the
//! whole harness into them would be dead code in each.
//!
//! `#[sqlx::test]` creates a database per test and applies every migration
//! into it. With 243 migrations that is a second or more of Postgres work per
//! test, repeated for every test in the suite to produce an identical schema.
//! `CREATE DATABASE ... TEMPLATE` copies a migrated database in roughly a
//! tenth of the time, and because nextest gives each test its own process,
//! the thing being reused has to live in Postgres rather than in memory.
//!
//! Three properties are worth stating, because each is a way this could go
//! quietly wrong.
//!
//! **The template is named after the migrations it contains.** The name is a
//! digest over every migration's file name and bytes, so editing or adding one
//! produces a different template rather than reusing a stale schema. A suite
//! that silently ran against last week's schema would be worse than a slow
//! one.
//!
//! **A half-built template is never usable.** It is built under a
//! `_building` name and renamed only once every migration has applied, so a
//! process killed part-way through leaves a carcass that the next run drops,
//! not a template that looks finished.
//!
//! **Only one process builds it.** The build runs under a session-level
//! advisory lock on a fixed key, so the first test to arrive builds while the
//! rest wait, and they then clone.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection, PgPool};

pub use mokosh_test_macros::mokosh_test;

/// The runtime the attribute runs a body on: current-thread with every driver
/// enabled, which is what `sqlx::rt::test_block_on` builds, so a body that
/// spawns or sleeps behaves as it did under `#[sqlx::test]`.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start the test runtime")
}

/// Close the pool the body was handed, naming the test if it held on. The
/// ten-second bound and the wording are `#[sqlx::test]`'s, because a suite
/// that leaked a pool should report it the same way it did before.
pub async fn close_pool(pool: &PgPool, test_path: &str) {
    if tokio::time::timeout(Duration::from_secs(10), pool.close())
        .await
        .is_err()
    {
        eprintln!("test {test_path} held onto Pool after exiting");
    }
}

/// Tidy up after a case, on a runtime of its own.
///
/// The attribute drops the test's runtime before calling this, which is what
/// actually releases the database: a body that boots the API spawns an axum
/// server, and that task holds its connection until it is dropped, so a close
/// of the pool alone leaves a backend sitting idle on the database and
/// Postgres refuses to drop a database anything is connected to. Nothing of
/// the test survives into here, so this needs its own runtime to run the drop
/// on.
pub fn finish(db: TestDatabase, passed: bool) {
    if !passed {
        // KEPT when the body panicked, which is what `#[sqlx::test]` does and
        // the only reason a failing test can be inspected afterwards.
        db.keep_for_inspection();
        return;
    }
    runtime().block_on(db.drop_database());
}

/// The advisory-lock key the template build serialises on. Arbitrary but
/// fixed, and namespaced to this repository so it cannot collide with a lock
/// the application takes (`pg_advisory_lock` shares one space per cluster).
const BUILD_LOCK_KEY: i64 = 0x6d6f6b6f_73685f31;

/// How long a test database may take to appear before we give up. A clone is
/// ~100ms; a template build is a second or two plus however long the caller
/// waited for the lock.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the tidy-up waits for the last backend to go before it calls a
/// still-occupied database a real leak. See [`TestDatabase::drop_database`]
/// for why it waits rather than forces.
const DROP_ATTEMPTS: u32 = 60;
const DROP_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A database cloned from the template, owned by one test.
pub struct TestDatabase {
    name: String,
    admin_url: String,
    pool: PgPool,
}

impl TestDatabase {
    /// The pool the test body runs against.
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Drop the database, once nothing is on it any more.
    ///
    /// Deliberately NOT `WITH (FORCE)`, and the wait is done here rather than
    /// by `DROP DATABASE` itself for two different reasons. Forcing would
    /// terminate whatever still holds a session instead of saying so, which
    /// turns a test that leaked a connection into a test that passes quietly.
    /// And `DROP DATABASE` waits a fixed five seconds before it refuses, so
    /// letting it discover a backend that is on its way out costs five seconds
    /// per test; polling `pg_stat_activity` costs a millisecond and answers
    /// the moment the backend is gone.
    ///
    /// Something can still be there: the caller drops the test's runtime
    /// first, which closes the sockets, but Postgres reaps the backends a
    /// moment later. A database still occupied when the wait runs out is left
    /// standing with its occupants named, because that is a connection the
    /// body really did leave open and the name printed here is the thread to
    /// pull on.
    pub async fn drop_database(&self) {
        let Ok(mut admin) = PgConnection::connect(&self.admin_url).await else {
            eprintln!("could not connect to drop test database {}", self.name);
            return;
        };

        let mut holders = self.sessions_on(&mut admin).await;
        for _ in 0..DROP_ATTEMPTS {
            if holders.is_empty() {
                break;
            }
            tokio::time::sleep(DROP_RETRY_DELAY).await;
            holders = self.sessions_on(&mut admin).await;
        }
        if !holders.is_empty() {
            eprintln!(
                "test database {} still has sessions on it, so it is left in \
                 place rather than forced away: {holders:?}",
                self.name
            );
            return;
        }

        if let Err(e) = admin
            .execute(format!(r#"DROP DATABASE IF EXISTS "{}""#, self.name).as_str())
            .await
        {
            eprintln!("failed to drop test database {}: {e}", self.name);
        }
    }

    /// Who is connected, named well enough to identify the owner: the role,
    /// what it is doing and the last statement it ran.
    async fn sessions_on(&self, admin: &mut PgConnection) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT format('%s/%s/%s', usename, state, left(query, 60)) \
             FROM pg_stat_activity WHERE datname = $1",
        )
        .bind(&self.name)
        .fetch_all(&mut *admin)
        .await
        .unwrap_or_default()
    }

    /// Leave the database in place and say where it is. Called when the body
    /// panicked, so the state that failed can be inspected.
    pub fn keep_for_inspection(&self) {
        eprintln!(
            "test database kept for inspection: {} (drop it with: DROP DATABASE \"{}\")",
            self.name, self.name
        );
    }
}

/// Build the template if it is not there yet, and answer its name.
///
/// Called on its own by `integration.yml` and `just test-integration` before
/// the suite runs, so the migrations are applied by a step of the job rather
/// than by whichever test process happened to arrive first, and so the line
/// naming the template lands in the job log instead of inside one test case's
/// captured output. [`acquire`] calls the same thing, so a run that skips the
/// step still works; it just does the build under the lock with the rest of
/// the suite waiting.
pub async fn ensure_template_built() -> String {
    let base = database_url();
    let template = template_name();
    ensure_template(&maintenance_url(&base), &template).await;
    template
}

/// A fresh database for `test_path`, cloned from the migrated template,
/// building the template first if this is the process that gets there first.
pub async fn acquire(test_path: &str) -> TestDatabase {
    let base = database_url();
    let admin_url = maintenance_url(&base);
    let template = template_name();

    ensure_template(&admin_url, &template).await;

    // Unique per test and per run, so it collides with nothing: not with a
    // peer running now, and not with a database a failed run left behind.
    let name = test_database_name(test_path);
    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect to the maintenance database");
    admin
        .execute(format!(r#"CREATE DATABASE "{name}" TEMPLATE "{template}""#).as_str())
        .await
        .unwrap_or_else(|e| panic!("clone {name} from template {template}: {e}"));
    drop(admin);

    let pool = PgPoolOptions::new()
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(connect_options(&base, &name))
        .await
        .unwrap_or_else(|e| panic!("connect to test database {name}: {e}"));

    TestDatabase {
        name,
        admin_url,
        pool,
    }
}

/// Build the template if it is not there, under an advisory lock so only one
/// process does it. Returns once a template of this exact name exists.
async fn ensure_template(admin_url: &str, template: &str) {
    let mut admin = PgConnection::connect(admin_url)
        .await
        .expect("connect to the maintenance database");

    if database_exists(&mut admin, template).await {
        return;
    }

    // Session-level, so it is held across the statements below and released
    // when this connection closes, including if the process dies.
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BUILD_LOCK_KEY)
        .execute(&mut admin)
        .await
        .expect("take the template build lock");

    // Re-check: a peer may have built it while we waited.
    if database_exists(&mut admin, template).await {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(BUILD_LOCK_KEY)
            .execute(&mut admin)
            .await;
        return;
    }

    // A carcass from a run that died part-way through. Nothing is connected to
    // it: this process holds the build lock, so no peer is building, and the
    // process that made it is gone. A refusal here therefore means something
    // this code does not know about is holding the name, which is worth the
    // hard failure rather than a FORCE that would paper over it.
    let building = format!("{template}_building");
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{building}""#).as_str())
        .await
        .expect("drop a half-built template from a previous run");
    admin
        .execute(format!(r#"CREATE DATABASE "{building}""#).as_str())
        .await
        .expect("create the template database");

    let base = database_url();
    {
        let mut conn = PgConnection::connect_with(&connect_options(&base, &building))
            .await
            .expect("connect to the template being built");
        sqlx::migrate!("../../migrations")
            .run(&mut conn)
            .await
            .expect("apply migrations into the template");
        conn.close().await.ok();
    }

    // Only now does it get the name everything else clones from.
    admin
        .execute(format!(r#"ALTER DATABASE "{building}" RENAME TO "{template}""#).as_str())
        .await
        .expect("publish the template");
    // One line per run, from the one process that built it, which is what
    // proves the migrations ran once rather than once per test.
    eprintln!("mokosh-test: built template {template} from ./migrations");

    drop_stale_templates(&mut admin, template).await;

    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BUILD_LOCK_KEY)
        .execute(&mut admin)
        .await;
}

/// Drop templates from older migration sets. The CI cluster is thrown away
/// after the run; a developer's is not, and one template per migration change
/// would accumulate. Only ones nobody is connected to, and never this one.
async fn drop_stale_templates(admin: &mut PgConnection, keep: &str) {
    let stale: Vec<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database d \
         WHERE datname LIKE 'mokosh_tpl_%' AND datname <> $1 \
           AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
    )
    .bind(keep)
    .fetch_all(&mut *admin)
    .await
    .unwrap_or_default();
    for name in stale {
        // The query already excluded anything with a session on it, so no
        // FORCE: a refusal means one arrived in between, and leaving that
        // template for the next run to collect is the right answer.
        if let Err(e) = admin
            .execute(format!(r#"DROP DATABASE IF EXISTS "{name}""#).as_str())
            .await
        {
            eprintln!("could not drop stale template {name}: {e}");
        }
    }
}

async fn database_exists(admin: &mut PgConnection, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(name)
        .fetch_one(&mut *admin)
        .await
        .unwrap_or(false)
}

/// The template's name, derived from the migrations it will contain, so a
/// change to any of them produces a different template rather than reusing a
/// schema that no longer matches the tree.
fn template_name() -> String {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("read the migrations directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("sql"))
        .collect();
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.file_name().expect("file name").as_encoded_bytes());
        hasher.update(std::fs::read(&path).expect("read a migration"));
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("mokosh_tpl_{hex}")
}

/// A database name unique to this test and this run: the test path, so a
/// kept failure says which test it belongs to, plus a random tail so two runs
/// never collide.
fn test_database_name(test_path: &str) -> String {
    // Postgres truncates an identifier at 63 bytes and says so in a NOTICE.
    // The UUID therefore goes FIRST: with the readable part in front, a long
    // test path pushed the random tail over the edge and two tests whose names
    // agreed for 63 characters would have been handed one database. The tail
    // of the path is what is kept, because that is the test's own name rather
    // than the module it sits in.
    const MAX_IDENTIFIER: usize = 63;
    let prefix = format!("mokosh_t_{}_", uuid::Uuid::new_v4().simple());
    let room = MAX_IDENTIFIER - prefix.len();

    let slug: String = test_path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let tail: String = slug
        .chars()
        .rev()
        .take(room)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}{}", tail.trim_matches('_'))
}

/// Connection options for `name` on the same server `DATABASE_URL` points at.
fn connect_options(base: &str, name: &str) -> PgConnectOptions {
    base.parse::<PgConnectOptions>()
        .expect("DATABASE_URL is not a valid Postgres URL")
        .database(name)
}

/// The cluster every database here lives on.
fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for database-backed tests")
}

/// `DATABASE_URL` pointed at a database that always exists, for CREATE and
/// DROP, which cannot run inside the database they are changing.
fn maintenance_url(base: &str) -> String {
    let mut url = url::Url::parse(base).expect("DATABASE_URL is not a valid URL");
    url.set_path("/postgres");
    url.to_string()
}
