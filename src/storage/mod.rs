//! PMS-910: the seam between "a feature has bytes to keep" and "where bytes
//! live".
//!
//! Before this, three modules each answered that question for themselves:
//! ticket attachments, the tenant logo, and KB article attachments all read
//! `ATTACHMENT_DIR` directly and each assembled its own path. The pattern was
//! still spreading - KB was the third and arrived after PMS-910 was written -
//! and it had already produced two defects that only a shared owner can prevent:
//!
//! - **Two roots.** Tickets and the logo fell back to `./attachments` when
//!   `ATTACHMENT_DIR` was unset; KB fell back to `/data/attachments`. One
//!   process, two roots, and nothing to notice.
//! - **Three answers to tenant scoping.** A ticket attachment lives under
//!   `{tenant}/`, a logo is named for its tenant, and a KB attachment carries
//!   no tenant anywhere in its path. Each is a convention its own module
//!   reimplements rather than a rule anything enforces.
//!
//! So the interface takes a tenant and an object's identity and never a path.
//! A caller cannot assemble one, because it is not the sort of thing any method
//! here accepts, and the layout is decided in exactly one file.
//!
//! PMS-910 changed no path at all, deliberately: a storage refactor that also
//! moves files is two risky changes wearing one commit. PMS-960 is the second
//! of the two, and closes the third bullet above. A KB attachment is now
//! addressed as `{tenant}/kb-articles/{id}` like everything else, and
//! [`ObjectKind::LegacyKbAttachment`] is the flat path it came from, kept
//! addressable so a file the mover has not reached yet is still served.
//!
//! [`LocalStore::path_for`] is where every layout decision lives, and the test
//! below pins each of them, so a future change is a deliberate edit to a stated
//! expectation rather than an accident that orphans a customer's attachments.

mod ledger;

pub use ledger::{FileLedger, FileRecord};

use std::path::{Path, PathBuf};
use std::pin::Pin;

use async_trait::async_trait;
use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

/// Storage root when `ATTACHMENT_DIR` is unset.
///
/// One value, where there were two: tickets and the logo used this, KB used
/// `/data/attachments`.
///
/// This one survives, and not because it is the prettier of the pair. A
/// compiled-in default is reached ONLY by something that configured nothing -
/// a test, a bare `cargo run`, a bare `docker run` - because every real
/// deployment sets the variable (`compose.dev.yml` line 328, and PMS-836 makes
/// a compose line mandatory for anything the code reads). And
/// `oci-build/Dockerfile` is built around this exact value: it says
/// "`ATTACHMENT_DIR` defaults to `./attachments` against WORKDIR /app, so this
/// path is also what a bare `docker run` uses", and it `mkdir -p
/// /app/attachments` so a fresh named volume is seeded with the right
/// ownership for a container that runs as uid 1001.
///
/// So an absolute default is not a tidier choice, it is a broken one: it points
/// at a directory the image never creates and the non-root user cannot make,
/// and the failure is a 500 on the first upload. PMS-910 picked the wrong
/// survivor of the two and CI caught it on the tenant-logo upload, which
/// configures no root at all.
const DEFAULT_ROOT: &str = "./attachments";

/// Where a stored object lives, relative to the root.
///
/// Each variant carries the identity its feature already uses, and NOT a path:
/// the point of the enum is that a caller says what the object is and the store
/// decides where that goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A file attached to a ticket or a ticket note. Stored per tenant since
    /// PMS-19, which is why this one already had isolation in its path.
    TicketAttachment { id: Uuid },
    /// The tenant's logo, named for the tenant inside a shared directory. The
    /// extension comes from the validated mime type, and is the only
    /// caller-supplied string anywhere in this module: see `validate_segment`.
    TenantLogo { extension: String },
    /// An image embedded in a KB article (PMS-923).
    ///
    /// Under its tenant since PMS-960, in a `kb-articles/` subdirectory beside
    /// the tenant's ticket attachments. No collision with those, which are
    /// `{tenant}/{id}`, because `kb-articles` is not a UUID.
    ///
    /// The public read still presents nothing but the id (an `<img>` carries no
    /// `Authorization` header), so the v4 UUID remains the credential there and
    /// this changes nothing about that bargain. What it changes is that the
    /// STORAGE layer no longer makes it: a key for tenant A cannot name tenant
    /// B's object, which is true of every other kind and is now true of this
    /// one.
    KbAttachment { id: Uuid },
    /// Where a KB attachment used to live: flat, with no tenant anywhere in the
    /// path.
    ///
    /// Every file uploaded before PMS-960 is at one of these, on volumes this
    /// code cannot reach, so the path has to stay addressable until the mover
    /// has been everywhere. It is its own variant rather than a flag on the one
    /// above so that reaching it means saying the word "legacy" at the call
    /// site: a fallback hidden inside `LocalStore` would apply to every read
    /// and would be reachable from any tenant's key, which is precisely the
    /// hole PMS-960 closes.
    ///
    /// Two constructors exist and both derive the tenant from a database row
    /// rather than from a request: the mover, and the public read's fallback.
    /// Delete this variant once no deployment can still hold a file under it.
    LegacyKbAttachment { id: Uuid },
}

/// A tenant and an object. The whole address, and the only thing the store
/// accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectKey {
    pub tenant_id: Uuid,
    pub kind: ObjectKind,
}

impl ObjectKey {
    pub fn ticket_attachment(tenant_id: Uuid, id: Uuid) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::TicketAttachment { id },
        }
    }

    pub fn tenant_logo(tenant_id: Uuid, extension: impl Into<String>) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::TenantLogo {
                extension: extension.into(),
            },
        }
    }

    pub fn kb_attachment(tenant_id: Uuid, id: Uuid) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::KbAttachment { id },
        }
    }

    /// The pre-PMS-960 location of a KB attachment. See
    /// [`ObjectKind::LegacyKbAttachment`] for who may call this.
    pub fn legacy_kb_attachment(tenant_id: Uuid, id: Uuid) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::LegacyKbAttachment { id },
        }
    }
}

/// A handle to an object's bytes that has not read them yet.
///
/// `AsyncRead` rather than a `Vec<u8>`, because the ticket-attachment download
/// streams: PMS-783 F6 removed a `tokio::fs::read` of a whole file into memory
/// and this interface must not put it back. `ReaderStream` wraps this directly,
/// and an object store's response body adapts to it, so the shape survives the
/// second backend (PMS-958).
pub type ObjectReader = Pin<Box<dyn AsyncRead + Send>>;

/// What a feature can ask of storage.
///
/// Deliberately small. Everything a caller needs is here and nothing that would
/// let one reach outside its tenant, because there is no method that takes a
/// path.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &ObjectKey, bytes: &[u8]) -> AppResult<()>;
    /// The whole object. For a logo or a KB image, which are already read whole
    /// and are capped in the megabytes.
    async fn read(&self, key: &ObjectKey) -> AppResult<Vec<u8>>;
    /// A reader for an object served as a stream, so a large attachment never
    /// lands in memory.
    async fn open(&self, key: &ObjectKey) -> AppResult<ObjectReader>;
    /// Best-effort: an object that is already gone is not an error, because
    /// every caller deletes the database row first and a missing blob then says
    /// the same thing as a deleted one.
    async fn delete(&self, key: &ObjectKey) -> AppResult<()>;
    async fn exists(&self, key: &ObjectKey) -> AppResult<bool>;
    /// Move an object from one key to another, atomically.
    ///
    /// Exists for the PMS-960 mover, and is a primitive rather than a
    /// `read` + `put` + `delete` at the call site for one reason: a crash
    /// part-way through the `put` leaves a truncated object at the
    /// destination, and nothing afterwards can tell that from a completed
    /// move, so a corrupt image would be served forever. A rename cannot
    /// half-happen. The S3 backend (PMS-958) has its own atomic answer
    /// (server-side copy, then delete), which is exactly why the choice
    /// belongs to the backend and not to the caller.
    ///
    /// Unlike [`delete`](Self::delete) this is NOT best-effort: a missing
    /// source is an error, because the only caller is moving something it
    /// has just established is there and a silent success would mark the
    /// object migrated when nothing moved.
    async fn rename(&self, from: &ObjectKey, to: &ObjectKey) -> AppResult<()>;
}

/// Where the local backend keeps things.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub root: PathBuf,
}

impl StorageConfig {
    /// The ONE reader of `ATTACHMENT_DIR`. Three modules used to have their own,
    /// with two different fallbacks between them.
    pub fn from_env() -> Self {
        let root = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ROOT.to_string());
        Self {
            root: PathBuf::from(root),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// The local-filesystem backend, and the only one self-hosting needs.
///
/// It stays the default with nothing configured; an S3-compatible sibling is
/// PMS-958 and is selected by configuration rather than assumed.
#[derive(Clone, Debug)]
pub struct LocalStore {
    config: StorageConfig,
}

impl LocalStore {
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    pub fn from_env() -> Self {
        Self::new(StorageConfig::from_env())
    }

    pub fn root(&self) -> &Path {
        &self.config.root
    }

    /// The layout, in one place.
    ///
    /// Each arm reproduces exactly what its module did before PMS-910, and the
    /// test at the bottom of this file pins all three. Changing one is then a
    /// visible edit to a pinned expectation rather than a line in a module that
    /// silently orphans everything already stored under the old shape.
    pub fn path_for(&self, key: &ObjectKey) -> AppResult<PathBuf> {
        Ok(self.config.root.join(key.relative_path()?))
    }
}

impl ObjectKey {
    /// Where this object lives BELOW the root, which is the half of a path that
    /// is a property of the object rather than of the deployment.
    ///
    /// PMS-957 needs it separately from [`LocalStore::path_for`], because the
    /// file ledger records where a file is and the root is not part of that: it
    /// is runtime configuration that differs between a dev container and a
    /// production volume, and an absolute path baked into a row goes stale the
    /// first time it moves. That is the same lesson `ticket_attachments`
    /// learned, whose absolute `storage_path` PMS-910 stopped reading.
    ///
    /// It is also what makes a backfill possible: a relative path is derivable
    /// in SQL from the ids a feature table already holds, where an absolute one
    /// would need the running process's configuration.
    pub fn relative_path(&self) -> AppResult<PathBuf> {
        let path = match &self.kind {
            ObjectKind::TicketAttachment { id } => {
                PathBuf::from(self.tenant_id.to_string()).join(id.to_string())
            }
            ObjectKind::TenantLogo { extension } => {
                // The only caller-supplied string that reaches a path anywhere
                // in this module. Everything else is a UUID, which cannot
                // contain a separator or a dot-dot by construction.
                validate_segment(extension)?;
                PathBuf::from("tenant-logos").join(format!("{}.{extension}", self.tenant_id))
            }
            ObjectKind::KbAttachment { id } => PathBuf::from(self.tenant_id.to_string())
                .join("kb-articles")
                .join(id.to_string()),
            ObjectKind::LegacyKbAttachment { id } => {
                PathBuf::from("kb-articles").join(id.to_string())
            }
        };
        Ok(path)
    }
}

/// Refuse anything that is not a plain lowercase-ish filename fragment.
///
/// A separator or a `..` in the one caller-supplied segment would put the
/// object outside its own prefix, and for the logo that prefix is the tenant's
/// whole isolation. The check is an allowlist rather than a search for bad
/// sequences, because a denylist of traversal spellings is the kind that gets
/// one wrong.
fn validate_segment(segment: &str) -> AppResult<()> {
    if segment.is_empty()
        || segment.len() > 16
        || !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AppError::BadRequest(format!(
            "{segment:?} is not a usable file extension"
        )));
    }
    Ok(())
}

#[async_trait]
impl ObjectStore for LocalStore {
    async fn put(&self, key: &ObjectKey, bytes: &[u8]) -> AppResult<()> {
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AppError::Internal(format!("could not create storage dir: {e}")))?;
        }
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|e| AppError::Internal(format!("could not write object: {e}")))
    }

    async fn read(&self, key: &ObjectKey) -> AppResult<Vec<u8>> {
        let path = self.path_for(key)?;
        tokio::fs::read(&path)
            .await
            .map_err(|e| AppError::NotFound(format!("object not found: {e}")))
    }

    async fn open(&self, key: &ObjectKey) -> AppResult<ObjectReader> {
        let path = self.path_for(key)?;
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| AppError::Internal(format!("object blob missing: {e}")))?;
        Ok(Box::pin(file))
    }

    async fn delete(&self, key: &ObjectKey) -> AppResult<()> {
        let path = self.path_for(key)?;
        let _ = tokio::fs::remove_file(&path).await;
        Ok(())
    }

    async fn exists(&self, key: &ObjectKey) -> AppResult<bool> {
        let path = self.path_for(key)?;
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn rename(&self, from: &ObjectKey, to: &ObjectKey) -> AppResult<()> {
        let from_path = self.path_for(from)?;
        let to_path = self.path_for(to)?;
        if let Some(parent) = to_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AppError::Internal(format!("could not create storage dir: {e}")))?;
        }
        // Same root, so same filesystem, so this is the kernel's atomic
        // rename rather than a copy that can be interrupted.
        tokio::fs::rename(&from_path, &to_path)
            .await
            .map_err(|e| AppError::Internal(format!("could not move object: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> LocalStore {
        LocalStore::new(StorageConfig {
            root: PathBuf::from("/data/attachments"),
        })
    }

    const TENANT: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const OTHER: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
    const OBJECT: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);

    /// Every layout this store knows, pinned.
    ///
    /// This is the test that makes a layout change safe to merge: every file
    /// already on a customer's volume is at one of these paths, so a change to
    /// any arm has to come here first and be seen. Getting one wrong does not
    /// fail loudly at runtime, it serves a 404 for an attachment that is still
    /// sitting on disk.
    #[test]
    fn the_layout_is_exactly_what_each_module_used_to_build() {
        let s = store();
        assert_eq!(
            s.path_for(&ObjectKey::ticket_attachment(TENANT, OBJECT))
                .unwrap(),
            PathBuf::from(format!("/data/attachments/{TENANT}/{OBJECT}"))
        );
        assert_eq!(
            s.path_for(&ObjectKey::tenant_logo(TENANT, "png")).unwrap(),
            PathBuf::from(format!("/data/attachments/tenant-logos/{TENANT}.png"))
        );
        // PMS-960 moved this one under its tenant. The path it came from is
        // still addressable, because every KB image uploaded before that
        // release is sitting at it until the mover reaches it.
        assert_eq!(
            s.path_for(&ObjectKey::kb_attachment(TENANT, OBJECT))
                .unwrap(),
            PathBuf::from(format!("/data/attachments/{TENANT}/kb-articles/{OBJECT}"))
        );
        assert_eq!(
            s.path_for(&ObjectKey::legacy_kb_attachment(TENANT, OBJECT))
                .unwrap(),
            PathBuf::from(format!("/data/attachments/kb-articles/{OBJECT}"))
        );
    }

    /// A KB attachment cannot land on a ticket attachment, which shares its
    /// tenant's directory.
    ///
    /// The two are only kept apart by `kb-articles` not being a UUID, which is
    /// true but is the sort of thing worth asserting rather than reasoning
    /// about once and forgetting.
    #[test]
    fn a_kb_attachment_cannot_collide_with_a_ticket_attachment() {
        let s = store();
        assert_ne!(
            s.path_for(&ObjectKey::kb_attachment(TENANT, OBJECT))
                .unwrap(),
            s.path_for(&ObjectKey::ticket_attachment(TENANT, OBJECT))
                .unwrap()
        );
    }

    /// Isolation is a property of the address, not of the caller remembering.
    /// Two tenants asking for "their" object of the same kind cannot land on
    /// one file. Since PMS-960 that is every kind a feature can address, which
    /// is the whole of what that issue asked for.
    #[test]
    fn two_tenants_cannot_address_the_same_object() {
        let s = store();
        assert_ne!(
            s.path_for(&ObjectKey::ticket_attachment(TENANT, OBJECT))
                .unwrap(),
            s.path_for(&ObjectKey::ticket_attachment(OTHER, OBJECT))
                .unwrap()
        );
        assert_ne!(
            s.path_for(&ObjectKey::tenant_logo(TENANT, "png")).unwrap(),
            s.path_for(&ObjectKey::tenant_logo(OTHER, "png")).unwrap()
        );
        assert_ne!(
            s.path_for(&ObjectKey::kb_attachment(TENANT, OBJECT))
                .unwrap(),
            s.path_for(&ObjectKey::kb_attachment(OTHER, OBJECT))
                .unwrap()
        );
    }

    /// The legacy path is the one exception, and it is an exception on purpose.
    ///
    /// It names a file written before there was a tenant in the layout, so it
    /// cannot suddenly have one. That is exactly why it is a separate variant
    /// nothing reaches by accident: both callers derive the tenant from a
    /// database row, and once the mover has been everywhere the variant goes.
    #[test]
    fn the_legacy_path_is_the_one_that_ignores_its_tenant() {
        let s = store();
        assert_eq!(
            s.path_for(&ObjectKey::legacy_kb_attachment(TENANT, OBJECT))
                .unwrap(),
            s.path_for(&ObjectKey::legacy_kb_attachment(OTHER, OBJECT))
                .unwrap()
        );
    }

    /// The one caller-supplied segment cannot leave its prefix. An allowlist,
    /// so a traversal spelling nobody thought of is refused by not being
    /// alphanumeric rather than by being recognised.
    #[test]
    fn a_hostile_extension_cannot_escape_the_root() {
        let s = store();
        for hostile in [
            "../../etc/passwd",
            "..",
            "png/../../..",
            "png\0",
            "",
            "a/b",
            "pngpngpngpngpngpng",
        ] {
            assert!(
                s.path_for(&ObjectKey::tenant_logo(TENANT, hostile))
                    .is_err(),
                "{hostile:?} must be refused"
            );
        }
        // And the real ones still work.
        for ok in ["png", "jpeg", "jpg", "gif", "webp", "bin"] {
            let path = s.path_for(&ObjectKey::tenant_logo(TENANT, ok)).unwrap();
            assert!(path.starts_with("/data/attachments/tenant-logos"));
        }
    }

    /// One root, from one place. Two of the three modules used to disagree
    /// about the fallback, so an unset variable split uploads across
    /// `./attachments` and `/data/attachments` in the same process.
    #[test]
    fn there_is_one_default_root() {
        const SRC: &str = include_str!("mod.rs");
        let readers = SRC.matches("ATTACHMENT_DIR").count();
        assert!(
            readers >= 1,
            "this module is the one that reads the variable"
        );
        assert_eq!(
            SRC.matches("var(\"ATTACHMENT_DIR\")").count(),
            1,
            "and it reads it exactly once"
        );
    }

    /// A move is one operation, so nothing can observe a half-moved object.
    ///
    /// This is the property the PMS-960 mover depends on and the reason
    /// `rename` is on the trait at all: a `read` + `put` + `delete` at the call
    /// site can be interrupted between the write and the unlink, and what it
    /// leaves behind at the destination is indistinguishable from a finished
    /// move.
    #[tokio::test]
    async fn a_move_carries_the_bytes_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = LocalStore::new(StorageConfig {
            root: dir.path().to_path_buf(),
        });
        let from = ObjectKey::ticket_attachment(TENANT, OBJECT);
        let to = ObjectKey::ticket_attachment(OTHER, OBJECT);
        s.put(&from, b"bytes").await.expect("put");

        s.rename(&from, &to).await.expect("rename");

        assert!(!s.exists(&from).await.expect("exists"), "source is gone");
        assert_eq!(s.read(&to).await.expect("read"), b"bytes".to_vec());
    }

    /// And a source that is not there is an error, unlike a delete.
    ///
    /// The caller is moving something it has just established exists; a silent
    /// success would let it record the object as migrated when nothing moved.
    #[tokio::test]
    async fn moving_something_that_is_not_there_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = LocalStore::new(StorageConfig {
            root: dir.path().to_path_buf(),
        });
        assert!(s
            .rename(
                &ObjectKey::ticket_attachment(TENANT, OBJECT),
                &ObjectKey::ticket_attachment(OTHER, OBJECT),
            )
            .await
            .is_err());
    }

    /// And it is relative, which is a contract rather than a preference.
    ///
    /// `oci-build/Dockerfile` `mkdir -p /app/attachments` precisely because the
    /// default resolves against its WORKDIR, so a bare `docker run` writes
    /// somewhere the non-root user owns. An absolute default points at a
    /// directory the image never creates, and the symptom is a 500 on the first
    /// upload from anything that configured no root: a test, a bare run, CI.
    /// This assertion exists because that is exactly the change PMS-910 made
    /// and had to take back.
    #[test]
    fn the_default_root_is_relative_because_the_image_depends_on_it() {
        assert!(
            !PathBuf::from(DEFAULT_ROOT).is_absolute(),
            "an absolute default writes where nothing prepared a directory"
        );
        assert_eq!(DEFAULT_ROOT, "./attachments");
    }
}
