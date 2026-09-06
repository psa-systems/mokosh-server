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
//! [`LocalProvider::path_for`] is where every layout decision lives, and the test
//! below pins each of them, so a future change is a deliberate edit to a stated
//! expectation rather than an accident that orphans a customer's attachments.
//!
//! PMS-958 found the seam documented and not built: `dyn ObjectProvider`
//! appeared nowhere, six structs held a `LocalProvider` by name and four free
//! functions constructed one inline, so "selected by configuration" had nowhere
//! to plug in. Every caller now holds an `Arc<dyn ObjectProvider>` from
//! [`shared`], which is built once per process from `STORAGE_BACKEND` and
//! touched first by `main` so a misconfigured provider ends startup rather than
//! the first upload. A process-wide handle rather than a constructor argument,
//! because the provider is constructed at thirteen sites across the router, the
//! tenants routes, billing and the seeders, and because an object-store client
//! owns a connection pool that is only useful if it is shared; `utils::net` and
//! `utils::client_ip` hold their env-derived configuration the same way.
//!
//! PMS-1010 settled the word: a selectable implementation of a capability is a
//! PROVIDER, here as in [`crate::secrets`] and as
//! [`crate::modules::billing::provider::PaymentProvider`] already was. The
//! operator-facing variable is still `STORAGE_BACKEND` and deliberately so:
//! renaming it breaks every existing deployment for a vocabulary change.

mod ledger;
pub mod s3;

pub use ledger::{FileLedger, FileRecord};

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::utils::deployment::{provider, EnablementSource};
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
/// the point of the enum is that a caller says what the object is and the
/// provider decides where that goes.
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
    /// PMS-959: the PDF of a financial document, as it was issued.
    ///
    /// One per invoice or credit note, keyed on that document's own id. Written
    /// once, inside the transaction that freezes the document, and never
    /// rewritten: what was sent is a fact, and a second write would make it a
    /// rendering again.
    ///
    /// Stored rather than regenerated for one reason, which is narrower than it
    /// looks. Branding is frozen (PMS-911) and `crate::pdf::render` is a pure
    /// function of its input, so a re-render from the snapshot agrees with what
    /// was sent - until somebody edits the renderer or the document layout, at
    /// which point every past invoice quietly reprints differently. These bytes
    /// are insurance against this codebase changing, not against the data
    /// changing.
    FinancialDocument { id: Uuid },
    /// PMS-911: a copy of a logo, frozen at the moment an invoice was sent.
    ///
    /// Content-addressed by a digest of its own bytes, for a reason particular
    /// to what it is for. The live tenant logo is written to ONE key per tenant
    /// and overwritten on replace (`TenantLogoStore` says so outright), so an
    /// invoice snapshot that held its ADDRESS would re-render with whatever
    /// logo is current: replacing a logo would silently change every invoice
    /// already sent, which is the thing PMS-911 exists to prevent. Holding the
    /// bytes instead makes the snapshot immutable, and addressing them by
    /// digest means one object is shared by every invoice sent while that logo
    /// was current rather than a megabyte copied per invoice.
    BrandingLogo { digest: String },
    /// Where a KB attachment used to live: flat, with no tenant anywhere in the
    /// path.
    ///
    /// Every file uploaded before PMS-960 is at one of these, on volumes this
    /// code cannot reach, so the path has to stay addressable until the mover
    /// has been everywhere. It is its own variant rather than a flag on the one
    /// above so that reaching it means saying the word "legacy" at the call
    /// site: a fallback hidden inside `LocalProvider` would apply to every read
    /// and would be reachable from any tenant's key, which is precisely the
    /// hole PMS-960 closes.
    ///
    /// Two constructors exist and both derive the tenant from a database row
    /// rather than from a request: the mover, and the public read's fallback.
    /// Delete this variant once no deployment can still hold a file under it.
    LegacyKbAttachment { id: Uuid },
}

/// How long an object has to be kept (PMS-959).
///
/// **Declared, not enforced.** Nothing in this codebase deletes a stored object
/// on a schedule: there is no reaper, and this enum does not add one. What it
/// does is put the answer where the object's identity already lives, so
/// whatever eventually sweeps has one place to ask rather than a rule
/// rediscovered per feature. Writing this as if it were enforced would be worse
/// than not writing it at all, so it says so here and the test below pins that
/// no caller treats it as a delete authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep while something references it. An attachment, a logo: the feature
    /// row's own lifetime decides, and deleting the row deletes the object.
    WhileReferenced,
    /// Keep for a fixed period regardless of what references it, because the
    /// law rather than the product decides. PMS-910 recorded seven years for
    /// financial documents, shortened only against a stated legal requirement
    /// and never by default.
    Years(u32),
}

impl ObjectKind {
    /// What the object's kind says about how long it lives.
    pub fn retention(&self) -> Retention {
        match self {
            // An invoice or a credit note is a financial record. It outlives
            // the row that points at it and it outlives a tenant deciding to
            // tidy up, because the obligation to produce it is not this
            // product's to waive.
            ObjectKind::FinancialDocument { .. } => Retention::Years(7),
            ObjectKind::TicketAttachment { .. }
            | ObjectKind::TenantLogo { .. }
            | ObjectKind::KbAttachment { .. }
            | ObjectKind::LegacyKbAttachment { .. }
            // A frozen logo lives as long as the documents that show it, which
            // is the financial retention above; it is content-addressed and
            // shared, so it cannot be reasoned about on its own and no sweep
            // may remove one while any document still names its digest.
            | ObjectKind::BrandingLogo { .. } => Retention::WhileReferenced,
        }
    }
}

/// A tenant and an object. The whole address, and the only thing the provider
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

    /// PMS-959: the issued PDF of an invoice or a credit note.
    pub fn financial_document(tenant_id: Uuid, id: Uuid) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::FinancialDocument { id },
        }
    }

    /// PMS-911: a frozen copy of a logo, named by a digest of its bytes.
    pub fn branding_logo(tenant_id: Uuid, digest: impl Into<String>) -> Self {
        Self {
            tenant_id,
            kind: ObjectKind::BrandingLogo {
                digest: digest.into(),
            },
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
/// second provider (PMS-958).
pub type ObjectReader = Pin<Box<dyn AsyncRead + Send>>;

/// What a feature can ask of storage.
///
/// Deliberately small. Everything a caller needs is here and nothing that would
/// let one reach outside its tenant, because there is no method that takes a
/// path.
#[async_trait]
pub trait ObjectProvider: Send + Sync + std::fmt::Debug {
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
    /// half-happen. The S3 provider (PMS-958) has its own atomic answer
    /// (server-side copy, then delete), which is exactly why the choice
    /// belongs to the provider and not to the caller.
    ///
    /// Unlike [`delete`](Self::delete) this is NOT best-effort: a missing
    /// source is an error, because the only caller is moving something it
    /// has just established is there and a silent success would mark the
    /// object migrated when nothing moved.
    async fn rename(&self, from: &ObjectKey, to: &ObjectKey) -> AppResult<()>;
    /// Where the object is, in this provider's own words: an absolute path on
    /// the local one, a bucket URL on an object store.
    ///
    /// Descriptive only. It exists because `ticket_attachments.storage_path`
    /// is `NOT NULL` and every row holds one, and for a log line. It is a
    /// `String` rather than a path so that no caller can hand it back as an
    /// address: the only way to reach an object is still an [`ObjectKey`].
    fn location(&self, key: &ObjectKey) -> AppResult<String>;
}

/// Where the local provider keeps things.
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

/// The local-filesystem provider, and the only one self-hosting needs.
///
/// It stays the default with nothing configured; an S3-compatible sibling is
/// PMS-958 and is selected by configuration rather than assumed.
#[derive(Clone, Debug)]
pub struct LocalProvider {
    config: StorageConfig,
}

impl LocalProvider {
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
    /// PMS-957 needs it separately from [`LocalProvider::path_for`], because the
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
            ObjectKind::FinancialDocument { id } => PathBuf::from(self.tenant_id.to_string())
                .join("documents")
                .join(id.to_string()),
            ObjectKind::BrandingLogo { digest } => {
                // The second caller-supplied string this module accepts, and
                // held tighter than the logo extension: a digest is
                // machine-generated, so anything that is not one is a bug or an
                // attack rather than an unusual filename.
                validate_digest(digest)?;
                PathBuf::from(self.tenant_id.to_string())
                    .join("branding")
                    .join(digest)
            }
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

/// Exactly a lowercase hex SHA-256, and nothing else.
///
/// An allowlist like [`validate_segment`], but narrower, because the only
/// caller computes this value rather than receiving it: a digest that is not 64
/// hex characters did not come from `Sha256`, so refusing it is refusing a bug
/// rather than inconveniencing a user.
fn validate_digest(digest: &str) -> AppResult<()> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::Internal(format!(
            "{digest:?} is not a content digest"
        )));
    }
    Ok(())
}

#[async_trait]
impl ObjectProvider for LocalProvider {
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

    fn location(&self, key: &ObjectKey) -> AppResult<String> {
        // Byte-identical to what `AttachmentService` wrote into
        // `storage_path` before PMS-958, because every existing row holds
        // that shape and a reader that comes back for the column should find
        // one value, not two.
        Ok(self.path_for(key)?.to_string_lossy().into_owned())
    }
}

/// Which implementation a deployment runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageProviderKind {
    /// The filesystem under `ATTACHMENT_DIR`. The default, and the only one
    /// self-hosting needs.
    Local,
    /// An S3-compatible object store, configured by the `S3_*` variables
    /// (PMS-958).
    S3,
}

impl StorageProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageProviderKind::Local => provider::LOCAL,
            StorageProviderKind::S3 => provider::S3,
        }
    }

    /// The ONE reader of `STORAGE_BACKEND`, the way [`StorageConfig::from_env`]
    /// is the only reader of `ATTACHMENT_DIR`.
    ///
    /// Returns the source alongside the backend (PMS-1011), because "nobody
    /// configured this and the hosting profile chose local" and "the operator
    /// asked for local" are different facts and the boot record reports both.
    /// The hosting profile's own strictness is the startup wiring's business:
    /// it hands in an already-resolved provider name.
    pub fn from_env(profile_default: &str) -> AppResult<(Self, EnablementSource)> {
        Self::resolve(
            profile_default,
            &std::env::var("STORAGE_BACKEND").unwrap_or_default(),
        )
    }

    /// An unset or blank value takes `profile_default`, the hosting profile's
    /// provider for [`ProviderKind::Storage`], which is `local` in both modes:
    /// a forwarded-but-unset variable arrives as `""` (PMS-836) and the
    /// default has to be the one that needs no other service, since no
    /// integration is a hard requirement.
    ///
    /// The default arrives as a NAME rather than as the deployment shape, so
    /// this module never holds that knowledge (PMS-904 confines it to the auth
    /// service and the startup wiring) and only needs to know which provider
    /// it got.
    pub fn resolve(profile_default: &str, raw: &str) -> AppResult<(Self, EnablementSource)> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok((Self::parse(profile_default)?, EnablementSource::Profile));
        }
        Ok((Self::parse(raw)?, EnablementSource::Explicit))
    }

    /// A provider NAME to a backend. An unrecognised value is a hard error
    /// rather than a fall back to local, the same rule `SECRET_BACKEND`
    /// follows: an operator who wrote `STORAGE_BACKEND=s3 ` with a typo asked
    /// for S3, and quietly writing their uploads to a container filesystem
    /// instead is the silent degrade this crate refuses everywhere else. Blank
    /// is not a name; [`resolve`](Self::resolve) settles it against the
    /// profile before it reaches here, so this cannot become a second place
    /// that knows the default.
    pub fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim() {
            provider::LOCAL => Ok(StorageProviderKind::Local),
            provider::S3 => Ok(StorageProviderKind::S3),
            other => Err(AppError::Configuration(format!(
                "STORAGE_BACKEND {other:?} is not a known provider; expected 'local' or 's3'"
            ))),
        }
    }
}

/// Build the provider this deployment is configured for.
///
/// The ONE place a [`StorageProviderKind`] becomes an [`ObjectProvider`], so no
/// construction site can pick a provider of its own. Fallible, so that
/// [`init_from_env`] can end startup on a bad configuration: the local provider
/// cannot fail to build, but the S3 one refuses a half-configured deployment
/// here rather than on the first upload.
///
/// Returns the resolution alongside the provider (PMS-1011) so the boot record
/// can report what serves storage and whether the hosting profile or the
/// operator chose it, without a second reader of `STORAGE_BACKEND`.
pub fn provider_from_env(
    profile_default: &str,
) -> AppResult<(Arc<dyn ObjectProvider>, EnablementSource)> {
    let (provider, source) = StorageProviderKind::from_env(profile_default)?;
    let built: Arc<dyn ObjectProvider> = match provider {
        StorageProviderKind::Local => Arc::new(LocalProvider::from_env()),
        StorageProviderKind::S3 => Arc::new(s3::S3Provider::from_env()?),
    };
    tracing::info!(
        provider = provider.as_str(),
        source = source.as_str(),
        "storage provider selected"
    );
    Ok((built, source))
}

static SHARED: OnceLock<Arc<dyn ObjectProvider>> = OnceLock::new();

/// Build the process-wide provider from the environment, once, and fail loudly.
///
/// `main` calls this before it builds anything that stores bytes, which is
/// what makes a misconfigured provider a boot failure rather than a 500 on the
/// first upload. A second call after the first succeeded returns the provider
/// already built and reads no configuration.
/// Returns the selection it made (PMS-1011), so the boot record reports what
/// serves storage and who chose it without reading `STORAGE_BACKEND` a second
/// time.
pub fn init_from_env(profile_default: &str) -> AppResult<(StorageProviderKind, EnablementSource)> {
    let (kind, source) = StorageProviderKind::from_env(profile_default)?;
    if SHARED.get().is_none() {
        let built: Arc<dyn ObjectProvider> = match kind {
            StorageProviderKind::Local => Arc::new(LocalProvider::from_env()),
            StorageProviderKind::S3 => Arc::new(s3::S3Provider::from_env()?),
        };
        tracing::info!(
            provider = kind.as_str(),
            source = source.as_str(),
            "storage provider selected"
        );
        let _ = SHARED.set(built);
    }
    Ok((kind, source))
}

/// The provider every feature uses.
///
/// Built from the environment on first use when nothing called
/// [`init_from_env`], which is the test and CLI path; a configuration that
/// cannot build is a panic there, because there is no request to answer with a
/// 500 and no startup to end.
pub fn shared() -> Arc<dyn ObjectProvider> {
    SHARED
        .get_or_init(|| {
            provider_from_env(provider::LOCAL)
                .unwrap_or_else(|e| panic!("storage provider configuration: {e}"))
                .0
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> LocalProvider {
        LocalProvider::new(StorageConfig {
            root: PathBuf::from("/data/attachments"),
        })
    }

    const TENANT: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const OTHER: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
    const OBJECT: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);
    /// A SHA-256 shaped string: 64 hex characters.
    const DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    /// Every layout this provider knows, pinned.
    ///
    /// This is the test that makes a layout change safe to merge: every file
    /// already on a customer's volume is at one of these paths, so a change to
    /// any arm has to come here first and be seen. Getting one wrong does not
    /// fail loudly at runtime, it serves a 404 for an attachment that is still
    /// sitting on disk.
    #[test]
    fn the_layout_is_exactly_what_each_module_used_to_build() {
        let s = provider();
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
        assert_eq!(
            s.path_for(&ObjectKey::branding_logo(TENANT, DIGEST))
                .unwrap(),
            PathBuf::from(format!("/data/attachments/{TENANT}/branding/{DIGEST}"))
        );
    }

    /// A digest is machine-generated, so anything that is not one is refused
    /// rather than sanitised. The traversal cases matter for the same reason
    /// the logo extension's do: this is the only other caller-supplied string
    /// that reaches a path.
    #[test]
    fn only_a_real_digest_names_a_branding_logo() {
        let s = provider();
        for hostile in [
            "../../etc/passwd",
            "..",
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            &format!("{}/x", "a".repeat(62)),
            &"g".repeat(64),
        ] {
            assert!(
                s.path_for(&ObjectKey::branding_logo(TENANT, hostile))
                    .is_err(),
                "{hostile:?} must be refused"
            );
        }
        assert!(s
            .path_for(&ObjectKey::branding_logo(TENANT, DIGEST.to_uppercase()))
            .is_ok());
    }

    /// A KB attachment cannot land on a ticket attachment, which shares its
    /// tenant's directory.
    ///
    /// The two are only kept apart by `kb-articles` not being a UUID, which is
    /// true but is the sort of thing worth asserting rather than reasoning
    /// about once and forgetting.
    #[test]
    fn a_kb_attachment_cannot_collide_with_a_ticket_attachment() {
        let s = provider();
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
        let s = provider();
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
        // Two tenants can hold identical logo bytes; the digest is the same and
        // the object still must not be.
        assert_ne!(
            s.path_for(&ObjectKey::branding_logo(TENANT, DIGEST))
                .unwrap(),
            s.path_for(&ObjectKey::branding_logo(OTHER, DIGEST))
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
        let s = provider();
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
        let s = provider();
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

    /// And one place picks the root on the test side, for the same reason.
    ///
    /// Nine Postgres-backed suites each named a fixed path under `/tmp`. `/tmp`
    /// is world-writable with the sticky bit, so the first OS user to run a
    /// suite on a host owned the directory and the second got `Permission
    /// denied`, surfaced through the API as a 500 that reads as a defect in
    /// this module. Each of those nine was written by copying the suite beside
    /// it, and three of them landed after the defect was already filed, so the
    /// rule is enforced here rather than left to the next person to notice.
    ///
    /// `tests/common/mod.rs` is the exception because it is the helper: it
    /// hands out a `tempfile` root unique to the run and exports the variable.
    /// A suite that needs the path calls it rather than composing one.
    ///
    /// The needle carries its quotes so this reads as "no suite names the
    /// variable in code". `set_var` takes the key as a string literal and so
    /// does a `const` holding it, while a doc comment naming the variable in
    /// backticks is ordinary prose and stays allowed: two suites explain when
    /// the provider reads it, which is worth keeping.
    #[test]
    fn only_the_test_harness_picks_a_storage_root() {
        let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        // The crate compiles without its integration suites (the release image
        // never copies them), so an absent directory is nothing to report.
        if !tests.is_dir() {
            return;
        }

        let needle = concat!("\"ATTACHMENT", "_DIR\"");
        let mut offenders: Vec<String> = Vec::new();
        let mut pending = vec![tests.clone()];

        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read the tests directory") {
                let entry = entry.expect("read a tests directory entry");
                let path = entry.path();
                if entry.file_type().expect("read entry type").is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let relative = path
                    .strip_prefix(&tests)
                    .expect("path came from this walk")
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative == "common/mod.rs" {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("read a test source file");
                if body.contains(needle) {
                    offenders.push(relative);
                }
            }
        }

        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these suites name ATTACHMENT_DIR in code instead of calling \
             common::storage_root(), which is how a fixed path under a \
             world-writable directory keeps coming back: {offenders:?}"
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
        let s = LocalProvider::new(StorageConfig {
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
        let s = LocalProvider::new(StorageConfig {
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

    /// A financial document is kept for seven years; everything else lives as
    /// long as the row that points at it.
    ///
    /// The assertion that matters is the second half of the doc comment on
    /// [`Retention`]: this is a declaration, and nothing here deletes anything.
    /// If a sweep is ever written, it goes through this and not through a rule
    /// of its own.
    #[test]
    fn a_financial_document_outlives_the_row_that_points_at_it() {
        assert_eq!(
            ObjectKind::FinancialDocument { id: OBJECT }.retention(),
            Retention::Years(7)
        );
        for kind in [
            ObjectKind::TicketAttachment { id: OBJECT },
            ObjectKind::TenantLogo {
                extension: "png".into(),
            },
            ObjectKind::KbAttachment { id: OBJECT },
            ObjectKind::BrandingLogo {
                digest: DIGEST.into(),
            },
        ] {
            assert_eq!(kind.retention(), Retention::WhileReferenced, "{kind:?}");
        }
    }

    /// Nothing acts on a retention yet, and that is the honest state.
    ///
    /// `Retention` exists so the answer lives with the object's identity rather
    /// than being rediscovered per feature. The day something sweeps, this test
    /// is what says the sweep has to be written against this enum; until then
    /// it stops the declaration from reading as a promise the code does not
    /// keep.
    #[test]
    fn retention_is_declared_and_not_enforced() {
        const SRC: &str = include_str!("mod.rs");
        // The needles are assembled rather than written, because a literal
        // would appear in this file and the test would match itself. Not
        // hypothetical: the first version did exactly that and failed.
        for needle in [concat!("fn ", "sweep"), concat!("fn ", "expire")] {
            assert!(
                !SRC.contains(needle),
                "{needle:?} now exists in this module, so retention has become enforceable; replace this test with one proving the sweep deletes the right things"
            );
        }
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

    /// The selection rule, without touching process env. Blank takes the
    /// default the startup wiring hands in (`local` in both hosting profiles,
    /// so an unconfigured deployment resolves exactly where it always did),
    /// because a forwarded-but-unset variable arrives as `""`; a typo is an
    /// error because the operator asked for something and did not get it.
    #[test]
    fn blank_takes_the_supplied_default_and_a_typo_is_an_error() {
        for blank in ["", "  "] {
            assert_eq!(
                StorageProviderKind::resolve(provider::LOCAL, blank).unwrap(),
                (StorageProviderKind::Local, EnablementSource::Profile),
                "{blank:?}"
            );
        }
        assert_eq!(
            StorageProviderKind::resolve(provider::LOCAL, " s3 ").unwrap(),
            (StorageProviderKind::S3, EnablementSource::Explicit)
        );
        assert_eq!(
            StorageProviderKind::parse("local").unwrap(),
            StorageProviderKind::Local
        );
        assert_eq!(
            StorageProviderKind::parse(" s3 ").unwrap(),
            StorageProviderKind::S3
        );
        for typo in ["S3", "minio", "filesystem", "s3,local"] {
            assert!(
                StorageProviderKind::parse(typo).is_err(),
                "{typo:?} must not fall back to local"
            );
            assert!(
                StorageProviderKind::resolve(provider::LOCAL, typo).is_err(),
                "{typo:?} must not fall back to the profile default either"
            );
        }
        // Blank is not a provider name; only `resolve` may settle it.
        assert!(StorageProviderKind::parse("").is_err());
    }

    /// `STORAGE_BACKEND` has exactly one reader, like `ATTACHMENT_DIR`: a
    /// second is how two parts of one process come to disagree about where
    /// bytes are.
    #[test]
    fn there_is_one_reader_of_the_provider_variable() {
        const SRC: &str = include_str!("mod.rs");
        assert_eq!(SRC.matches("var(\"STORAGE_BACKEND\")").count(), 1);
    }
}
