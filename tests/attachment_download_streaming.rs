//! PMS-783 F6: the ticket-note attachment download streams the blob instead of
//! buffering it.
//!
//! This lives in its own test binary on purpose. The probe is a
//! `#[global_allocator]` recording the largest single allocation the PROCESS
//! has made, and `cargo test` runs four cases per binary concurrently
//! (`--test-threads=4` in `just test-integration` and integration.yml), so any
//! sibling case here would have its allocations charged to the download. That
//! is exactly how PMS-822 failed CI: argon2's 19 MiB hash buffer, allocated by
//! another case's `seed_admin` / `login`, tripped a probe watching a handler
//! that streams correctly. Keep this binary at one test; the test asserts it.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use sqlx::PgPool;
use uuid::Uuid;

/// The largest single allocation this process has made since the counter was
/// last reset.
///
/// Peak RSS cannot answer "did the server buffer the whole blob?": it is a
/// monotonic high-water mark for a process that also runs the client, so 25 MiB
/// of slack hides the very allocation being looked for. The largest single
/// allocation does answer it, because the old code path (`tokio::fs::read`)
/// preallocates one `Vec` the size of the file, and a streamed body never asks
/// for more than a chunk.
static MAX_ALLOC: AtomicUsize = AtomicUsize::new(0);

struct MaxAllocTracker;

unsafe impl GlobalAlloc for MaxAllocTracker {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        MAX_ALLOC.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        MAX_ALLOC.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        MAX_ALLOC.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: MaxAllocTracker = MaxAllocTracker;

/// A storage root private to this run, plus the same tight 1 KiB cap
/// `tests/ticket_note_attachments.rs` uses. The two used to name one directory
/// under `/tmp` on the argument that unique uuid filenames made sharing safe;
/// they no longer share one, because the collision that mattered was never
/// between two blobs but between two OS users over the directory itself.
fn install_test_attachment_env() -> PathBuf {
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1024");
    common::storage_root().to_path_buf()
}

/// PMS-783 F6: ten concurrent 25 MiB downloads used to mean 250 MiB of
/// transient heap. Seeds the blob and the row directly rather than uploading,
/// because the cap is 1 KiB and the upload path is not what is under test.
#[sqlx::test]
async fn a_large_download_never_allocates_the_whole_blob(pool: PgPool) {
    const BLOB_BYTES: usize = 25 * 1024 * 1024;
    /// Comfortably above any HTTP read buffer on either side of the socket and
    /// far below the blob, so the assertion only fires on a buffered body.
    const ALLOC_CEILING: usize = 4 * 1024 * 1024;

    // PMS-822: the probe is process-global, so a second case in this binary
    // would run concurrently and be measured as this one.
    let test_attributes = include_str!("attachment_download_streaming.rs")
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with("#[") && line.ends_with("test]")
        })
        .count();
    assert_eq!(
        test_attributes, 1,
        "this binary must hold exactly one test: the allocation probe below \
         measures the whole process, so a concurrent sibling case is charged \
         to the download under test (PMS-822)"
    );

    let dir = install_test_attachment_env();
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;

    let attachment_id = Uuid::new_v4();
    // PMS-910: the blob goes where the store looks for it, which is
    // `{root}/{tenant_id}/{attachment_id}`. The download no longer opens
    // whatever path the row happens to carry - it derives one from the tenant
    // and the id - so a fixture that invents a path is testing a contract that
    // no longer exists. `storage_path` is still written below because the
    // column is NOT NULL.
    let tenant_dir = dir.join(common::DEFAULT_TENANT_ID.to_string());
    let blob_path = tenant_dir.join(attachment_id.to_string());
    tokio::fs::create_dir_all(&tenant_dir)
        .await
        .expect("blob dir");
    tokio::fs::write(&blob_path, vec![7u8; BLOB_BYTES])
        .await
        .expect("write blob");
    sqlx::query(
        r#"INSERT INTO ticket_attachments
           (id, tenant_id, ticket_id, note_id, file_name, file_size, mime_type,
            storage_path, uploaded_by_id)
           VALUES ($1, $2, $3, $4, 'big.bin', $5, 'application/octet-stream', $6, $7)"#,
    )
    .bind(attachment_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(note_id)
    .bind(BLOB_BYTES as i32)
    .bind(blob_path.to_string_lossy().to_string())
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed attachment row");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    // Reset AFTER the fixture: writing the blob allocates it once, on purpose,
    // and argon2 asks for 19 MiB per password hash in `seed_admin` / `login`.
    MAX_ALLOC.store(0, Ordering::Relaxed);
    let mut resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert!(resp.status().is_success());
    assert_eq!(resp.headers()["content-length"], BLOB_BYTES.to_string());
    // Consume chunk by chunk and drop each: a `bytes()` call would buffer the
    // whole body client-side and measure the test, not the server.
    let mut received = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        received += chunk.len();
    }
    let peak = MAX_ALLOC.load(Ordering::Relaxed);
    assert_eq!(received, BLOB_BYTES, "the whole blob still arrives");
    assert!(
        peak < ALLOC_CEILING,
        "serving a {BLOB_BYTES}-byte attachment allocated {peak} bytes in one \
         block; the body must stream, not buffer"
    );
}
