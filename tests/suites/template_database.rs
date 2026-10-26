//! PMS-1254: build the template every other test clones, as a step of its own.
//!
//! The suite builds it by itself when it finds none, under an advisory lock,
//! so this is not what makes a run correct. It is what makes a run legible.
//! Run first, by `integration.yml` and `just test-integration`, the 243
//! migrations are applied by a step of the job rather than inside whichever
//! case happened to arrive first with every other case waiting on the lock,
//! and the line naming the template is printed where a reader can see it
//! rather than into one case's captured output. That line comes from the
//! process that did the build and from no other, so it is the evidence that
//! the migrations ran once for the whole run.
//!
//! In the root package rather than in `mokosh-test` so CI runs it out of the
//! nextest archive it already built. Building `mokosh-test` on its own
//! resolves a narrower feature set for `sqlx` and `tokio` than the suite does,
//! which means compiling both of them a second time for one `println!`.
//!
//! It skips loudly with no `DATABASE_URL`, the shape `tests/s3_storage.rs`
//! uses, because nothing else in this file can run without a cluster.

#[test]
fn builds_the_migrated_template() {
    let Ok(_url) = std::env::var("DATABASE_URL") else {
        println!("mokosh-test: DATABASE_URL is unset, so no template was built");
        return;
    };
    let template = mokosh_test::runtime().block_on(mokosh_test::ensure_template_built());
    println!("mokosh-test: the suite will clone {template}");
}
