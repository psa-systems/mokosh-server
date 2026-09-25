//! PMS-1254: `#[mokosh_test]`, the database-backed test attribute.
//!
//! `#[sqlx::test]` gives every test its own database and applies every
//! migration into it, one file at a time. With 243 migrations and ~2,500
//! tests that is the better part of an hour of Postgres work per run,
//! recreating an identical schema. `CREATE DATABASE ... TEMPLATE` copies a
//! migrated database in about a tenth of the time, and nextest runs each test
//! in its own process, so the thing being reused has to live in Postgres
//! rather than in memory.
//!
//! This attribute is deliberately a near-copy of what `#[sqlx::test]` expands
//! to, because the test bodies are unchanged and any difference in runtime,
//! pool lifetime or cleanup would be a difference in what ~2,500 tests mean:
//!
//! * a current-thread Tokio runtime with all drivers enabled, which is what
//!   `sqlx::rt::test_block_on` builds;
//! * the pool handed to the body as its argument, then closed with a ten
//!   second timeout, warning by test name if the body held onto it;
//! * the database dropped when the body returns, and KEPT when it panics,
//!   with its name printed so the failure can be inspected.
//!
//! One step has no counterpart there, because `#[sqlx::test]` did not need it:
//! the runtime is dropped BEFORE the database is, since an axum server the
//! body spawned holds its connection until its task is dropped and Postgres
//! refuses to drop a database anything is still connected to.
//!
//! The support code it calls lives in the `mokosh-test` crate, which also
//! re-exports this attribute, so a test binary depends on that one crate and
//! needs nothing else in scope.

use proc_macro::TokenStream;
use quote::quote;

/// Run this test against a fresh database cloned from the migrated template.
///
/// Takes no arguments. `#[sqlx::test(migrations = "./migrations")]` and the
/// bare form both become this: the template is built from `./migrations`
/// either way, so the two were never different tests.
#[proc_macro_attribute]
pub fn mokosh_test(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[mokosh_test] takes no arguments; the template is built from ./migrations",
        )
        .to_compile_error()
        .into();
    }

    let input = syn::parse_macro_input!(input as syn::ItemFn);
    let attrs = &input.attrs;
    let vis = &input.vis;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;
    let body = &input.block;

    if input.sig.asyncness.is_none() {
        return syn::Error::new_spanned(
            &input.sig,
            "#[mokosh_test] expects an async fn, the shape #[sqlx::test] takes",
        )
        .to_compile_error()
        .into();
    }
    if inputs.len() != 1 {
        return syn::Error::new_spanned(
            inputs,
            "#[mokosh_test] expects exactly one argument, the pool: `async fn name(pool: PgPool)`",
        )
        .to_compile_error()
        .into();
    }

    quote! {
        #(#attrs)*
        #[::core::prelude::v1::test]
        #vis fn #name() #output {
            // The body, untouched, as an inner async fn taking the pool. The
            // same shape `#[sqlx::test]` uses, so a body that names its
            // argument's type still compiles.
            async fn #name(#inputs) #output {
                #body
            }

            let __test_path = ::std::concat!(module_path!(), "::", ::std::stringify!(#name));
            let __rt = ::mokosh_test::runtime();
            let __db = __rt.block_on(::mokosh_test::acquire(__test_path));
            let __pool = __db.pool();

            // The body reports a failed assertion by panicking, and the panic
            // would otherwise unwind past the cleanup below. Caught around the
            // synchronous `block_on` rather than around the future, so this
            // needs nothing but `std`.
            let __outcome = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                __rt.block_on(#name(__pool.clone()))
            }));

            let __ok = __outcome.is_ok();
            __rt.block_on(::mokosh_test::close_pool(&__pool, __test_path));

            // The test's runtime goes before the database is tidied up, and
            // the order matters: a body that boots the API spawns an axum
            // server, that task holds its connection until it is dropped, and
            // Postgres refuses to drop a database anything is still connected
            // to. Closing the pool is not enough on its own.
            ::std::mem::drop(__pool);
            ::std::mem::drop(__rt);
            ::mokosh_test::finish(__db, __ok);

            match __outcome {
                Ok(__value) => __value,
                Err(__panic) => ::std::panic::resume_unwind(__panic),
            }
        }
    }
    .into()
}
