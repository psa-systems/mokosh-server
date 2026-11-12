//! PMS-1310: the integrations framework, through the API.
//!
//! The unit tests in `modules::integrations::registry` and `::service` cover the
//! registry's shape and the subset rule as pure functions. What needs a database
//! and a booted app is everything those cannot show: that the row is confined to
//! its tenant, that a credential reaches the secrets provider and never the row,
//! and that the catalog a client renders agrees with what the server will
//! accept.
//!
//! PMS-1571 took the four per-provider routes out, so three cases went with
//! them. `a_provider_the_registry_does_not_know_is_a_404` pinned
//! `parse_provider`'s message listing the known providers, and there is no
//! handler left to parse a provider at all.
//! `delegating_a_capability_to_a_planned_provider_is_refused` and
//! `a_provider_managed_elsewhere_cannot_be_connected_here` each drove one path
//! for one provider; `no_provider_can_be_connected_here_and_the_catalog_says_
//! where_each_one_is` now drives all four paths for every provider in the
//! catalog and asserts the same two things they did, that nothing is written
//! and no credential is stored.
//!
//! What those cases also pinned was the refusal MESSAGE naming the owning
//! surface. That message is gone with the route, and it was never read: the SPA
//! renders its controls off `configurable_here`, so it never called these
//! paths. The surface an operator needs is in the catalog, as `setup`, which
//! the page does render, and that is where the "no two providers sent to the
//! same page" rule is asserted now.

use crate::common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Xero's connection is managed by this subsystem (`ConnectionHome::Integrations`),
/// so it is the provider the write paths are exercised against.
///
/// MAPPS-1121: those paths now REFUSE it, because this build has no Xero client
/// and nothing reads what it would be delegated. That is not a gap in this
/// suite, it is the subsystem's current truth: after MAPPS-1098 moved the
/// payment providers to Settings > Payment Gateways, every provider still on
/// this surface is either planned (QuickBooks, Xero) or managed elsewhere
/// (Google, Microsoft 365), so nothing here can be connected at all. The
/// success-path cases this file used to run against Xero return when
/// MAPPS-1099 Phase A ships `billing/provider/xero.rs` and the registry entry
/// flips to `Built`; they are in this file's history to restore from.
const MANAGED_HERE: &str = "xero";
/// Google's connection still lives in `contact_sync_connections` until PMS-1315
/// moves it, so it is the provider every refusal is exercised through. It was
/// Stripe until PMS-1312 brought the payment providers over, and the refusal has
/// to keep being exercised against whichever provider is still outside: the
/// message is what an operator gets back, and there is nothing else that tells
/// them where to go instead.
const MANAGED_ELSEWHERE: &str = "google";
/// Microsoft 365 joined it in MAPPS-1121: its Graph client shipped (MAPPS-1101)
/// and its connection is the Entra consent round trip that writes
/// `contact_sync_connections`, so this surface is the wrong one for it too.
const ALSO_ELSEWHERE: &str = "microsoft";

async fn list(app: &common::TestApp, token: &str) -> Vec<Value> {
    let response = app
        .client
        .get(app.url("/api/v1/integrations"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list integrations");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("list json")
}

fn entry<'a>(entries: &'a [Value], provider: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| entry["provider"] == provider)
        .unwrap_or_else(|| panic!("{provider} is not in the catalog"))
}

/// A path this surface does not serve, whatever method asked for it.
///
/// PMS-1571: two statuses, because the app-level fallback in
/// `create_api_router` is `get(not_a_frontend)` - a GET-only method router. A
/// path no route matches therefore answers 404 to a GET (that handler's own
/// HTML page, not the JSON envelope) and 405 to anything else, since the
/// fallback matched the path and refused the method. Both mean "no route
/// here", and asserting the pair rather than one of them is what keeps this
/// about the integrations surface instead of pinning the fallback's shape.
fn assert_not_served(status: StatusCode, what: &str) {
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
        "{what} answered {status}, so something still serves it"
    );
}

async fn connect(
    app: &common::TestApp,
    token: &str,
    provider: &str,
    body: Value,
) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/integrations/{provider}/connect")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("connect")
}

/// The second tenant in the isolation check, named once because its slug is
/// both the tenant label and the login's `tenant_slug`.
const OTHER_SLUG: &str = "other-msp";

/// Log in against a named tenant. `common::login` hardcodes `default`, which is
/// right for the seeded admin every other case uses and wrong for a second
/// tenant.
async fn login_to(app: &common::TestApp, email: &str, password: &str, slug: &str) -> String {
    let response = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": password, "tenant_slug": slug }))
        .send()
        .await
        .expect("login");
    assert_eq!(response.status(), StatusCode::OK, "login as {email}");
    let body: Value = response.json().await.expect("login json");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

async fn row_count(pool: &PgPool, provider: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM integrations WHERE provider = $1")
        .bind(provider)
        .fetch_one(pool)
        .await
        .expect("count integrations")
}

/// MAPPS-1129: `configurable_here` agrees with what the write route actually
/// does, for every provider in the catalog.
///
/// PMS-1571: what it does now is not exist. The field has to stay false while
/// that is true, and the day a provider takes `CredentialHome::Integration`
/// both have to move together - the route comes back and the field goes true
/// for that provider. This is that pairing at the HTTP level;
/// `registry::tests::an_integration_home_provider_needs_the_per_provider_routes_back`
/// is the same pairing read off the source, which is what fails first and says
/// what to do.
///
/// The client renders its one mutating control set - the capability
/// checkboxes, Connect/Disconnect, the poll interval - exactly where it
/// believes a change is accepted, and before this field it believed that
/// wherever `managed_elsewhere` was absent. Stripe's connection home IS this
/// subsystem since PMS-1312, so it carries no `managed_elsewhere`, and
/// MAPPS-1122 put it back in this list; the page offered an admin checkboxes
/// whose every tick came back 404.
///
/// Asserted against the route's own answer rather than against a list of
/// provider names, because a second list is how the first one drifts. The
/// question "will PUT take this?" has one true answer and this is it.
#[mokosh_test]
async fn the_catalog_says_which_providers_the_write_route_will_take(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = list(&app, &token).await;
    assert!(!entries.is_empty(), "the catalog is never empty");
    let mut refused = 0;
    for row in &entries {
        let provider = row["provider"].as_str().expect("provider");
        let configurable = row["configurable_here"]
            .as_bool()
            .unwrap_or_else(|| panic!("{provider} does not say whether it is configurable: {row}"));

        let put = app
            .client
            .put(app.url(&format!("/api/v1/integrations/{provider}")))
            .bearer_auth(&token)
            .json(&json!({ "capabilities": [] }))
            .send()
            .await
            .expect("put");
        // Served at all, by the same pair `assert_not_served` explains: a
        // mounted PUT answers with its handler's status, an absent one with
        // the fallback's 404 or 405.
        let takes_it =
            put.status() != StatusCode::NOT_FOUND && put.status() != StatusCode::METHOD_NOT_ALLOWED;
        assert_eq!(
            configurable,
            takes_it,
            "{provider} says configurable_here={configurable} and PUT answered {}; a client \
             renders its controls off this field, so the two disagreeing is a control that \
             404s (MAPPS-1129)",
            put.status()
        );
        if !configurable {
            refused += 1;
        }
    }
    assert_eq!(
        refused,
        entries.len(),
        "PMS-1571: every provider is configured on its own surface, so none of them is \
         configurable here and the per-provider routes are gone. A provider that WAS \
         configurable needs those routes back in the same change, which is why this counts \
         rather than sampling"
    );
}

/// The page's job is to show what COULD be connected, so every provider in the
/// registry is listed on a tenant that has installed nothing, and each carries
/// the supported set the server will hold it to.
#[mokosh_test]
async fn the_catalog_lists_every_provider_before_anything_is_connected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = list(&app, &token).await;
    let providers: Vec<&str> = entries
        .iter()
        .map(|entry| entry["provider"].as_str().expect("provider"))
        .collect();
    assert_eq!(
        providers,
        vec![
            "stripe",
            "paypal",
            "quickbooks",
            "xero",
            "google",
            "microsoft",
            "icloud"
        ],
        "MAPPS-1122: the panel lists the whole registry. MAPPS-1098 filtered the payment \
         providers out of this list as well as out of the write routes, which left the page \
         unable to answer what an organization is connected to; the write routes still \
         refuse them, asserted below"
    );

    // MAPPS-1122: every listed provider says where it is set up, or says
    // nothing when there is nowhere to send an operator yet. Asserted as a
    // table, because the failure worth catching is one provider pointing at
    // another's page: `CredentialHome::ContactSync` names one surface for
    // three providers, which is why the kind is served per provider.
    for (provider, kind) in [
        ("stripe", Some("payment_gateway")),
        ("paypal", Some("payment_gateway")),
        ("google", Some("contact_sync_google")),
        ("icloud", Some("contact_sync_icloud")),
        ("microsoft", Some("contact_sync_microsoft")),
        // MAPPS-1153: both issuers have their own page now, which is where
        // the consent round trip starts and where the mappings live.
        ("quickbooks", Some("invoice_issuer_quickbooks")),
        ("xero", Some("invoice_issuer_xero")),
    ] {
        let row = entry(&entries, provider);
        match kind {
            Some(expected) => assert_eq!(
                row["setup"]["kind"].as_str(),
                Some(expected),
                "{provider} points at the wrong setup surface: {row}"
            ),
            None => assert!(
                row.get("setup").is_none(),
                "{provider} has no setup surface until its client exists: {row}"
            ),
        }
    }

    let xero = entry(&entries, MANAGED_HERE);
    assert_eq!(xero["status"], "not_connected");
    // MAPPS-1121: the fact the page needs and could not derive. Xero is listed
    // so its capabilities can be named; Google's client exists, so the two
    // differ here even though neither can be connected on this surface.
    assert_eq!(
        xero["available"], true,
        "MAPPS-1153: the client, the consent flow, the mapping surface and the settings page \
         all exist now, which is what `available` has always meant"
    );
    assert_eq!(
        entry(&entries, MANAGED_ELSEWHERE)["available"],
        true,
        "Google's contact sync is built; it is simply configured elsewhere"
    );
    assert_eq!(
        entry(&entries, ALSO_ELSEWHERE)["available"],
        true,
        "MAPPS-1101 shipped the Microsoft Graph client"
    );
    assert_eq!(
        xero["enabled_capabilities"]
            .as_array()
            .expect("array")
            .len(),
        0,
        "nothing is delegated yet"
    );
    let supported: Vec<&str> = xero["supported_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["key"].as_str().expect("key"))
        .collect();
    assert_eq!(supported, vec!["invoicing", "bills_and_expenses"]);
    assert!(
        xero["supported_capabilities"][0]["description"]
            .as_str()
            .expect("description")
            .contains("system of record"),
        "a capability says what handing it over MEANS: {}",
        xero["supported_capabilities"][0]
    );
    assert!(
        xero.get("polling").is_none_or(|p| p.is_null()),
        "PMS-1583: nothing paces Xero's poll off integrations.poll_interval_minutes, so it \
         declares no polling cadence: {xero}"
    );

    // Google is listed, but the page is told where it is actually configured
    // rather than being offered a Connect button that would 409.
    let elsewhere = entry(&entries, MANAGED_ELSEWHERE);
    assert_eq!(
        elsewhere["managed_elsewhere"]["table"],
        "contact_sync_connections"
    );
    assert_eq!(
        elsewhere["managed_elsewhere"]["configured_at"], "Settings > Contact sync",
        "the page is told where to go instead"
    );
    // PMS-1315: and no issue pointer. The field named the ticket that would
    // bring this connection under the integrations surface, and the answer
    // turned out to be that it stays where the flow that creates it lives.
    assert!(
        elsewhere["managed_elsewhere"].get("issue").is_none(),
        "{}",
        elsewhere["managed_elsewhere"]
    );
    assert!(
        xero.get("managed_elsewhere").is_none(),
        "a provider managed here says nothing about being managed elsewhere: {xero}"
    );
}

/// Nothing on this surface can be connected, and the catalog says where each
/// provider IS set up.
///
/// MAPPS-1121 asserted the two refusal reasons were different from each other,
/// because an operator acts on them differently: a planned provider waits on
/// us, a provider managed elsewhere waits on the operator to open another
/// page. PMS-1571 removed the routes that carried those reasons, so the half
/// that matters to an operator is read where it is actually rendered - the
/// catalog's `setup` - and the half that matters to this subsystem is that
/// the paths are gone and a request to one writes nothing.
///
/// Driven off the catalog rather than a list of provider names, because a
/// second list is how the first one drifts: every provider the server lists is
/// probed, so a provider added without a route is caught here whatever it is
/// called.
#[mokosh_test]
async fn no_provider_can_be_connected_here_and_the_catalog_says_where_each_one_is(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = list(&app, &token).await;
    assert!(!entries.is_empty(), "the catalog is never empty");

    for row in &entries {
        let provider = row["provider"].as_str().expect("provider");
        let base = format!("/api/v1/integrations/{provider}");

        // All four, because they were four separate handlers and a partial
        // removal is the mistake worth catching: three gone and one left is a
        // surface that answers for a provider nothing can finish connecting.
        let get = app
            .client
            .get(app.url(&base))
            .bearer_auth(&token)
            .send()
            .await
            .expect("get");
        assert_not_served(get.status(), &format!("GET {base}"));

        let put = app
            .client
            .put(app.url(&base))
            .bearer_auth(&token)
            .json(&json!({ "capabilities": ["invoicing"] }))
            .send()
            .await
            .expect("put");
        assert_not_served(put.status(), &format!("PUT {base}"));

        let connected = connect(&app, &token, provider, json!({ "credential": "anything" })).await;
        assert_not_served(connected.status(), &format!("POST {base}/connect"));

        let disconnected = app
            .client
            .post(app.url(&format!("{base}/disconnect")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("disconnect");
        assert_not_served(disconnected.status(), &format!("POST {base}/disconnect"));

        assert_eq!(
            row_count(&pool, provider).await,
            0,
            "a request to a route that does not exist still wrote a row for {provider}"
        );
    }

    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM secrets WHERE name LIKE 'INTEGRATION__%'"
        )
        .fetch_one(&pool)
        .await
        .expect("count integration secrets"),
        0,
        "a credential was stored for a provider this surface cannot connect"
    );

    // The operator-facing half: each provider names a page, and no provider
    // is sent to another one's. This was asserted against the refusal
    // messages while they existed; the catalog is where the SPA reads it, so
    // it is where the rule belongs.
    //
    // Sharing a page is allowed, and the first version of this assertion was
    // wrong to forbid it: Stripe and PayPal are both set up on Settings >
    // Payment Gateways, because the surface is a property of the credential
    // home and two payment providers do not get to disagree about where the
    // payments page is. What must not happen is a provider sent to a page
    // that belongs to a DIFFERENT home - a Xero admin pointed at contact
    // sync - so the rule is that two providers naming one page must name one
    // home too. `credential_elsewhere` is the home as the response states it,
    // absent for the invoice issuers, whose credential is a consent round
    // trip and is entered nowhere.
    let mut by_surface: std::collections::HashMap<&str, Vec<(&str, Option<&str>)>> =
        std::collections::HashMap::new();
    for row in &entries {
        let provider = row["provider"].as_str().expect("provider");
        let label = row["setup"]["label"].as_str().unwrap_or_else(|| {
            panic!("{provider} is configured nowhere this surface can name: {row}")
        });
        assert!(
            !label.contains("MAPPS-") && !label.contains("PMS-"),
            "an MSP admin has no use for our issue keys: {label}"
        );
        let home = row["credential_elsewhere"].as_str();
        by_surface.entry(label).or_default().push((provider, home));
    }
    for (label, sharers) in &by_surface {
        let homes: Vec<Option<&str>> = sharers.iter().map(|(_, home)| *home).collect();
        assert!(
            homes.windows(2).all(|pair| pair[0] == pair[1]),
            "{label} is named by providers whose credentials live in different places, so at \
             least one of them is pointed at another provider's page: {sharers:?}"
        );
    }
}

/// A row left by an earlier build can still be disconnected, and disconnecting
/// deletes its credential.
///
/// This is the state a tenant who connected QuickBooks before MAPPS-1121 is in:
/// a `connected` row and a stored credential for a provider that was never able
/// to use either. `disconnect` is deliberately not gated on the build state, so
/// the button that clears both still works, and this is what says so.
#[mokosh_test]
async fn a_row_left_by_an_earlier_build_can_still_be_disconnected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, config, enabled_capabilities, \
         connected_at) VALUES ($1, $2, 'connected', '{}'::jsonb, ARRAY['invoicing'], NOW())",
    )
    .bind(tenant_id)
    .bind(MANAGED_HERE)
    .execute(&pool)
    .await
    .expect("seed the row an earlier build would have written");
    sqlx::query("INSERT INTO secrets (tenant_id, name, value_encrypted) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        // The name `SecretKey::integration` renders: the prefix, the tenant's
        // uuid in simple form (no dashes), then the provider upper-cased.
        // Built the same way here rather than guessed, because a near-miss
        // would leave this case asserting that disconnect deleted a row that
        // was never the one it looks for.
        .bind(format!("INTEGRATION__{}__XERO", tenant_id.simple()))
        .bind(vec![1u8, 2, 3])
        .execute(&pool)
        .await
        .expect("seed the credential it would have stored");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // PMS-1571: this route is gone, so the 404 is its absence rather than a
    // refusal naming another page. That distinction is the reason the second
    // half of this case exists and always did.
    let response = app
        .client
        .post(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}/disconnect")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("disconnect");
    assert_not_served(
        response.status(),
        "POST /integrations/{provider}/disconnect",
    );

    // And the way out exists on the page that owns it, which is the half of
    // this case that matters: the invariant is that a tenant is never
    // stranded in a state an earlier build wrote, not that one particular
    // route is the exit.
    let response = app
        .client
        .post(app.url(&format!(
            "/api/v1/integrations/invoice-issuer/{MANAGED_HERE}/disconnect"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("disconnect through the owning surface");
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "the way out of the old state cannot be gated on the state being possible"
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM integrations WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(tenant_id)
    .bind(MANAGED_HERE)
    .fetch_one(&pool)
    .await
    .expect("read the row back");
    assert_eq!(status, "disconnected");
    assert_eq!(
        row_count(&pool, MANAGED_HERE).await,
        1,
        "the row is kept, so what was delegated survives for a reconnect"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM secrets WHERE name LIKE 'INTEGRATION__%'"
        )
        .fetch_one(&pool)
        .await
        .expect("count integration secrets"),
        0,
        "and the credential it could never use is gone"
    );
}

// MAPPS-1121 removed four cases here, all of which drove a write path through
// Xero: the credential never reaching the row or the audit trail, narrowing a
// delegation to empty while staying connected, disconnect keeping the row, and
// a capability change on a provider that was never connected. Every one of them
// now gets a 409 before reaching the behaviour it asserted, because this build
// has no Xero client. The rules survive: `resolve_capabilities` and the
// credential-home split are unit-tested in `modules::integrations::service`,
// disconnect's row-and-credential handling is covered above against a row an
// earlier build left, and the rest come back with MAPPS-1099 Phase A, out of
// this file's history.
//
// PMS-1571 removed two more for the same reason one layer up: there is no
// route to drive. `a_provider_managed_elsewhere_cannot_be_connected_here`
// asserted that a credential for Google reached neither the row nor the
// secrets provider, and the case above now asserts that for every provider
// the catalog lists. `a_provider_the_registry_does_not_know_is_a_404` pinned
// `parse_provider`'s message listing the known providers, and there is no
// handler left to parse one; an unknown provider and a known one are the same
// unrouted path now, which is not a statement worth a case.

/// Tenant scoping, through the app rather than through the policy alone: one
/// tenant's row is invisible to the other, in both directions.
///
/// MAPPS-1121: the rows are seeded rather than connected, because no provider
/// on this surface can be connected any more. What is being asserted is the
/// policy, not the write path, so seeding costs the case nothing: `boot_rls`
/// still runs the reads as the unprivileged `mokosh_app` posture, which is the
/// only way this says anything about RLS at all (PMS-285).
#[mokosh_test]
async fn one_tenants_integration_is_invisible_to_another(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_other_tenant, _other_id, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, OTHER_SLUG).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, config, enabled_capabilities, \
         connected_at) VALUES ($1, $2, 'connected', '{}'::jsonb, ARRAY['invoicing'], NOW())",
    )
    .bind(tenant_id)
    .bind(MANAGED_HERE)
    .execute(&pool)
    .await
    .expect("seed one tenant's row");

    let app = common::boot_rls(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let other_token = login_to(&app, &other_email, &other_password, OTHER_SLUG).await;

    // The other tenant sees the catalog entry with no installation on it.
    let theirs = list(&app, &other_token).await;
    let their_xero = entry(&theirs, MANAGED_HERE);
    assert_eq!(
        their_xero["status"], "not_connected",
        "the other tenant sees our installation: {their_xero}"
    );
    assert_eq!(their_xero["enabled_capabilities"], json!([]));

    // And disconnecting ours is not something they can do: there is nothing
    // there for them to disconnect.
    let response = app
        .client
        .post(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}/disconnect")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("disconnect across tenants");
    // PMS-1571: the route is gone, so this says less than it did - the
    // isolation it was asserting is the LIST above, which is where this case
    // earns its keep. Kept as the statement that no path on this surface lets
    // one tenant touch another's row.
    assert_not_served(
        response.status(),
        "POST /integrations/{provider}/disconnect across tenants",
    );

    // Ours is untouched.
    let ours = list(&app, &token).await;
    assert_eq!(entry(&ours, MANAGED_HERE)["status"], "connected");
}

/// Every capability a row reports is renderable and the list is never empty.
///
/// MAPPS-1121: this used to finish by connecting with exactly the set the row
/// advertised, which was the sharp end of it: the row offering something the
/// server would refuse. That half cannot run while no provider is connectable,
/// and it returns with the first built one. What is left still catches the
/// failure that reaches a screen, a capability with no label to draw.
#[mokosh_test]
async fn every_capability_a_row_reports_is_renderable(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = list(&app, &token).await;
    let row = entry(&entries, MANAGED_HERE);
    let supported: Vec<String> = row["supported_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| {
            let label = c["label"].as_str().unwrap_or_default();
            assert!(
                !label.is_empty(),
                "a capability with no label cannot be rendered: {c}",
            );
            c["key"].as_str().expect("key").to_string()
        })
        .collect();
    assert!(
        !supported.is_empty(),
        "the row's capability list cannot be empty: it is what the card draws",
    );
}

/// MAPPS-1122: a provider whose connection lives in contact sync reports the
/// state contact sync is actually in.
///
/// This is the defect the panel existed around rather than solved. `compose`
/// built every row from the `integrations` table, and Google never has one:
/// its connection is a `contact_sync_connections` row. So a tenant whose
/// Google Contacts was connected and syncing read "Not connected" on the page
/// whose entire job is to say what is connected, and an admin had no way to
/// tell that from a tenant that had never set it up.
///
/// The four states are asserted together because what matters is that they
/// DIFFER: one case per state would each pass against a server that answered
/// `connected` for any row at all.
#[mokosh_test]
async fn a_contact_sync_provider_reports_the_state_contact_sync_is_in(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");

    // google: connected and syncing. icloud: the provider asked us to wait,
    // which is not a broken integration (PSA-70 J). microsoft: the grant was
    // revoked, which is the one state with something for a human to do.
    for (provider, is_active, sync_status, disconnected) in [
        ("google", true, "success", false),
        ("icloud", true, "throttled", false),
        ("microsoft", true, "reconnect_required", false),
    ] {
        sqlx::query(
            "INSERT INTO contact_sync_connections \
             (tenant_id, provider, account_email, is_active, sync_status, last_error, disconnected_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(format!("admin@{provider}.example"))
        .bind(is_active)
        .bind(sync_status)
        .bind(Some("the grant was revoked"))
        .bind(disconnected.then(chrono::Utc::now))
        .execute(&pool)
        .await
        .expect("seed a contact-sync connection");
    }

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let entries = list(&app, &token).await;

    assert_eq!(
        entry(&entries, "google")["status"],
        "connected",
        "a syncing connection has to read as connected, which is the whole ticket"
    );
    assert_eq!(
        entry(&entries, "icloud")["status"],
        "connected",
        "throttled is the provider asking us to wait, not a broken integration"
    );
    let microsoft = entry(&entries, "microsoft");
    assert_eq!(
        microsoft["status"], "error",
        "a revoked grant is the one state with something for a human to do"
    );
    assert_eq!(
        microsoft["last_error"], "the grant was revoked",
        "and the reason is shown: {microsoft}"
    );
    assert_eq!(
        entry(&entries, "xero")["status"],
        "not_connected",
        "a provider with no connection anywhere is untouched by this"
    );
    assert!(
        entry(&entries, "google").get("last_error").is_none(),
        "a stale message from a sync that later succeeded would read as a live failure"
    );
}

/// MAPPS-1131: what a contact-sync provider is DELEGATED comes from contact
/// sync too, and it takes both halves.
///
/// MAPPS-1122 moved the status to the owning subsystem and stopped there. These
/// three providers have no `integrations` row at all - `ConnectionHome::Elsewhere`,
/// so two tables cannot disagree about one fact - which left
/// `enabled_capabilities` permanently empty, and a tenant actively syncing
/// Google Contacts was listed as connected with nothing delegated to it.
///
/// The two halves are asserted apart, because each alone is a state a tenant
/// can be in and they mean different things: a live connection with the switch
/// off is an account still linked and nothing being read from it.
#[mokosh_test]
async fn a_contact_sync_provider_reports_what_it_is_actually_delegated(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");

    // google: live and switched on. icloud: live, switched OFF. microsoft:
    // disconnected, switched on.
    for (provider, disconnected) in [("google", false), ("icloud", false), ("microsoft", true)] {
        sqlx::query(
            "INSERT INTO contact_sync_connections \
             (tenant_id, provider, account_email, is_active, sync_status, disconnected_at) \
             VALUES ($1, $2, $3, TRUE, 'success', $4)",
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(format!("admin@{provider}.example"))
        .bind(disconnected.then(chrono::Utc::now))
        .execute(&pool)
        .await
        .expect("seed a contact-sync connection");
    }
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'integrations', 'icloud_contacts_enabled', 'false'::jsonb)",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("switch iCloud off");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let entries = list(&app, &token).await;

    let delegated = |provider: &str| -> Vec<String> {
        entry(&entries, provider)["enabled_capabilities"]
            .as_array()
            .expect("array")
            .iter()
            .map(|c| c.as_str().expect("capability").to_string())
            .collect()
    };

    assert_eq!(
        delegated("google"),
        vec!["contacts".to_string()],
        "a tenant syncing Google Contacts has delegated contacts to it"
    );

    let icloud = entry(&entries, "icloud");
    assert_eq!(
        icloud["status"], "connected",
        "the account is still linked, and saying otherwise would hide a credential that still exists: {icloud}"
    );
    assert!(
        delegated("icloud").is_empty(),
        "the switch is off, so nothing is being read from it: {icloud}"
    );

    assert!(
        delegated("microsoft").is_empty(),
        "a disconnected connection hands nothing over, switch or no switch"
    );

    // The row that is not an integration. `contact_sync_connections` holds a
    // vcard row per tenant since PMS-1290; it has no registry entry, so it is
    // neither listed nor asked for a switch it does not have.
    sqlx::query(
        "INSERT INTO contact_sync_connections (tenant_id, provider, account_email, is_active) \
         VALUES ($1, 'vcard', 'files@msp.example', TRUE)",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed the vcard row");
    let after = list(&app, &token).await;
    assert!(
        after.iter().all(|row| row["provider"] != "vcard"),
        "an uploaded file is not an integration"
    );
    assert_eq!(
        after.len(),
        entries.len(),
        "and it changes nothing else about the catalog"
    );
}

/// PMS-1525: migration 283 clears the capability from the rows that carry it,
/// and leaves `payments` alone.
///
/// The row is seeded the way a deployment actually has it and then given the
/// extra value the closed route used to be able to write. No API can produce
/// this state any more, which is exactly why it needs a migration rather than
/// a release note telling an admin to untick it.
///
/// The migration has already run against this database (every suite database
/// is migrated before a case touches it) and the row is seeded after, so the
/// case runs the migration's own statement to prove the state cannot survive
/// it, and then reads the result back through the API the panel uses.
#[mokosh_test]
async fn a_stripe_row_no_longer_claims_an_invoicing_delegation(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities) \
         VALUES ($1, 'stripe', 'connected', ARRAY['payments', 'invoicing']::text[])",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed a stripe row from before the capability was retired");

    sqlx::query(
        "UPDATE integrations SET enabled_capabilities = array_remove(enabled_capabilities, 'invoicing') \
         WHERE provider = 'stripe' AND 'invoicing' = ANY(enabled_capabilities)",
    )
    .execute(&pool)
    .await
    .expect("run the migration statement");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let entries = list(&app, &token).await;
    let stripe = entry(&entries, "stripe");

    let delegated: Vec<&str> = stripe["enabled_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c.as_str().expect("capability"))
        .collect();
    assert_eq!(
        delegated,
        vec!["payments"],
        "card payments are real and read; invoicing was neither: {stripe}"
    );

    let supported: Vec<&str> = stripe["supported_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["key"].as_str().expect("key"))
        .collect();
    assert_eq!(
        supported,
        vec!["payments"],
        "and the catalog stops offering a capability no issuer can receive: {stripe}"
    );
}

/// A disconnected contact-sync row reads as disconnected, not as never set up.
///
/// Contact sync KEEPS the row when an admin disconnects (PSA-70 J), because the
/// contacts it imported stay and their provenance has to keep naming where they
/// came from. The panel has to tell that apart from a tenant that never
/// connected, which is the same distinction `integrations.status` draws for the
/// providers it owns.
#[mokosh_test]
async fn a_disconnected_contact_sync_row_is_not_a_tenant_that_never_connected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("the seeded admin's tenant");
    sqlx::query(
        "INSERT INTO contact_sync_connections \
         (tenant_id, provider, account_email, is_active, sync_status, disconnected_at) \
         VALUES ($1, 'google', 'admin@example.com', FALSE, 'success', NOW())",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed a disconnected connection");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let entries = list(&app, &token).await;
    assert_eq!(entry(&entries, "google")["status"], "disconnected");
    assert_eq!(
        entry(&entries, "icloud")["status"],
        "not_connected",
        "and the one that was never connected still says so"
    );
}
