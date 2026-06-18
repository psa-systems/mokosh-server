//! Integration tests for the projects + tasks module (PMS-51).
//!
//! Covers the full delivery flow the story calls for: project CRUD with
//! budget-vs-actual, ordered phases, hierarchical tasks with per-tenant
//! statuses, task dependencies with uniqueness + cycle rejection, and
//! approved time rolling up into task and project actual hours/amount.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a company under the default tenant. Returns its id.
async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

/// Tolerant read of a serde JSON value that may carry a `Decimal` as
/// either a number or a string (the wire form depends on rust_decimal's
/// serde feature set).
fn dec(v: &serde_json::Value) -> f64 {
    if let Some(f) = v.as_f64() {
        f
    } else if let Some(s) = v.as_str() {
        s.parse().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

async fn post(
    app: &common::TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send POST")
}

async fn get_json(app: &common::TestApp, token: &str, path: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send GET");
    assert!(
        resp.status().is_success(),
        "GET {path} expected 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("GET JSON")
}

/// Grab the first seeded task status id (migration 023 seeds these).
async fn first_task_status(app: &common::TestApp, token: &str) -> String {
    let body = get_json(app, token, "/api/v1/task-statuses").await;
    body["data"][0]["id"]
        .as_str()
        .expect("a seeded task status exists")
        .to_string()
}

// AC1-4 + AC6: project -> phase -> task -> subtask -> dependency, end to
// end, with budget-vs-actual on a fresh project and dependency guards.
#[sqlx::test]
async fn project_phase_task_dependency_flow(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // --- Project CRUD + budget vs actual (AC1) ---
    let created = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Network Upgrade",
            "company_id": company,
            "status": "active",
            "budget_hours": "100",
            "budget_amount": "10000",
        }),
    )
    .await;
    assert!(created.status().is_success(), "create project should 2xx");
    let project: serde_json::Value = created.json().await.expect("project JSON");
    let project_id = project["id"].as_str().expect("project id").to_string();
    // Owning company name is resolved via the LEFT join (PMS-335), so a
    // consumer can render the client without a second lookup.
    assert_eq!(
        project["company_name"].as_str(),
        Some("Acme Co"),
        "create response carries the owning company name"
    );
    // Fresh project: budget present, actuals zero (no approved time yet).
    assert_eq!(dec(&project["budget_hours"]), 100.0);
    assert_eq!(
        dec(&project["actual_hours"]),
        0.0,
        "no time -> 0 actual hours"
    );
    assert_eq!(dec(&project["actual_amount"]), 0.0);

    // Filter by company + status.
    let listed = get_json(
        &app,
        &token,
        &format!("/api/v1/projects?company_id={company}&status=active"),
    )
    .await;
    let listed_project = listed["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"].as_str() == Some(project_id.as_str()))
        .expect("project appears in the filtered list");
    // The list query resolves company_name too (PMS-335), so the list view
    // can show a Company column.
    assert_eq!(
        listed_project["company_name"].as_str(),
        Some("Acme Co"),
        "list response carries the owning company name"
    );

    // --- Phases, ordered by sort_order (AC2) ---
    // Insert out of order; the list must come back sorted.
    post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/phases"),
        serde_json::json!({ "name": "Rollout", "sort_order": 2 }),
    )
    .await;
    post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/phases"),
        serde_json::json!({ "name": "Design", "sort_order": 1 }),
    )
    .await;
    let phases = get_json(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/phases"),
    )
    .await;
    let phase_names: Vec<&str> = phases["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert_eq!(
        phase_names,
        vec!["Design", "Rollout"],
        "phases come back ordered by sort_order"
    );

    // --- Tasks: a parent + a subtask (AC3) ---
    let status_id = first_task_status(&app, &token).await;
    let parent = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({
            "title": "Replace core switch",
            "status_id": status_id,
            "priority": "high",
            "estimated_hours": "8",
            "due_date": "2026-03-15",
        }),
    )
    .await;
    assert!(parent.status().is_success(), "create task should 2xx");
    let parent: serde_json::Value = parent.json().await.expect("task JSON");
    let parent_id = parent["id"].as_str().expect("task id").to_string();
    assert_eq!(parent["priority"].as_str(), Some("high"));
    assert_eq!(
        dec(&parent["actual_hours"]),
        0.0,
        "no time -> 0 actual hours"
    );

    let sub = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({
            "title": "Cable the new switch",
            "status_id": status_id,
            "parent_task_id": parent_id,
        }),
    )
    .await;
    let sub: serde_json::Value = sub.json().await.expect("subtask JSON");
    assert_eq!(
        sub["parent_task_id"].as_str(),
        Some(parent_id.as_str()),
        "subtask is linked to its parent"
    );
    let sub_id = sub["id"].as_str().expect("subtask id").to_string();

    let task_list = get_json(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
    )
    .await;
    assert_eq!(
        task_list["data"].as_array().unwrap().len(),
        2,
        "both tasks listed under the project"
    );

    // --- Dependencies: uniqueness + cycle rejection (AC4) ---
    // sub depends on parent.
    let dep = post(
        &app,
        &token,
        &format!("/api/v1/tasks/{sub_id}/depends-on/{parent_id}"),
        serde_json::json!({}),
    )
    .await;
    assert!(dep.status().is_success(), "adding a dependency should 2xx");

    // Re-adding the same edge is idempotent (ON CONFLICT DO NOTHING) and
    // must not create a duplicate row (UNIQUE(task_id, depends_on_task_id)).
    let dep_again = post(
        &app,
        &token,
        &format!("/api/v1/tasks/{sub_id}/depends-on/{parent_id}"),
        serde_json::json!({}),
    )
    .await;
    assert!(dep_again.status().is_success(), "re-add is idempotent");
    let dep_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM task_dependencies WHERE task_id = $1 AND depends_on_task_id = $2",
    )
    .bind(Uuid::parse_str(&sub_id).unwrap())
    .bind(Uuid::parse_str(&parent_id).unwrap())
    .fetch_one(&app.pool)
    .await
    .expect("count deps");
    assert_eq!(
        dep_count, 1,
        "uniqueness enforced: exactly one dependency row"
    );

    // The reverse edge (parent depends on sub) would close a cycle -> 409.
    let cycle = post(
        &app,
        &token,
        &format!("/api/v1/tasks/{parent_id}/depends-on/{sub_id}"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        cycle.status(),
        reqwest::StatusCode::CONFLICT,
        "a cycle-closing dependency is rejected with 409"
    );

    // Self-dependency -> 400.
    let selfdep = post(
        &app,
        &token,
        &format!("/api/v1/tasks/{parent_id}/depends-on/{parent_id}"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        selfdep.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a self-dependency is rejected with 400"
    );
}

// PMS-361: the create form exposes the same status/date/manager fields the
// edit form does, so a project can be born "active" (and with a manager and
// dates) in one submission instead of create-then-edit. Prove every such
// field set on POST /projects round-trips into the row and back out on read.
#[sqlx::test]
async fn create_accepts_status_dates_and_manager(pool: PgPool) {
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // No status override -> default stays "planning" (today's behaviour).
    let defaulted = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Defaulted", "company_id": company }),
    )
    .await;
    assert!(defaulted.status().is_success(), "create project should 2xx");
    let defaulted: serde_json::Value = defaulted.json().await.expect("project JSON");
    assert_eq!(
        defaulted["status"].as_str(),
        Some("planning"),
        "no status override keeps the 'planning' default"
    );

    // Full override: status, both dates, actual_end_date, and a manager all
    // supplied on create.
    let created = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Born Active",
            "company_id": company,
            "status": "active",
            "project_manager_id": admin_id,
            "start_date": "2026-01-05",
            "target_end_date": "2026-06-30",
            "actual_end_date": "2026-06-28",
        }),
    )
    .await;
    assert!(created.status().is_success(), "create project should 2xx");
    let created: serde_json::Value = created.json().await.expect("project JSON");
    let project_id = created["id"].as_str().expect("project id").to_string();

    // Round-trips on the create response itself.
    assert_eq!(created["status"].as_str(), Some("active"));
    assert_eq!(
        created["project_manager_id"].as_str(),
        Some(admin_id.to_string().as_str())
    );
    assert_eq!(created["start_date"].as_str(), Some("2026-01-05"));
    assert_eq!(created["target_end_date"].as_str(), Some("2026-06-30"));
    assert_eq!(created["actual_end_date"].as_str(), Some("2026-06-28"));

    // And lands on the detail read (what the project page shows).
    let fetched = get_json(&app, &token, &format!("/api/v1/projects/{project_id}")).await;
    assert_eq!(fetched["status"].as_str(), Some("active"));
    assert_eq!(
        fetched["project_manager_id"].as_str(),
        Some(admin_id.to_string().as_str())
    );
    assert_eq!(fetched["start_date"].as_str(), Some("2026-01-05"));
    assert_eq!(fetched["target_end_date"].as_str(), Some("2026-06-30"));
    assert_eq!(fetched["actual_end_date"].as_str(), Some("2026-06-28"));
}

// AC5: a time entry linked to a task/project rolls into actual hours and
// amount once approved (and not before).
#[sqlx::test]
async fn approved_time_rolls_into_actuals(pool: PgPool) {
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // Project + task.
    let project: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Delivery", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let project_id = project["id"].as_str().unwrap().to_string();

    let status_id = first_task_status(&app, &token).await;
    let task: serde_json::Value = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({ "title": "Build", "status_id": status_id }),
    )
    .await
    .json()
    .await
    .expect("task JSON");
    let task_id = task["id"].as_str().unwrap().to_string();

    // A work type for the entry (migration 023 seeds these).
    let work_types = get_json(&app, &token, "/api/v1/work-types").await;
    let work_type_id = work_types["data"][0]["id"].as_str().unwrap().to_string();

    // Log 2h against the task at $50/h.
    let date = "2026-03-02"; // a Monday
    let entry = post(
        &app,
        &token,
        "/api/v1/time-entries",
        serde_json::json!({
            "user_id": admin_id,
            "date": date,
            "duration_minutes": 120,
            "work_type_id": work_type_id,
            "project_id": project_id,
            "task_id": task_id,
            "company_id": company,
            "is_billable": true,
            "hourly_rate": "50",
        }),
    )
    .await;
    assert!(
        entry.status().is_success(),
        "create time entry should 2xx, got {}",
        entry.status()
    );

    // Pending time must NOT count toward actuals yet.
    let task_before = get_json(&app, &token, &format!("/api/v1/tasks/{task_id}")).await;
    assert_eq!(
        dec(&task_before["actual_hours"]),
        0.0,
        "pending (unapproved) time does not roll into actual hours"
    );

    // Submit the week first (PMS-183: entries start as draft and must be
    // submitted before a manager can approve them).
    let submit = post(
        &app,
        &token,
        &format!("/api/v1/timesheets/{admin_id}/{date}/submit"),
        serde_json::json!({}),
    )
    .await;
    assert!(
        submit.status().is_success(),
        "submit timesheet should 2xx, got {}",
        submit.status()
    );

    // Approve the week.
    let approve = post(
        &app,
        &token,
        &format!("/api/v1/timesheets/{admin_id}/{date}/approve"),
        serde_json::json!({}),
    )
    .await;
    assert!(
        approve.status().is_success(),
        "approve timesheet should 2xx, got {}",
        approve.status()
    );

    // Now the task and project reflect the approved 2h / $100.
    let task_after = get_json(&app, &token, &format!("/api/v1/tasks/{task_id}")).await;
    assert!(
        (dec(&task_after["actual_hours"]) - 2.0).abs() < 0.01,
        "approved time rolls into task actual_hours (expected 2.0, got {})",
        dec(&task_after["actual_hours"])
    );

    let project_after = get_json(&app, &token, &format!("/api/v1/projects/{project_id}")).await;
    assert!(
        (dec(&project_after["actual_hours"]) - 2.0).abs() < 0.01,
        "approved time rolls into project actual_hours"
    );
    assert!(
        (dec(&project_after["actual_amount"]) - 100.0).abs() < 0.01,
        "approved billable time rolls into project actual_amount (expected 100.0, got {})",
        dec(&project_after["actual_amount"])
    );
}

/// PMS-329: a task exposes `logged_hours` (every non-rejected entry) next to
/// `actual_hours` (approved-only). Draft time shows in logged but not actual;
/// approving makes both reflect it; rejecting drops it from both. The approval
/// transitions are driven directly in SQL so the test pins the rollup SELECT,
/// not the timesheet state machine.
#[sqlx::test]
async fn task_logged_hours_counts_non_rejected(pool: PgPool) {
    let probe = pool.clone();
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Logged Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let project: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Delivery", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let project_id = project["id"].as_str().unwrap().to_string();

    let status_id = first_task_status(&app, &token).await;
    let task: serde_json::Value = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({ "title": "Build", "status_id": status_id }),
    )
    .await
    .json()
    .await
    .expect("task JSON");
    let task_id = task["id"].as_str().unwrap().to_string();

    let work_types = get_json(&app, &token, "/api/v1/work-types").await;
    let work_type_id = work_types["data"][0]["id"].as_str().unwrap().to_string();

    // Log 2h against the task. Entries default to 'draft' (non-rejected).
    let entry = post(
        &app,
        &token,
        "/api/v1/time-entries",
        serde_json::json!({
            "user_id": admin_id,
            "date": "2026-03-02",
            "duration_minutes": 120,
            "work_type_id": work_type_id,
            "project_id": project_id,
            "task_id": task_id,
            "company_id": company,
        }),
    )
    .await;
    assert!(
        entry.status().is_success(),
        "create entry: {}",
        entry.status()
    );
    let entry_id = entry.json::<serde_json::Value>().await.expect("entry JSON")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Draft: logged counts it, actual does not.
    let t = get_json(&app, &token, &format!("/api/v1/tasks/{task_id}")).await;
    assert!(
        (dec(&t["logged_hours"]) - 2.0).abs() < 0.01,
        "draft time counts toward logged_hours (got {})",
        dec(&t["logged_hours"])
    );
    assert_eq!(
        dec(&t["actual_hours"]),
        0.0,
        "draft time does not count toward actual_hours"
    );

    // The list read path carries logged_hours too.
    let list = get_json(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
    )
    .await;
    assert!(
        (dec(&list["data"][0]["logged_hours"]) - 2.0).abs() < 0.01,
        "list_tasks exposes logged_hours"
    );

    // Approve -> both reflect it.
    set_entry_approval(&probe, &entry_id, "approved").await;
    let t = get_json(&app, &token, &format!("/api/v1/tasks/{task_id}")).await;
    assert!(
        (dec(&t["logged_hours"]) - 2.0).abs() < 0.01,
        "approved time stays in logged_hours"
    );
    assert!(
        (dec(&t["actual_hours"]) - 2.0).abs() < 0.01,
        "approved time rolls into actual_hours"
    );

    // Reject -> neither reflects it.
    set_entry_approval(&probe, &entry_id, "rejected").await;
    let t = get_json(&app, &token, &format!("/api/v1/tasks/{task_id}")).await;
    assert_eq!(
        dec(&t["logged_hours"]),
        0.0,
        "rejected time drops out of logged_hours"
    );
    assert_eq!(
        dec(&t["actual_hours"]),
        0.0,
        "rejected time drops out of actual_hours"
    );
}

/// Force a time entry's approval_status directly, bypassing the timesheet
/// workflow, so a test can pin the task rollup SELECT across all states.
async fn set_entry_approval(pool: &PgPool, entry_id: &str, status: &str) {
    let id: Uuid = entry_id.parse().expect("entry uuid");
    sqlx::query("UPDATE time_entries SET approval_status = $1 WHERE id = $2")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await
        .expect("set approval status");
}

// AC6 / AC5: projects + tasks routes are wired (never 501) and require auth.
#[sqlx::test]
async fn projects_routes_require_auth_and_never_501(pool: PgPool) {
    let app = common::boot(pool).await;
    let some = Uuid::new_v4();
    let routes = [
        "/api/v1/projects".to_string(),
        format!("/api/v1/projects/{some}"),
        format!("/api/v1/projects/{some}/phases"),
        format!("/api/v1/projects/{some}/tasks"),
        format!("/api/v1/tasks/{some}"),
        "/api/v1/task-statuses".to_string(),
    ];
    for path in routes {
        let resp = app
            .client
            .get(app.url(&path))
            .send()
            .await
            .expect("unauth GET");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} should 401 without a token"
        );
        assert_ne!(
            resp.status(),
            reqwest::StatusCode::NOT_IMPLEMENTED,
            "{path} must never return 501"
        );
    }
}

/// PMS-184: editing a task and a project each write an in-transaction audit
/// row (entity_type + entity_id + the changed columns), which the per-record
/// history endpoint then surfaces. Asserted directly against `audit_log` so
/// this stays independent of the history-read endpoint (delivered separately).
#[sqlx::test]
async fn task_and_project_edits_write_audit_rows(pool: PgPool) {
    let probe = pool.clone();
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "History Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let project: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Rollout", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let project_id = project["id"].as_str().expect("project id").to_string();

    let status_id = first_task_status(&app, &token).await;
    let task: serde_json::Value = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({ "title": "Initial", "status_id": status_id, "priority": "low" }),
    )
    .await
    .json()
    .await
    .expect("task JSON");
    let task_id = task["id"].as_str().expect("task id").to_string();
    let task_uuid = Uuid::parse_str(&task_id).unwrap();
    let project_uuid = Uuid::parse_str(&project_id).unwrap();

    // Edit the task title, then the project name.
    let t_upd = app
        .client
        .put(app.url(&format!("/api/v1/tasks/{task_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Renamed" }))
        .send()
        .await
        .expect("update task");
    assert!(t_upd.status().is_success(), "PUT task should 2xx");

    let p_upd = app
        .client
        .put(app.url(&format!("/api/v1/projects/{project_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Rollout v2" }))
        .send()
        .await
        .expect("update project");
    assert!(p_upd.status().is_success(), "PUT project should 2xx");

    // An entity-scoped audit row (entity_id set) must exist for each edit,
    // with the changed column captured between the old/new snapshots.
    let task_changed: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
             SELECT 1 FROM audit_log
             WHERE entity_type = 'tasks' AND entity_id = $1 AND action = 'update'
               AND old_values->>'title' = 'Initial' AND new_values->>'title' = 'Renamed'
           )"#,
    )
    .bind(task_uuid)
    .fetch_one(&probe)
    .await
    .expect("query task audit");
    assert!(
        task_changed,
        "task edit must write an entity-scoped audit row"
    );

    let project_changed: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
             SELECT 1 FROM audit_log
             WHERE entity_type = 'projects' AND entity_id = $1 AND action = 'update'
               AND old_values->>'name' = 'Rollout' AND new_values->>'name' = 'Rollout v2'
           )"#,
    )
    .bind(project_uuid)
    .fetch_one(&probe)
    .await
    .expect("query project audit");
    assert!(
        project_changed,
        "project edit must write an entity-scoped audit row"
    );
}

/// PMS-318: creating a task writes a `create` audit row in the same tx as the
/// INSERT, so the task's change-history pane surfaces the create event. The
/// row is entity-scoped, has no `before` snapshot, captures the inserted row
/// in `after`, and records the creating user as actor.
#[sqlx::test]
async fn create_task_writes_create_audit_row(pool: PgPool) {
    let probe = pool.clone();
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Create Audit Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let project: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Audit P", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let project_id = project["id"].as_str().expect("project id").to_string();

    let status_id = first_task_status(&app, &token).await;
    let task: serde_json::Value = post(
        &app,
        &token,
        &format!("/api/v1/projects/{project_id}/tasks"),
        serde_json::json!({ "title": "Fresh", "status_id": status_id, "priority": "low" }),
    )
    .await
    .json()
    .await
    .expect("task JSON");
    let task_id = task["id"].as_str().expect("task id").to_string();
    let task_uuid = Uuid::parse_str(&task_id).unwrap();

    let (action, old_values, new_values, user_id): (
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"SELECT action, old_values, new_values, user_id
             FROM audit_log
             WHERE entity_type = 'tasks' AND entity_id = $1 AND action = 'create'"#,
    )
    .bind(task_uuid)
    .fetch_one(&probe)
    .await
    .expect("a create audit row exists for the new task");

    assert_eq!(action, "create");
    assert!(old_values.is_none(), "before snapshot is NULL on a create");
    let after = new_values.expect("after snapshot present");
    assert_eq!(after["id"].as_str(), Some(task_id.as_str()));
    assert_eq!(after["title"].as_str(), Some("Fresh"));
    assert_eq!(user_id, Some(admin_id), "actor is the creating user");
}

/// PMS-318 AC3: the create audit row shares the task INSERT's transaction.
/// Forcing the audit write to fail strictly after the INSERT (here a ctx whose
/// `user_id` violates the `audit_log -> users` FK) rolls the whole transaction
/// back, so neither the task nor an audit row survives.
#[sqlx::test]
async fn create_task_audit_failure_rolls_back_the_task(pool: PgPool) {
    use mokosh_server::modules::audit::AuditCtx;
    use mokosh_server::modules::auth::TenantId;
    use mokosh_server::modules::projects::{CreateTaskRequest, ProjectsService};
    use mokosh_server::Database;

    let probe = pool.clone();
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Rollback Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let project: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Doomed P", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let project_id = Uuid::parse_str(project["id"].as_str().expect("project id")).unwrap();
    let status_id = Uuid::parse_str(&first_task_status(&app, &token).await).unwrap();

    let service = ProjectsService::new(Database::from_pool(app.pool.clone()));
    // `user_id` references a row that does not exist in `users`, so audit_write's
    // INSERT fails the FK *after* the task INSERT has already run on the tx.
    let ctx = AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: Some(Uuid::new_v4()),
        ip: None,
        user_agent: None,
    };
    let req = CreateTaskRequest {
        title: "Doomed".to_string(),
        description: None,
        status_id,
        phase_id: None,
        parent_task_id: None,
        priority: "low".to_string(),
        assigned_to_id: None,
        estimated_hours: None,
        start_date: None,
        due_date: None,
        sort_order: 0,
    };

    let result = service
        .create_task(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            project_id,
            &req,
            &ctx,
        )
        .await;
    assert!(
        result.is_err(),
        "create must fail when the in-tx audit write FK-violates"
    );

    let task_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE project_id = $1 AND title = 'Doomed'")
            .bind(project_id)
            .fetch_one(&probe)
            .await
            .expect("count tasks");
    assert_eq!(
        task_count, 0,
        "the task INSERT must roll back with the failed audit write"
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'tasks' AND action = 'create'",
    )
    .fetch_one(&probe)
    .await
    .expect("count audit rows");
    assert_eq!(audit_count, 0, "no create audit row survives the rollback");
}

/// PMS-399: a cancelled project rejects task and phase creation with 409, the
/// status check runs before any insert, and a missing project is 404. An active
/// project still accepts both children (the guard scopes strictly to the
/// create/attach paths and never blocks an open project).
#[sqlx::test]
async fn cancelled_project_rejects_task_and_phase_creation(pool: PgPool) {
    let probe = pool.clone();
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Cancelled Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let status_id = first_task_status(&app, &token).await;

    // A cancelled project.
    let cancelled: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Dead Project", "company_id": company, "status": "cancelled" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let cancelled_id = cancelled["id"].as_str().expect("project id").to_string();

    // Task creation against it is rejected with 409.
    let task = post(
        &app,
        &token,
        &format!("/api/v1/projects/{cancelled_id}/tasks"),
        serde_json::json!({ "title": "Should not exist", "status_id": status_id }),
    )
    .await;
    assert_eq!(
        task.status(),
        reqwest::StatusCode::CONFLICT,
        "creating a task on a cancelled project must 409"
    );

    // Phase creation against it is rejected with 409.
    let phase = post(
        &app,
        &token,
        &format!("/api/v1/projects/{cancelled_id}/phases"),
        serde_json::json!({ "name": "Should not exist", "sort_order": 1 }),
    )
    .await;
    assert_eq!(
        phase.status(),
        reqwest::StatusCode::CONFLICT,
        "creating a phase on a cancelled project must 409"
    );

    // The status check runs before the insert: neither child row landed.
    let cancelled_uuid = Uuid::parse_str(&cancelled_id).unwrap();
    let task_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE project_id = $1")
            .bind(cancelled_uuid)
            .fetch_one(&probe)
            .await
            .expect("count tasks");
    assert_eq!(task_count, 0, "no task row inserted on a cancelled project");
    let phase_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM project_phases WHERE project_id = $1")
            .bind(cancelled_uuid)
            .fetch_one(&probe)
            .await
            .expect("count phases");
    assert_eq!(
        phase_count, 0,
        "no phase row inserted on a cancelled project"
    );

    // A missing project is a 404, not a 409.
    let missing_id = Uuid::new_v4();
    let missing = post(
        &app,
        &token,
        &format!("/api/v1/projects/{missing_id}/tasks"),
        serde_json::json!({ "title": "Orphan", "status_id": status_id }),
    )
    .await;
    assert_eq!(
        missing.status(),
        reqwest::StatusCode::NOT_FOUND,
        "creating a task on a non-existent project must 404"
    );

    // An active project still accepts both children (guard does not over-block).
    let active: serde_json::Value = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "Live Project", "company_id": company, "status": "active" }),
    )
    .await
    .json()
    .await
    .expect("project JSON");
    let active_id = active["id"].as_str().expect("project id").to_string();
    let ok_task = post(
        &app,
        &token,
        &format!("/api/v1/projects/{active_id}/tasks"),
        serde_json::json!({ "title": "Real work", "status_id": status_id }),
    )
    .await;
    assert!(
        ok_task.status().is_success(),
        "an active project still accepts task creation, got {}",
        ok_task.status()
    );
    let ok_phase = post(
        &app,
        &token,
        &format!("/api/v1/projects/{active_id}/phases"),
        serde_json::json!({ "name": "Design", "sort_order": 1 }),
    )
    .await;
    assert!(
        ok_phase.status().is_success(),
        "an active project still accepts phase creation, got {}",
        ok_phase.status()
    );
}

// ============================================================================
// PMS-322: project_types lookup table + CRUD.
// ============================================================================

/// The migration seeds client/internal as system defaults; the lookup has full
/// CRUD; and a newly created project resolves its project_type_id from the
/// legacy string.
#[sqlx::test]
async fn project_types_seeded_crud_and_backfill(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool, "Acme").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // Seeded system defaults present.
    let list = get_json(&app, &token, "/api/v1/project-types?per_page=100").await;
    let items = list["data"].as_array().expect("project-types data");
    let client = items
        .iter()
        .find(|t| t["name"].as_str() == Some("client"))
        .expect("seeded 'client' type");
    assert_eq!(client["is_system"].as_bool(), Some(true));
    assert_eq!(client["is_default"].as_bool(), Some(true));
    assert!(
        items
            .iter()
            .any(|t| t["name"].as_str() == Some("internal")
                && t["is_system"].as_bool() == Some(true)),
        "seeded 'internal' system type"
    );

    // CREATE a custom type.
    let created = post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "retainer", "sort_order": 5 }),
    )
    .await;
    assert_eq!(created.status(), reqwest::StatusCode::OK);
    let created: serde_json::Value = created.json().await.expect("create JSON");
    let custom_id = created["id"].as_str().expect("id").to_string();
    assert_eq!(created["is_system"].as_bool(), Some(false));

    // UPDATE it.
    let updated = app
        .client
        .put(app.url(&format!("/api/v1/project-types/{custom_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "retainer", "is_active": false, "sort_order": 9 }))
        .send()
        .await
        .expect("send update");
    assert_eq!(updated.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = updated.json().await.expect("update JSON");
    assert_eq!(updated["is_active"].as_bool(), Some(false));
    assert_eq!(
        updated["is_system"].as_bool(),
        Some(false),
        "update must echo the stored is_system flag"
    );

    // A new project created with the legacy string resolves project_type_id.
    let proj = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "P1", "company_id": company_id, "project_type": "client" }),
    )
    .await;
    assert_eq!(proj.status(), reqwest::StatusCode::OK);
    let proj: serde_json::Value = proj.json().await.expect("project JSON");
    assert_eq!(proj["project_type"].as_str(), Some("client"));
    assert_eq!(
        proj["project_type_id"].as_str(),
        client["id"].as_str(),
        "new project must resolve project_type_id from the seeded client row"
    );

    // DELETE the custom type, then re-delete is 404.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/project-types/{custom_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert!(
        del.status().is_success(),
        "delete custom type 2xx, got {}",
        del.status()
    );
    let redel = app
        .client
        .delete(app.url(&format!("/api/v1/project-types/{custom_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-delete");
    assert_eq!(redel.status(), reqwest::StatusCode::NOT_FOUND);
}

/// A system project type cannot be deleted via the API (409). A custom type
/// still referenced by a project is also 409, not 500.
#[sqlx::test]
async fn project_type_delete_protections(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool, "Acme").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // System row (client) is delete-protected.
    let list = get_json(&app, &token, "/api/v1/project-types?per_page=100").await;
    let client_id = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"].as_str() == Some("client"))
        .and_then(|t| t["id"].as_str())
        .expect("client id")
        .to_string();
    let del_system = app
        .client
        .delete(app.url(&format!("/api/v1/project-types/{client_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete system");
    assert_eq!(
        del_system.status(),
        reqwest::StatusCode::CONFLICT,
        "deleting a system project type must 409"
    );

    // Custom type referenced by a project is delete-blocked with 409.
    post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "special" }),
    )
    .await;
    let custom_id = get_json(&app, &token, "/api/v1/project-types?per_page=100").await["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"].as_str() == Some("special"))
        .and_then(|t| t["id"].as_str())
        .expect("special id")
        .to_string();
    post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({ "name": "P-special", "company_id": company_id, "project_type": "special" }),
    )
    .await;
    let del_ref = app
        .client
        .delete(app.url(&format!("/api/v1/project-types/{custom_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete referenced");
    assert_eq!(
        del_ref.status(),
        reqwest::StatusCode::CONFLICT,
        "deleting a referenced project type must 409, not 500"
    );
}

/// Setting a new default clears the prior default (seeded `client`).
#[sqlx::test]
async fn project_type_new_default_clears_prior(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "managed-services", "is_default": true }),
    )
    .await;
    let list = get_json(&app, &token, "/api/v1/project-types?per_page=100").await;
    let defaults: Vec<&serde_json::Value> = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["is_default"].as_bool() == Some(true))
        .collect();
    assert_eq!(defaults.len(), 1, "exactly one default project type");
    assert_eq!(defaults[0]["name"].as_str(), Some("managed-services"));
}

/// PMS-323: the partial unique index `idx_project_types_one_default` makes a
/// second `is_default = true` row in the same tenant impossible at the DB
/// layer, independent of the service guard. The default tenant already has the
/// seeded `client` row as default, so a direct insert of a second default
/// row for that tenant must raise a unique_violation (23505).
#[sqlx::test]
async fn project_type_second_default_violates_db_index(pool: PgPool) {
    let err = sqlx::query(
        "INSERT INTO project_types (tenant_id, name, is_default) VALUES ($1, $2, TRUE)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("second-default")
    .execute(&pool)
    .await
    .expect_err("a second default in one tenant must violate the partial unique index");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23505"),
        "expected a unique_violation (23505) from idx_project_types_one_default, got: {err}"
    );
}

/// A non-admin (technician) is refused on the mutation routes.
#[sqlx::test]
async fn project_type_mutation_requires_admin(pool: PgPool) {
    let (_id, email, pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "pt-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let create = post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "nope" }),
    )
    .await;
    assert_eq!(
        create.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a technician must not create a project type"
    );
}

/// A duplicate name in the same tenant violates the UNIQUE (tenant_id, name)
/// index and surfaces as a 409, not a 500. Covers both colliding with a seeded
/// system row and with a custom row.
#[sqlx::test]
async fn project_type_duplicate_name_conflicts(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // Colliding with a seeded system name ("client").
    let dup_system = post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "client" }),
    )
    .await;
    assert_eq!(
        dup_system.status(),
        reqwest::StatusCode::CONFLICT,
        "reusing a seeded system name must 409"
    );

    // Colliding with a custom row.
    let first = post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "retainer" }),
    )
    .await;
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let dup_custom = post(
        &app,
        &token,
        "/api/v1/project-types",
        serde_json::json!({ "name": "retainer" }),
    )
    .await;
    assert_eq!(
        dup_custom.status(),
        reqwest::StatusCode::CONFLICT,
        "reusing a custom name must 409, not 500"
    );
}

// ============================================================================
// PMS-324: project create/edit input validation.
//
// Reproduces the "Budget Hours request failed" 422 (the client posts budgets
// as JSON numbers, which the server's Decimal field rejected) and pins the
// Name length cap (80) plus the budget rules (non-negative, <= 2 decimal
// places, within the backing DECIMAL column).
// ============================================================================

/// PUT a partial update to a project, returning the raw response.
async fn put_project(
    app: &common::TestApp,
    token: &str,
    project_id: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/projects/{project_id}")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send PUT project")
}

#[sqlx::test]
async fn project_input_validation(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Budget Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // Baseline create (string budgets, as the existing flow and other callers use).
    let created = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Budgeting",
            "company_id": company,
            "status": "active",
            "budget_hours": "100",
            "budget_amount": "10000",
        }),
    )
    .await;
    assert!(created.status().is_success(), "baseline create should 2xx");
    let project: serde_json::Value = created.json().await.expect("project JSON");
    let id = project["id"].as_str().expect("project id").to_string();

    // --- Budget Hours 422 reproduction: budgets posted as JSON numbers ---
    // mokosh-apps `insert_opt_num` serializes both budget fields as JSON
    // numbers, not strings. Both must be accepted (no 422 on the wire form).
    let num_amount = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_amount": 500 }),
    )
    .await;
    assert!(
        num_amount.status().is_success(),
        "numeric budget_amount should 2xx, got {}",
        num_amount.status()
    );
    let num_hours = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_hours": 8.5 }),
    )
    .await;
    assert!(
        num_hours.status().is_success(),
        "numeric budget_hours should 2xx (the reported 422 bug), got {}",
        num_hours.status()
    );

    // Values persisted, parsed from the exact textual form (no float drift).
    let after = get_json(&app, &token, &format!("/api/v1/projects/{id}")).await;
    assert_eq!(dec(&after["budget_hours"]), 8.5);
    assert_eq!(dec(&after["budget_amount"]), 500.0);

    // --- Name length cap = 80 ---
    let too_long = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "name": "x".repeat(81) }),
    )
    .await;
    assert_eq!(
        too_long.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "name longer than 80 must 422"
    );
    let at_limit = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "name": "x".repeat(80) }),
    )
    .await;
    assert!(
        at_limit.status().is_success(),
        "name of exactly 80 should 2xx"
    );

    // --- Budget rules: non-negative, <= 2 decimal places, no opaque 500 ---
    let negative = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_amount": -1 }),
    )
    .await;
    assert_eq!(
        negative.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "negative budget must 422"
    );
    let too_precise = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_hours": 1.234 }),
    )
    .await;
    assert_eq!(
        too_precise.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "budget with more than 2 decimal places must 422, not silent rounding"
    );
    let bobby = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_amount": "Bobby Tables" }),
    )
    .await;
    assert_eq!(
        bobby.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "non-numeric budget must 422, not 500 or silent acceptance"
    );

    // null is accepted (clears / leaves the field), never an error.
    let nulled = put_project(
        &app,
        &token,
        &id,
        serde_json::json!({ "budget_hours": null }),
    )
    .await;
    assert!(nulled.status().is_success(), "null budget should 2xx");
}

// ============================================================================
// PMS-316: oversized-budget rejection + company display-text safety.
//
// The budget fields back onto DECIMAL(12, 2) (amount) and DECIMAL(10, 2)
// (hours). Before the budget range check, an extreme value reached Postgres
// and surfaced as a 500 numeric-overflow (amount) / a raw deserialization 422
// (hours) instead of a controlled, field-level validation error. This pins the
// in-range maxima as accepted and the just-over-the-limit values as a clean
// 422 on the create path. Separately, a company is selected by typed `Uuid`
// (`company_id`), so a raw display string can never reach the query: a
// SQL-injection-shaped value is rejected at extraction and the companies table
// is left intact.
// ============================================================================

#[sqlx::test]
async fn project_oversized_budget_and_safe_company_id(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Oversize Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // --- Largest in-range budgets create cleanly (column maxima) ---
    let at_max = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "At column maxima",
            "company_id": company,
            "budget_amount": "9999999999.99",
            "budget_hours": "99999999.99",
        }),
    )
    .await;
    assert!(
        at_max.status().is_success(),
        "budgets at the DECIMAL column maxima must 2xx, got {}",
        at_max.status()
    );

    // --- Oversized budget_amount: a clean 422, never a 500 overflow ---
    let big_amount = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Oversize amount",
            "company_id": company,
            "budget_amount": 10_000_000_000_i64,
            "budget_hours": "100",
        }),
    )
    .await;
    assert_eq!(
        big_amount.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "budget_amount above the DECIMAL(12, 2) limit must 422, not 500"
    );

    // --- Oversized budget_hours: a clean 422, never a 500 overflow ---
    let big_hours = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Oversize hours",
            "company_id": company,
            "budget_amount": "10000",
            "budget_hours": 100_000_000_i64,
        }),
    )
    .await;
    assert_eq!(
        big_hours.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "budget_hours above the DECIMAL(10, 2) limit must 422, not 500"
    );

    // --- Company selection is by typed id, never by raw display text ---
    // A SQL-injection-shaped company value cannot deserialize into the
    // `Option<Uuid>` field, so it is rejected at request extraction and never
    // reaches the parameterized query.
    let injected = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Injection attempt",
            "company_id": "ZQA'); DROP TABLE companies;--",
        }),
    )
    .await;
    assert_eq!(
        injected.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "a non-UUID company_id must 422 (typed id), never reaching the query"
    );

    // The companies table is intact: a normal create against the real,
    // typed company id still succeeds after the injection attempt.
    let after_injection = post(
        &app,
        &token,
        "/api/v1/projects",
        serde_json::json!({
            "name": "Post-injection create",
            "company_id": company,
        }),
    )
    .await;
    assert!(
        after_injection.status().is_success(),
        "create with a valid company_id must still 2xx after the injection attempt, got {}",
        after_injection.status()
    );
}
