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
    assert!(
        listed["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"].as_str() == Some(project_id.as_str())),
        "project appears in the filtered list"
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
