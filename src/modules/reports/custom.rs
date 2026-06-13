//! Safe custom report builder (PMS-180).
//!
//! PMS-93 rejected an ad-hoc SQL query builder for v1 (injection /
//! performance risk). This is the safe alternative: the user never writes
//! SQL or raw column names. They compose a report from a server-side
//! **catalog** of sources, each exposing a whitelisted set of dimensions
//! (group-by), measures (aggregates), and equality filters. Every
//! identifier in the generated SQL comes from a `&'static str` constant in
//! this file; every user-supplied value is a bound parameter; `tenant_id`
//! is always injected. Only `SELECT` is ever generated.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

// --- Catalog (server-side constants; never user input) ----------------------

struct Dim {
    key: &'static str,
    label: &'static str,
    /// Hardcoded SQL expression used in SELECT and GROUP BY.
    sql: &'static str,
}

struct Measure {
    key: &'static str,
    label: &'static str,
    /// Hardcoded aggregate SQL expression.
    sql: &'static str,
}

struct Filter {
    key: &'static str,
    label: &'static str,
    /// Hardcoded text/enum column expression the value is compared against.
    sql: &'static str,
}

struct Source {
    key: &'static str,
    label: &'static str,
    /// `FROM ... JOIN ...` clause (no WHERE).
    from: &'static str,
    /// Tenant column to scope on, e.g. `t.tenant_id`.
    tenant_col: &'static str,
    /// Column for the optional inclusive from/to date range.
    date_col: Option<&'static str>,
    dims: &'static [Dim],
    measures: &'static [Measure],
    filters: &'static [Filter],
}

const TICKETS: Source = Source {
    key: "tickets",
    label: "Tickets",
    from: "FROM tickets t \
           LEFT JOIN ticket_statuses ts ON t.status_id = ts.id \
           LEFT JOIN ticket_priorities tp ON t.priority_id = tp.id \
           LEFT JOIN users u ON t.assigned_to_id = u.id",
    tenant_col: "t.tenant_id",
    date_col: Some("t.created_at"),
    dims: &[
        Dim {
            key: "status",
            label: "Status",
            sql: "ts.name",
        },
        Dim {
            key: "priority",
            label: "Priority",
            sql: "tp.name",
        },
        Dim {
            key: "assignee",
            label: "Assignee",
            sql: "COALESCE(NULLIF(TRIM(u.first_name || ' ' || u.last_name), ''), 'Unassigned')",
        },
        Dim {
            key: "created_date",
            label: "Created date",
            sql: "t.created_at::date",
        },
        Dim {
            key: "created_month",
            label: "Created month",
            sql: "to_char(t.created_at, 'YYYY-MM')",
        },
    ],
    measures: &[Measure {
        key: "count",
        label: "Count",
        sql: "COUNT(*)",
    }],
    filters: &[
        Filter {
            key: "status",
            label: "Status",
            sql: "ts.name",
        },
        Filter {
            key: "priority",
            label: "Priority",
            sql: "tp.name",
        },
    ],
};

const TIME: Source = Source {
    key: "time_entries",
    label: "Time entries",
    from: "FROM time_entries te \
           LEFT JOIN users u ON te.user_id = u.id \
           LEFT JOIN work_types wt ON te.work_type_id = wt.id",
    tenant_col: "te.tenant_id",
    date_col: Some("te.date"),
    dims: &[
        Dim {
            key: "user",
            label: "User",
            sql: "COALESCE(NULLIF(TRIM(u.first_name || ' ' || u.last_name), ''), u.email)",
        },
        Dim {
            key: "work_type",
            label: "Work type",
            sql: "wt.name",
        },
        Dim {
            key: "date",
            label: "Date",
            sql: "te.date",
        },
        Dim {
            key: "month",
            label: "Month",
            sql: "to_char(te.date, 'YYYY-MM')",
        },
        Dim {
            key: "billable",
            label: "Billable",
            sql: "CASE WHEN te.is_billable THEN 'Billable' ELSE 'Non-billable' END",
        },
    ],
    measures: &[
        Measure {
            key: "count",
            label: "Entries",
            sql: "COUNT(*)",
        },
        Measure {
            key: "minutes",
            label: "Minutes",
            sql: "COALESCE(SUM(te.duration_minutes), 0)",
        },
        Measure {
            key: "hours",
            label: "Hours",
            sql: "ROUND(COALESCE(SUM(te.duration_minutes), 0)::numeric / 60, 2)",
        },
        Measure {
            key: "amount",
            label: "Amount",
            sql: "COALESCE(SUM(te.total_amount), 0)",
        },
    ],
    filters: &[Filter {
        key: "work_type",
        label: "Work type",
        sql: "wt.name",
    }],
};

const ASSETS: Source = Source {
    key: "assets",
    label: "Assets",
    from: "FROM assets a \
           LEFT JOIN asset_types at2 ON a.asset_type_id = at2.id \
           LEFT JOIN companies c ON a.company_id = c.id",
    tenant_col: "a.tenant_id",
    date_col: None,
    dims: &[
        Dim {
            key: "type",
            label: "Type",
            sql: "at2.name",
        },
        Dim {
            key: "status",
            label: "Status",
            sql: "a.status",
        },
        Dim {
            key: "company",
            label: "Company",
            sql: "c.name",
        },
        Dim {
            key: "manufacturer",
            label: "Manufacturer",
            sql: "COALESCE(NULLIF(a.manufacturer, ''), '(unknown)')",
        },
    ],
    measures: &[Measure {
        key: "count",
        label: "Count",
        sql: "COUNT(*)",
    }],
    filters: &[
        Filter {
            key: "status",
            label: "Status",
            sql: "a.status",
        },
        Filter {
            key: "type",
            label: "Type",
            sql: "at2.name",
        },
    ],
};

const SOURCES: &[Source] = &[TICKETS, TIME, ASSETS];

// --- Public schema (what the SPA renders the builder from) ------------------

#[derive(Serialize)]
pub struct FieldSchema {
    pub key: &'static str,
    pub label: &'static str,
}

#[derive(Serialize)]
pub struct SourceSchema {
    pub key: &'static str,
    pub label: &'static str,
    pub dimensions: Vec<FieldSchema>,
    pub measures: Vec<FieldSchema>,
    pub filters: Vec<FieldSchema>,
    pub has_date_range: bool,
}

/// The full catalog, for `GET /reports/custom/schema`.
pub fn schema() -> Vec<SourceSchema> {
    SOURCES
        .iter()
        .map(|s| SourceSchema {
            key: s.key,
            label: s.label,
            dimensions: s
                .dims
                .iter()
                .map(|d| FieldSchema {
                    key: d.key,
                    label: d.label,
                })
                .collect(),
            measures: s
                .measures
                .iter()
                .map(|m| FieldSchema {
                    key: m.key,
                    label: m.label,
                })
                .collect(),
            filters: s
                .filters
                .iter()
                .map(|f| FieldSchema {
                    key: f.key,
                    label: f.label,
                })
                .collect(),
            has_date_range: s.date_col.is_some(),
        })
        .collect()
}

// --- Request / response -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CustomFilter {
    pub field: String,
    #[serde(default)]
    pub op: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct CustomSpec {
    pub source: String,
    #[serde(default)]
    pub dimensions: Vec<String>,
    #[serde(default)]
    pub measures: Vec<String>,
    #[serde(default)]
    pub filters: Vec<CustomFilter>,
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
    pub limit: Option<i64>,
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CustomReportResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub totals: BTreeMap<String, String>,
}

enum Bind {
    Text(String),
    Date(NaiveDate),
}

/// Validate `spec` against the catalog, build a parameterized SELECT, and
/// run it tenant-scoped. Returns the generic columns / rows / totals
/// envelope. Every unknown key is a 400 before any SQL is built.
pub async fn run(
    executor: impl sqlx::PgExecutor<'_>,
    tenant_id: TenantId,
    spec: &CustomSpec,
) -> AppResult<CustomReportResponse> {
    let src = SOURCES
        .iter()
        .find(|s| s.key == spec.source)
        .ok_or_else(|| AppError::BadRequest(format!("unknown report source {:?}", spec.source)))?;

    if spec.measures.is_empty() {
        return Err(AppError::BadRequest(
            "at least one measure is required".into(),
        ));
    }

    let mut dims = Vec::new();
    for k in &spec.dimensions {
        let d = src.dims.iter().find(|d| d.key == *k).ok_or_else(|| {
            AppError::BadRequest(format!("unknown dimension {k:?} for source {:?}", src.key))
        })?;
        dims.push(d);
    }
    let mut measures = Vec::new();
    for k in &spec.measures {
        let m = src.measures.iter().find(|m| m.key == *k).ok_or_else(|| {
            AppError::BadRequest(format!("unknown measure {k:?} for source {:?}", src.key))
        })?;
        measures.push(m);
    }

    // Column labels: dimensions first, then measures.
    let mut columns: Vec<String> = dims.iter().map(|d| d.label.to_string()).collect();
    columns.extend(measures.iter().map(|m| m.label.to_string()));

    // SELECT list: every expression cast ::text for a uniform dynamic read.
    let mut selects: Vec<String> = Vec::with_capacity(dims.len() + measures.len());
    selects.extend(dims.iter().map(|d| format!("({})::text", d.sql)));
    selects.extend(measures.iter().map(|m| format!("({})::text", m.sql)));

    let mut sql = format!(
        "SELECT {} {} WHERE {} = $1",
        selects.join(", "),
        src.from,
        src.tenant_col
    );

    // Bound values beyond $1 (tenant), in placement order.
    let mut binds: Vec<Bind> = Vec::new();
    let mut ph = 2;

    for f in &spec.filters {
        if !f.op.is_empty() && f.op != "eq" {
            return Err(AppError::BadRequest(format!(
                "unsupported filter op {:?}; only 'eq' is supported",
                f.op
            )));
        }
        let fs = src
            .filters
            .iter()
            .find(|x| x.key == f.field)
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "unknown filter field {:?} for source {:?}",
                    f.field, src.key
                ))
            })?;
        sql.push_str(&format!(" AND {} = ${}", fs.sql, ph));
        binds.push(Bind::Text(f.value.clone()));
        ph += 1;
    }

    if let Some(dc) = src.date_col {
        if let Some(from) = spec.from {
            sql.push_str(&format!(" AND {dc}::date >= ${ph}"));
            binds.push(Bind::Date(from));
            ph += 1;
        }
        if let Some(to) = spec.to {
            sql.push_str(&format!(" AND {dc}::date <= ${ph}"));
            binds.push(Bind::Date(to));
            // `ph` is intentionally not advanced here: this is the last
            // placeholder, so nothing reads it afterward.
        }
    }

    if !dims.is_empty() {
        let ordinals: Vec<String> = (1..=dims.len()).map(|i| i.to_string()).collect();
        let joined = ordinals.join(", ");
        sql.push_str(&format!(" GROUP BY {joined} ORDER BY {joined}"));
    }

    let limit = spec.limit.unwrap_or(100).clamp(1, 1000);
    sql.push_str(&format!(" LIMIT {limit}"));

    let mut q = sqlx::query(&sql).bind(tenant_id);
    for b in &binds {
        q = match b {
            Bind::Text(s) => q.bind(s),
            Bind::Date(d) => q.bind(d),
        };
    }
    let rows = q.fetch_all(executor).await?;

    let ncols = dims.len() + measures.len();
    let mut out_rows: Vec<Vec<Option<String>>> = Vec::with_capacity(rows.len());
    let mut totals_acc: Vec<f64> = vec![0.0; measures.len()];

    for row in &rows {
        let mut r: Vec<Option<String>> = Vec::with_capacity(ncols);
        for i in 0..ncols {
            r.push(row.try_get::<Option<String>, _>(i)?);
        }
        for (j, _) in measures.iter().enumerate() {
            if let Some(Some(s)) = r.get(dims.len() + j) {
                if let Ok(n) = s.parse::<f64>() {
                    totals_acc[j] += n;
                }
            }
        }
        out_rows.push(r);
    }

    let mut totals = BTreeMap::new();
    for (j, m) in measures.iter().enumerate() {
        totals.insert(m.label.to_string(), fmt_num(totals_acc[j]));
    }

    Ok(CustomReportResponse {
        columns,
        rows: out_rows,
        totals,
    })
}

/// Render a totals number without a needless `.0` on whole values.
fn fmt_num(n: f64) -> String {
    if n.fract().abs() < 1e-9 {
        format!("{}", n as i64)
    } else {
        format!("{n:.2}")
    }
}

/// Serialise a result as CSV (header row + data rows).
pub fn to_csv(r: &CustomReportResponse) -> String {
    let mut s = r
        .columns
        .iter()
        .map(|c| csv_cell(c))
        .collect::<Vec<_>>()
        .join(",");
    s.push('\n');
    for row in &r.rows {
        let line = row
            .iter()
            .map(|c| csv_cell(c.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(",");
        s.push_str(&line);
        s.push('\n');
    }
    s
}

/// Quote a CSV cell if it contains a comma, quote, or newline.
fn csv_cell(v: &str) -> String {
    if v.contains([',', '"', '\n']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}
