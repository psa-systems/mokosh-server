//! PMS-477: saved-report execution-runtime compiler.
//!
//! Takes a stored `saved_reports` row (`entity_type` + `filters` +
//! `columns` + `sort` JSONB) and emits a parameterised SELECT against
//! the chosen entity table. Phase 2 implements ONE entity (tickets)
//! with a fixed column + filter whitelist; the data shape on the
//! `saved_reports` row is opaque-on-write so the SPA can iterate
//! without a server redeploy, and validation happens here at execute
//! time. Anything the compiler does not recognise surfaces as 422
//! naming the offender.
//!
//! Why a hand-rolled compiler instead of the existing list endpoint:
//! the list endpoint shape is fixed (it returns `TicketResponse` rows
//! with every column). A report needs a CALLER-CHOSEN column subset
//! plus arbitrary filters; threading that through TicketResponse
//! would force every consumer to deal with optional fields. Compile
//! to a dedicated SELECT + emit row maps keyed by alias so the SPA
//! gets `{ ticket_number: ..., status_name: ... }` directly.

use serde_json::Value;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

/// A compiled report query: ready-to-bind SQL + the ordered list of
/// bind values + the alias-list the executor uses to shape the
/// returned rows. Bind values are kept as JSON so the executor can
/// emit each one with the right SQLx adapter (`Uuid::parse_str` for
/// uuid columns, `as_str` for text, etc.) based on the column type.
#[derive(Debug, Clone)]
pub struct CompiledQuery {
    /// The full SELECT including `WHERE` + `ORDER BY` + `LIMIT $N
    /// OFFSET $M`. Always ends with a `LIMIT ? OFFSET ?` whose binds
    /// are the LAST two entries in `binds`.
    pub sql: String,
    /// Ordered bind values. JSON shape so the executor can pick a
    /// per-column type at bind time without a separate type-tag
    /// vector. Mixed (`Uuid`, `String`, `Vec<Uuid>`, `Vec<String>`,
    /// `i64`) per the column whitelist.
    pub binds: Vec<BindValue>,
    /// Output row shape: ordered SQL output names. Derived from the
    /// `ticket_column` whitelist keys (never from caller input, see
    /// PMS-690), so these are the keys `row_to_json` produces.
    pub columns: Vec<String>,
    /// Display headers, positionally matching `columns`. The executor
    /// re-keys each row from `columns` to these before returning, so
    /// the SPA still gets operator-chosen labels.
    pub aliases: Vec<String>,
    /// COUNT(*) query that matches the same WHERE clause (but no
    /// LIMIT/OFFSET) so the executor can return `total` alongside
    /// the rows for the SPA's pagination footer.
    pub count_sql: String,
    /// Binds for `count_sql` - the same WHERE binds, excluding
    /// pagination's LIMIT/OFFSET.
    pub count_binds: Vec<BindValue>,
}

/// Bind value that survives the JSON round trip. Each variant
/// corresponds to a Postgres column type the whitelist surfaces.
#[derive(Debug, Clone)]
pub enum BindValue {
    Uuid(Uuid),
    UuidList(Vec<Uuid>),
    Text(String),
    TextList(Vec<String>),
    Int(i64),
    Bool(bool),
}

/// Public entry point. Validates the saved-report inputs, picks the
/// per-entity compiler, returns the compiled query.
pub fn compile(
    tenant_id: Uuid,
    entity_type: &str,
    filters: &Value,
    columns: &Value,
    sort: &Value,
    pagination_limit: u32,
    pagination_offset: u32,
) -> AppResult<CompiledQuery> {
    match entity_type {
        "tickets" => compile_tickets(
            tenant_id,
            filters,
            columns,
            sort,
            pagination_limit,
            pagination_offset,
        ),
        other => Err(AppError::BadRequest(format!(
            "Unsupported entity_type='{other}'. Phase 2 only supports 'tickets'.",
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tickets compiler
// ---------------------------------------------------------------------------

/// Per-column metadata for the tickets entity. The compiler picks
/// the SQL expression by column-key match and validates filter
/// operators against the column's type.
#[derive(Debug, Clone, Copy)]
struct TicketColumn {
    /// SQL fragment used both in SELECT (with `AS <key>`) and as
    /// the LHS of a filter or ORDER BY. Comes from the existing
    /// TICKET_RESPONSE_SELECT join tree (see
    /// `src/modules/tickets/service.rs`) so the join shape stays
    /// in sync with the agent list endpoint.
    sql: &'static str,
    /// Column's Postgres type. Drives how filter values bind.
    ty: ColumnType,
    /// `true` if this column is reachable through `JOIN_TREE` below
    /// (every whitelisted column is, by construction; the field
    /// exists for symmetry + future per-column joins).
    #[allow(dead_code)]
    requires_join: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Int is reserved for future integer columns (e.g. estimated_hours-in-minutes); the variant exists so the column-type matcher stays exhaustive when one lands.
enum ColumnType {
    Uuid,
    Text,
    Int,
    Bool,
    Timestamp,
}

/// JOIN tree the tickets compiler always emits. Same shape as
/// `TICKET_RESPONSE_SELECT` in `src/modules/tickets/service.rs` so
/// every whitelisted column resolves without an extra LEFT JOIN
/// per-call. Lifted to a constant so the JOIN cost is paid once and
/// the SQL is grep-able when a future column joins a new table.
const TICKETS_JOIN_TREE: &str = "
    FROM tickets t
    INNER JOIN ticket_statuses    ts ON t.status_id     = ts.id
    INNER JOIN ticket_priorities  tp ON t.priority_id   = tp.id
    INNER JOIN ticket_queues      tq ON t.queue_id      = tq.id
    LEFT  JOIN ticket_types       tt ON t.type_id       = tt.id
    LEFT  JOIN ticket_categories  tc ON t.category_id   = tc.id
    INNER JOIN companies          co ON t.company_id    = co.id
    LEFT  JOIN contacts           ct ON t.contact_id    = ct.id
    LEFT  JOIN users              au ON t.assigned_to_id = au.id
    LEFT  JOIN assets             a  ON t.asset_id      = a.id
    LEFT  JOIN users              cu ON t.created_by_id = cu.id
";

/// Column whitelist for the tickets entity. Anything outside this
/// map is 422'd. Adding a column = one line here; the `requires_join`
/// flag is informational since `TICKETS_JOIN_TREE` already covers
/// every entry.
fn ticket_column(key: &str) -> Option<TicketColumn> {
    use ColumnType::*;
    Some(match key {
        "ticket_number" => TicketColumn {
            sql: "t.ticket_number",
            ty: Text,
            requires_join: false,
        },
        "title" => TicketColumn {
            sql: "t.title",
            ty: Text,
            requires_join: false,
        },
        "description" => TicketColumn {
            sql: "t.description",
            ty: Text,
            requires_join: false,
        },
        "source" => TicketColumn {
            sql: "t.source",
            ty: Text,
            requires_join: false,
        },
        "is_billable" => TicketColumn {
            sql: "t.is_billable",
            ty: Bool,
            requires_join: false,
        },
        "billing_status" => TicketColumn {
            sql: "t.billing_status",
            ty: Text,
            requires_join: false,
        },
        "created_at" => TicketColumn {
            sql: "t.created_at",
            ty: Timestamp,
            requires_join: false,
        },
        "updated_at" => TicketColumn {
            sql: "t.updated_at",
            ty: Timestamp,
            requires_join: false,
        },
        "closed_at" => TicketColumn {
            sql: "t.closed_at",
            ty: Timestamp,
            requires_join: false,
        },
        "status_id" => TicketColumn {
            sql: "t.status_id",
            ty: Uuid,
            requires_join: false,
        },
        "priority_id" => TicketColumn {
            sql: "t.priority_id",
            ty: Uuid,
            requires_join: false,
        },
        "queue_id" => TicketColumn {
            sql: "t.queue_id",
            ty: Uuid,
            requires_join: false,
        },
        "type_id" => TicketColumn {
            sql: "t.type_id",
            ty: Uuid,
            requires_join: false,
        },
        "company_id" => TicketColumn {
            sql: "t.company_id",
            ty: Uuid,
            requires_join: false,
        },
        "contact_id" => TicketColumn {
            sql: "t.contact_id",
            ty: Uuid,
            requires_join: false,
        },
        "assigned_to_id" => TicketColumn {
            sql: "t.assigned_to_id",
            ty: Uuid,
            requires_join: false,
        },
        "status_name" => TicketColumn {
            sql: "ts.name",
            ty: Text,
            requires_join: true,
        },
        "priority_name" => TicketColumn {
            sql: "tp.name",
            ty: Text,
            requires_join: true,
        },
        "queue_name" => TicketColumn {
            sql: "tq.name",
            ty: Text,
            requires_join: true,
        },
        "type_name" => TicketColumn {
            sql: "tt.name",
            ty: Text,
            requires_join: true,
        },
        "category_name" => TicketColumn {
            sql: "tc.name",
            ty: Text,
            requires_join: true,
        },
        "company_name" => TicketColumn {
            sql: "co.name",
            ty: Text,
            requires_join: true,
        },
        "contact_name" => TicketColumn {
            // Mirror the agent endpoint's NULLIF/COALESCE so a contact
            // with empty first+last shows as null, not " ".
            sql:
                "NULLIF(TRIM(COALESCE(ct.first_name, '') || ' ' || COALESCE(ct.last_name, '')), '')",
            ty: Text,
            requires_join: true,
        },
        "assigned_to_name" => TicketColumn {
            sql:
                "NULLIF(TRIM(COALESCE(au.first_name, '') || ' ' || COALESCE(au.last_name, '')), '')",
            ty: Text,
            requires_join: true,
        },
        "asset_name" => TicketColumn {
            sql: "a.name",
            ty: Text,
            requires_join: true,
        },
        "created_by_name" => TicketColumn {
            sql: "COALESCE(TRIM(cu.first_name || ' ' || cu.last_name), '')",
            ty: Text,
            requires_join: true,
        },
        _ => return None,
    })
}

fn compile_tickets(
    tenant_id: Uuid,
    filters: &Value,
    columns: &Value,
    sort: &Value,
    pagination_limit: u32,
    pagination_offset: u32,
) -> AppResult<CompiledQuery> {
    // -------- columns --------
    // Default to the agent endpoint's most-useful subset when the
    // saved report's `columns` array is empty - keeps the "save it
    // blank, hit execute" path from returning an empty result set
    // shape that confuses the SPA.
    let column_specs = parse_columns(columns)?;
    let mut select_fragments: Vec<String> = Vec::with_capacity(column_specs.len());
    let mut output_columns: Vec<String> = Vec::with_capacity(column_specs.len());
    let mut aliases: Vec<String> = Vec::with_capacity(column_specs.len());
    for (field, header) in &column_specs {
        let Some(col) = ticket_column(field) else {
            return Err(AppError::BadRequest(format!(
                "Unsupported column '{field}' for entity 'tickets'. \
                 See the saved-report column whitelist."
            )));
        };
        // PMS-690: the SQL alias comes from the whitelisted field key,
        // never from the caller's header, so no `columns` payload can
        // reach the SQL text. The header travels in `aliases` only.
        let key = unique_output_key(&output_columns, field);
        select_fragments.push(format!("{} AS \"{}\"", col.sql, key));
        output_columns.push(key);
        aliases.push(header.clone());
    }
    let select_clause = select_fragments.join(", ");

    // -------- filters --------
    // tenant_id is the first bind. Every per-filter clause uses
    // `${N}` where N is the next index; using a running counter
    // keeps the indexes synchronised with `binds.len()`.
    let mut binds: Vec<BindValue> = vec![BindValue::Uuid(tenant_id)];
    let mut where_clauses: Vec<String> = vec!["t.tenant_id = $1".into()];

    if let Some(filter_obj) = filters.as_object() {
        for (field, value) in filter_obj {
            let Some(col) = ticket_column(field) else {
                return Err(AppError::BadRequest(format!(
                    "Unsupported filter field '{field}' for entity 'tickets'."
                )));
            };
            let (clause, extra_binds) = compile_filter(field, &col, value, binds.len() + 1)?;
            where_clauses.push(clause);
            binds.extend(extra_binds);
        }
    }
    let where_clause = where_clauses.join(" AND ");

    // -------- sort --------
    let order_by_clause = parse_sort(sort)?;

    // -------- count + paged SELECT --------
    let count_sql = format!("SELECT COUNT(*)::bigint {TICKETS_JOIN_TREE} WHERE {where_clause}");
    let count_binds = binds.clone();

    let limit_idx = binds.len() + 1;
    let offset_idx = binds.len() + 2;
    binds.push(BindValue::Int(pagination_limit as i64));
    binds.push(BindValue::Int(pagination_offset as i64));

    let sql = format!(
        "SELECT {select_clause} \
         {TICKETS_JOIN_TREE} \
         WHERE {where_clause} \
         {order_by_clause} \
         LIMIT ${limit_idx} OFFSET ${offset_idx}",
    );

    Ok(CompiledQuery {
        sql,
        binds,
        columns: output_columns,
        aliases,
        count_sql,
        count_binds,
    })
}

/// Pick a unique SQL output name for a whitelisted field key. The same
/// field selected twice would otherwise collapse to one `row_to_json`
/// key, so repeats get a `_2`, `_3`, ... suffix. Input is always a
/// whitelist key, so the result never carries caller-supplied text.
fn unique_output_key(taken: &[String], field: &str) -> String {
    let mut key = field.to_string();
    let mut n = 2;
    while taken.contains(&key) {
        key = format!("{field}_{n}");
        n += 1;
    }
    key
}

/// Longest display header the compiler accepts. A header is a column
/// label, not free text; anything longer is a malformed payload.
const MAX_HEADER_LEN: usize = 100;

/// Parse the saved-report `columns` JSON into `(field, header)` pairs.
/// Accepts `[{"field": "ticket_number"}, {"field": "title", "header": "Subject"}]`
/// or a plain string array `["ticket_number", "title"]`. When the
/// array is empty, fall back to a sensible default subset rather
/// than emit `SELECT ` with no columns.
///
/// The header is display-only (PMS-690) and never reaches the SQL
/// text, but an over-long header or one carrying a `"` is still
/// rejected here so a hostile payload fails loudly rather than
/// silently rendering under a different name.
fn parse_columns(columns: &Value) -> AppResult<Vec<(String, String)>> {
    let Some(arr) = columns.as_array() else {
        // A non-array `columns` blob is a SPA bug; better to 422
        // than silently fall back to defaults.
        return Err(AppError::BadRequest(
            "saved_reports.columns must be a JSON array".into(),
        ));
    };
    if arr.is_empty() {
        return Ok(default_ticket_columns());
    }
    let mut out = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        // Support both shapes for SPA-iteration flexibility:
        // `"ticket_number"` (string) and
        // `{"field": "ticket_number", "header": "Number"}` (object).
        let (field, header) = match entry {
            Value::String(s) => (s.clone(), s.clone()),
            Value::Object(o) => {
                let field = o
                    .get("field")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::BadRequest(format!(
                            "columns[{idx}].field is required (got {entry})"
                        ))
                    })?
                    .to_string();
                let header = o
                    .get("header")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&field)
                    .to_string();
                (field, header)
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "columns[{idx}] must be a string or an object (got {entry})"
                )));
            }
        };
        if header.contains('"') {
            return Err(AppError::BadRequest(format!(
                "columns[{idx}].header must not contain a double quote"
            )));
        }
        if header.chars().count() > MAX_HEADER_LEN {
            return Err(AppError::BadRequest(format!(
                "columns[{idx}].header must be at most {MAX_HEADER_LEN} characters"
            )));
        }
        out.push((field, header));
    }
    Ok(out)
}

/// Default column set when the saved report's `columns` array is
/// empty. Mirrors the most-used fields on the agent ticket list so
/// a freshly-saved blank report produces a useful default render.
fn default_ticket_columns() -> Vec<(String, String)> {
    [
        "ticket_number",
        "title",
        "status_name",
        "priority_name",
        "company_name",
        "assigned_to_name",
        "created_at",
        "updated_at",
    ]
    .iter()
    .map(|s| (s.to_string(), s.to_string()))
    .collect()
}

/// Compile a single `{field: value}` filter entry into a `WHERE`
/// clause + bind value list. Value semantics:
///   - scalar (string/bool/number) => equality
///   - array => IN
///
/// The compiler runs the value through `coerce_bind` to assert the
/// type matches the column whitelist; a uuid column with a string
/// value that does not parse 422s naming the field.
fn compile_filter(
    field: &str,
    col: &TicketColumn,
    value: &Value,
    start_bind_idx: usize,
) -> AppResult<(String, Vec<BindValue>)> {
    if let Some(arr) = value.as_array() {
        if arr.is_empty() {
            return Err(AppError::BadRequest(format!(
                "filter '{field}' is an empty array; remove the key or supply at least one value"
            )));
        }
        // IN. One bind for the whole array. Postgres `= ANY($N)`
        // with an explicit element-type cast - matches what the
        // existing list endpoints do for IN filters (see e.g. the
        // approvals pending queue's `ANY($3)` pattern).
        let element_cast = match col.ty {
            ColumnType::Uuid => "uuid",
            ColumnType::Text => "text",
            ColumnType::Int => "bigint",
            ColumnType::Bool => "boolean",
            ColumnType::Timestamp => "timestamptz",
        };
        let clause = format!(
            "{lhs} = ANY(${idx}::{cast}[])",
            lhs = col.sql,
            idx = start_bind_idx,
            cast = element_cast,
        );
        let bind = coerce_bind_array(field, col.ty, arr)?;
        Ok((clause, vec![bind]))
    } else {
        let clause = format!("{lhs} = ${idx}", lhs = col.sql, idx = start_bind_idx);
        let bind = coerce_bind_scalar(field, col.ty, value)?;
        Ok((clause, vec![bind]))
    }
}

fn coerce_bind_scalar(field: &str, ty: ColumnType, value: &Value) -> AppResult<BindValue> {
    match (ty, value) {
        (ColumnType::Uuid, Value::String(s)) => {
            Uuid::parse_str(s).map(BindValue::Uuid).map_err(|e| {
                AppError::BadRequest(format!(
                    "filter '{field}' expects a UUID; '{s}' is not one ({e})"
                ))
            })
        }
        (ColumnType::Text, Value::String(s)) => Ok(BindValue::Text(s.clone())),
        (ColumnType::Int, Value::Number(n)) => n
            .as_i64()
            .map(BindValue::Int)
            .ok_or_else(|| AppError::BadRequest(format!("filter '{field}' must fit in i64"))),
        (ColumnType::Bool, Value::Bool(b)) => Ok(BindValue::Bool(*b)),
        (ColumnType::Timestamp, Value::String(s)) => Ok(BindValue::Text(s.clone())),
        _ => Err(AppError::BadRequest(format!(
            "filter '{field}' has an unexpected value type for its column"
        ))),
    }
}

fn coerce_bind_array(field: &str, ty: ColumnType, arr: &[Value]) -> AppResult<BindValue> {
    match ty {
        ColumnType::Uuid => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let s = v.as_str().ok_or_else(|| {
                    AppError::BadRequest(format!("filter '{field}' UUID values must be strings"))
                })?;
                out.push(Uuid::parse_str(s).map_err(|e| {
                    AppError::BadRequest(format!("filter '{field}': '{s}' is not a UUID ({e})"))
                })?);
            }
            Ok(BindValue::UuidList(out))
        }
        ColumnType::Text | ColumnType::Timestamp => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let s = v.as_str().ok_or_else(|| {
                    AppError::BadRequest(format!("filter '{field}' values must be strings"))
                })?;
                out.push(s.to_string());
            }
            Ok(BindValue::TextList(out))
        }
        ColumnType::Int | ColumnType::Bool => Err(AppError::BadRequest(format!(
            "filter '{field}' does not support array values for its column type"
        ))),
    }
}

/// Parse `sort` JSON into an ORDER BY clause. Accepts an array of
/// `{field, dir}` objects. Empty / missing -> default to
/// `ORDER BY t.updated_at DESC` to give pagination a stable order.
fn parse_sort(sort: &Value) -> AppResult<String> {
    let Some(arr) = sort.as_array() else {
        return Ok("ORDER BY t.updated_at DESC".into());
    };
    if arr.is_empty() {
        return Ok("ORDER BY t.updated_at DESC".into());
    }
    let mut parts: Vec<String> = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let obj = entry.as_object().ok_or_else(|| {
            AppError::BadRequest(format!("sort[{idx}] must be an object {{field, dir}}"))
        })?;
        let field = obj
            .get("field")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("sort[{idx}].field is required")))?;
        let col = ticket_column(field).ok_or_else(|| {
            AppError::BadRequest(format!("sort[{idx}] unsupported field '{field}'"))
        })?;
        let dir = obj
            .get("dir")
            .and_then(|v| v.as_str())
            .unwrap_or("asc")
            .to_lowercase();
        let dir_sql = match dir.as_str() {
            "asc" => "ASC",
            "desc" => "DESC",
            other => {
                return Err(AppError::BadRequest(format!(
                    "sort[{idx}].dir must be 'asc' or 'desc' (got '{other}')"
                )));
            }
        };
        parts.push(format!("{} {}", col.sql, dir_sql));
    }
    Ok(format!("ORDER BY {}", parts.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tenant() -> Uuid {
        Uuid::from_u128(0xfeed)
    }

    #[test]
    fn unsupported_entity_rejected() {
        let err = compile(
            tenant(),
            "invoices",
            &json!({}),
            &json!([]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Phase 2 only supports 'tickets'"));
    }

    #[test]
    fn unknown_column_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([{"field": "totally_made_up"}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("totally_made_up"));
    }

    #[test]
    fn empty_columns_uses_default_subset() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert!(q.aliases.contains(&"ticket_number".to_string()));
        assert!(q.aliases.contains(&"status_name".to_string()));
    }

    #[test]
    fn in_filter_compiles_to_any() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({ "status_id": [Uuid::from_u128(1).to_string()] }),
            &json!([{"field": "ticket_number"}]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert!(q.sql.contains("= ANY($2::uuid[])"));
        assert!(matches!(q.binds[1], BindValue::UuidList(ref v) if v.len() == 1));
    }

    #[test]
    fn scalar_filter_compiles_to_equality() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({ "source": "email" }),
            &json!([{"field": "ticket_number"}]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert!(q.sql.contains("t.source = $2"));
    }

    #[test]
    fn unknown_filter_field_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({ "garbage": "x" }),
            &json!([{"field": "ticket_number"}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("garbage"));
    }

    #[test]
    fn empty_array_filter_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({ "status_id": [] }),
            &json!([{"field": "ticket_number"}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty array"));
    }

    #[test]
    fn malformed_uuid_filter_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({ "status_id": ["not-a-uuid"] }),
            &json!([{"field": "ticket_number"}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not-a-uuid"));
    }

    #[test]
    fn default_sort_is_updated_at_desc() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert!(q.sql.contains("ORDER BY t.updated_at DESC"));
    }

    // PMS-690: the header never reaches the SQL text.
    #[test]
    fn header_with_double_quote_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([{"field": "ticket_number", "header": "a\" , 1 AS \"b"}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("double quote"), "got {err}");
    }

    #[test]
    fn over_long_header_rejected() {
        let err = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([{"field": "ticket_number", "header": "x".repeat(MAX_HEADER_LEN + 1)}]),
            &json!([]),
            50,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at most"), "got {err}");
    }

    #[test]
    fn header_never_reaches_sql() {
        // Same payload shape as the injection report, minus the quote
        // that `parse_columns` now rejects outright: even an accepted
        // header contributes nothing to the SQL text.
        let q = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([
                {"field": "ticket_number", "header": "a , 1 AS b"},
                {"field": "title", "header": "Subject"},
            ]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert!(!q.sql.contains("1 AS b"), "sql: {}", q.sql);
        assert!(!q.sql.contains("Subject"), "sql: {}", q.sql);
        // One `AS` per whitelisted column, and every alias is a
        // whitelist key.
        assert_eq!(q.sql.matches(" AS ").count(), 2, "sql: {}", q.sql);
        assert!(q.sql.contains("t.ticket_number AS \"ticket_number\""));
        assert!(q.sql.contains("t.title AS \"title\""));
        assert_eq!(q.sql.matches('"').count(), 4, "sql: {}", q.sql);
        assert_eq!(q.columns, vec!["ticket_number", "title"]);
        // The display headers survive for the SPA.
        assert_eq!(q.aliases, vec!["a , 1 AS b", "Subject"]);
    }

    #[test]
    fn repeated_field_gets_distinct_output_keys() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([
                {"field": "title", "header": "Subject"},
                {"field": "title", "header": "Subject copy"},
            ]),
            &json!([]),
            50,
            0,
        )
        .expect("ok");
        assert_eq!(q.columns, vec!["title", "title_2"]);
        assert!(q.sql.contains("t.title AS \"title_2\""), "sql: {}", q.sql);
    }

    #[test]
    fn explicit_sort_uses_whitelisted_column() {
        let q = compile(
            tenant(),
            "tickets",
            &json!({}),
            &json!([]),
            &json!([{"field": "ticket_number", "dir": "asc"}]),
            50,
            0,
        )
        .expect("ok");
        assert!(q.sql.contains("ORDER BY t.ticket_number ASC"));
    }
}
