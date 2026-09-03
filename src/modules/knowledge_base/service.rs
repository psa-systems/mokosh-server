//! Knowledge base service.

use crate::modules::auth::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct KbService {
    db: Database,
}

impl KbService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Reject any `company_ids` entry that is not a company owned by this
    /// tenant, so a `client_specific` article cannot be scoped to another
    /// tenant's company (PMS-341). No-op for an empty set.
    async fn validate_company_ids(&self, tenant_id: TenantId, ids: &[Uuid]) -> AppResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let found: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT id) FROM companies WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_one(&mut *tx)
        .await?;
        let distinct = ids.iter().collect::<std::collections::HashSet<_>>().len() as i64;
        if found != distinct {
            return Err(AppError::BadRequest(
                "One or more company_ids do not belong to this tenant".to_string(),
            ));
        }
        Ok(())
    }

    // PMS-81 categories -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_categories(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbCategoryResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM kb_categories WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, CatRow>(
            r#"SELECT id, name, description, parent_id, slug, visibility, sort_order
               FROM kb_categories WHERE tenant_id = $1
               ORDER BY sort_order, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_category(
        &self,
        tenant_id: TenantId,
        request: &UpsertKbCategoryRequest,
        ctx: &AuditCtx,
    ) -> AppResult<KbCategoryResponse> {
        // Per-tenant unique slug (enforced at the app layer; the
        // `uq_kb_categories_tenant_slug` constraint is the DB backstop).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let dup: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_categories WHERE tenant_id = $1 AND slug = $2)",
        )
        .bind(tenant_id)
        .bind(&request.slug)
        .fetch_one(&mut *tx)
        .await?;
        if dup {
            return Err(AppError::Conflict(format!(
                "KbCategory slug '{}' already exists",
                request.slug
            )));
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO kb_categories
               (id, tenant_id, name, description, parent_id, slug, visibility, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.parent_id)
        .bind(&request.slug)
        .bind(&request.visibility)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM kb_categories t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "kb_categories",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(KbCategoryResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            parent_id: request.parent_id,
            slug: request.slug.clone(),
            visibility: request.visibility.clone(),
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_category(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertKbCategoryRequest,
    ) -> AppResult<KbCategoryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE kb_categories SET
                  name = $3, description = $4, parent_id = $5, slug = $6,
                  visibility = $7, sort_order = $8, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.parent_id)
        .bind(&request.slug)
        .bind(&request.visibility)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KB category".to_string()));
        }
        tx.commit().await?;
        Ok(KbCategoryResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            parent_id: request.parent_id,
            slug: request.slug.clone(),
            visibility: request.visibility.clone(),
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_category(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM kb_categories WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KB category".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-82 / PMS-83 articles + versions -------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_articles(
        &self,
        tenant_id: TenantId,
        filter: &KbArticleFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbArticleResponse>, u64)> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.category_id.is_some() {
            conditions.push(format!("category_id = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${idx}"));
            idx += 1;
        }
        if filter.visibility.is_some() {
            conditions.push(format!("visibility = ${idx}"));
            idx += 1;
        }
        // Full-text search via pg_trgm word similarity. The `<%`
        // operator (`query <% text`, true when
        // `word_similarity(query, text) >= word_similarity_threshold`,
        // default 0.6) is the right primitive for matching a short query
        // term against the most similar word/extent inside a longer
        // article body, and it is index-backed by
        // `idx_kb_articles_content_trgm` (GIN over
        // `(title || ' ' || content) gin_trgm_ops`). Results are ranked by
        // `word_similarity(...)` DESC so the closest matches come first;
        // falls back to `updated_at DESC` when no query term is given.
        let q_placeholder = if filter.q.is_some() {
            conditions.push(format!("${idx} <% (title || ' ' || content)"));
            let p = idx;
            idx += 1;
            Some(p)
        } else {
            None
        };
        let where_clause = conditions.join(" AND ");
        let order_by = match q_placeholder {
            Some(p) => {
                format!("word_similarity(${p}, title || ' ' || content) DESC, updated_at DESC")
            }
            None => "updated_at DESC".to_string(),
        };
        let limit_placeholder = idx;
        let offset_placeholder = idx + 1;
        let query = format!(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, company_ids, created_at, updated_at
               FROM kb_articles WHERE {where_clause}
               ORDER BY {order_by}
               LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}"#
        );
        let count_query = format!("SELECT COUNT(*) FROM kb_articles WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, ArticleRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.category_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.status {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.visibility {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.q {
            // pg_trgm compares the raw term against the indexed
            // expression; no ILIKE wildcards.
            q = q.bind(v.clone());
            cq = cq.bind(v.clone());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_article(
        &self,
        tenant_id: TenantId,
        author_id: Uuid,
        request: &CreateKbArticleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<KbArticleResponse> {
        // Resolve the company scope before any write. A
        // `client_specific` article requires a non-empty, tenant-owned
        // `company_ids`; for any other visibility the scope is ignored and
        // stored empty so it cannot leak into the portal filter (PMS-341).
        let company_ids: Vec<Uuid> = if request.visibility == "client_specific" {
            let ids = request.company_ids.clone().unwrap_or_default();
            if ids.is_empty() {
                return Err(AppError::validation_field(
                    "company_ids",
                    "client_specific articles require at least one company",
                ));
            }
            self.validate_company_ids(tenant_id, &ids).await?;
            ids
        } else {
            Vec::new()
        };

        // Per-tenant unique slug (app-layer check; the
        // `uq_kb_articles_tenant_slug` constraint is the DB backstop).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let dup: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE tenant_id = $1 AND slug = $2)",
        )
        .bind(tenant_id)
        .bind(&request.slug)
        .fetch_one(&mut *tx)
        .await?;
        if dup {
            return Err(AppError::Conflict(format!(
                "KbArticle slug '{}' already exists",
                request.slug
            )));
        }
        let id = Uuid::new_v4();
        // Stamp published_at when the article is created already
        // published; leave NULL for draft / archived. `NOW()` is applied
        // in SQL only when status = 'published'.
        let publish_now = request.status == "published";
        sqlx::query(
            r#"INSERT INTO kb_articles
               (id, tenant_id, title, slug, content, summary, category_id, visibility,
                status, author_id, tags, company_ids, published_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                       CASE WHEN $13 THEN NOW() ELSE NULL END)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.title)
        .bind(&request.slug)
        .bind(&request.content)
        .bind(&request.summary)
        .bind(request.category_id)
        .bind(&request.visibility)
        .bind(&request.status)
        .bind(author_id)
        .bind(&request.tags)
        .bind(&company_ids)
        .bind(publish_now)
        .execute(&mut *tx)
        .await?;
        // Seed the first version.
        sqlx::query(
            r#"INSERT INTO kb_article_versions
               (article_id, version_number, title, content, edited_by_id)
               VALUES ($1, 1, $2, $3, $4)"#,
        )
        .bind(id)
        .bind(&request.title)
        .bind(&request.content)
        .bind(author_id)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM kb_articles t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "kb_articles",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        self.get_article_inner(tenant_id, id, false).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_article(&self, tenant_id: TenantId, id: Uuid) -> AppResult<KbArticleResponse> {
        // Public reads count as a view.
        self.get_article_inner(tenant_id, id, true).await
    }

    /// Fetch an article, bumping `view_count` only when `bump_view` is
    /// true. Internal refetches after create/update pass `false` so the
    /// write path does not inflate the counter (PMS-195: a single
    /// create-then-return or update-then-return previously double-counted).
    async fn get_article_inner(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        bump_view: bool,
    ) -> AppResult<KbArticleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, company_ids, created_at, updated_at
               FROM kb_articles WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("KB article".to_string()))?;
        if bump_view {
            // Increment view count on read; fire-and-forget if the bump fails.
            let _ = sqlx::query("UPDATE kb_articles SET view_count = view_count + 1 WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await;
        }
        tx.commit().await?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_article(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        editor: Uuid,
        request: &UpdateKbArticleRequest,
    ) -> AppResult<KbArticleResponse> {
        let prior = self.get_article_inner(tenant_id, id, false).await?;

        // Resolve the company scope for the post-update state (PMS-341).
        // The effective visibility is the requested one when present, else
        // the article's current value. When that is `client_specific` the
        // scope must end up non-empty and tenant-owned (taking the request
        // override when given, otherwise keeping the existing set); for any
        // other visibility the scope is cleared so a downgraded article can
        // never stay portal-visible.
        let effective_visibility = request
            .visibility
            .as_deref()
            .unwrap_or(prior.visibility.as_str());
        let company_ids: Vec<Uuid> = if effective_visibility == "client_specific" {
            let ids = match &request.company_ids {
                Some(ids) => ids.clone(),
                None => prior.company_ids.clone(),
            };
            if ids.is_empty() {
                return Err(AppError::validation_field(
                    "company_ids",
                    "client_specific articles require at least one company",
                ));
            }
            if request.company_ids.is_some() {
                self.validate_company_ids(tenant_id, &ids).await?;
            }
            ids
        } else {
            Vec::new()
        };

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE kb_articles SET
                title = COALESCE($3, title),
                slug = COALESCE($4, slug),
                content = COALESCE($5, content),
                summary = COALESCE($6, summary),
                category_id = COALESCE($7, category_id),
                visibility = COALESCE($8, visibility),
                status = COALESCE($9, status),
                tags = COALESCE($10, tags),
                company_ids = $11,
                -- Stamp published_at on the first transition to
                -- 'published'; leave it untouched once set and for
                -- draft / archived transitions.
                published_at = CASE
                    WHEN COALESCE($9, status) = 'published' AND published_at IS NULL
                        THEN NOW()
                    ELSE published_at
                END,
                updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.title)
        .bind(&request.slug)
        .bind(&request.content)
        .bind(&request.summary)
        .bind(request.category_id)
        .bind(&request.visibility)
        .bind(&request.status)
        .bind(&request.tags)
        .bind(&company_ids)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KB article".to_string()));
        }

        // Snapshot the new version when title or content changed.
        let title_changed = request.title.is_some() && request.title.as_ref() != Some(&prior.title);
        let content_changed =
            request.content.is_some() && request.content.as_ref() != Some(&prior.content);
        if title_changed || content_changed {
            Self::snapshot_version(
                &mut tx,
                id,
                request.title.as_ref().unwrap_or(&prior.title),
                request.content.as_ref().unwrap_or(&prior.content),
                editor,
            )
            .await?;
        }

        // PMS-922: the save supersedes this author's draft, so it goes. Only
        // theirs: another editor's in-progress text is not resolved by someone
        // else pressing Save. In the same transaction as the write it
        // supersedes, so a failed commit cannot discard a draft whose article
        // never changed.
        sqlx::query(
            "DELETE FROM kb_article_drafts \
             WHERE tenant_id = $1 AND article_id = $2 AND user_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(editor)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_article_inner(tenant_id, id, false).await
    }

    /// PMS-922: upsert the caller's draft for `article_id`.
    ///
    /// Writes NO `kb_article_versions` row, which is the entire point: autosave
    /// against `update_article` would append a revision per interval and bury
    /// the real edits. Nothing here is ever promoted to a version; a draft is
    /// superseded by a real save, which deletes it.
    ///
    /// Reads the article first so a draft cannot become a way to write against
    /// an article the caller cannot open, and so the row's `article_id` FK is
    /// never the thing that reports a wrong id.
    pub async fn save_draft(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        user_id: Uuid,
        request: &SaveKbDraftRequest,
    ) -> AppResult<KbDraftResponse> {
        self.get_article_inner(tenant_id, article_id, false).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let updated_at: DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO kb_article_drafts (tenant_id, article_id, user_id, title, content)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, article_id, user_id)
            DO UPDATE SET title = EXCLUDED.title,
                          content = EXCLUDED.content,
                          updated_at = NOW()
            RETURNING updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(user_id)
        .bind(&request.title)
        .bind(&request.content)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(KbDraftResponse {
            article_id,
            title: request.title.clone(),
            content: request.content.clone(),
            updated_at,
        })
    }

    /// The caller's draft for `article_id`, if they have one.
    pub async fn get_draft(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Option<KbDraftResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT title, content, updated_at FROM kb_article_drafts \
             WHERE tenant_id = $1 AND article_id = $2 AND user_id = $3",
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        Ok(row.map(|(title, content, updated_at)| KbDraftResponse {
            article_id,
            title,
            content,
            updated_at,
        }))
    }

    /// Discard the caller's draft. Idempotent: discarding one that is already
    /// gone is a success, because the caller's intent is satisfied either way.
    pub async fn delete_draft(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "DELETE FROM kb_article_drafts \
             WHERE tenant_id = $1 AND article_id = $2 AND user_id = $3",
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Append a new monotonic version row for `article_id` inside an open
    /// transaction. Shared by `update_article` (snapshot-on-edit) and
    /// `restore_article_version` (snapshot-on-restore) so the
    /// `MAX(version_number) + 1` numbering stays in one place.
    async fn snapshot_version(
        tx: &mut sqlx::PgConnection,
        article_id: Uuid,
        title: &str,
        content: &str,
        editor: Uuid,
    ) -> AppResult<i32> {
        let next: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM kb_article_versions WHERE article_id = $1",
        )
        .bind(article_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO kb_article_versions
               (article_id, version_number, title, content, edited_by_id)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(article_id)
        .bind(next)
        .bind(title)
        .bind(content)
        .bind(editor)
        .execute(&mut *tx)
        .await?;
        Ok(next)
    }

    /// Restore a prior version's `title`/`content` onto the live article
    /// and record the restore as a NEW monotonic version (so the history
    /// is append-only and the restore itself is auditable). Tenant-scoped:
    /// the article must belong to `tenant_id` and the version must belong
    /// to that article.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn restore_article_version(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        version_number: i32,
        editor: Uuid,
    ) -> AppResult<KbArticleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Confirm the article is in this tenant before touching versions.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(article_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("KB article".to_string()));
        }

        let snapshot: Option<(String, String)> = sqlx::query_as(
            r#"SELECT title, content FROM kb_article_versions
               WHERE article_id = $1 AND version_number = $2"#,
        )
        .bind(article_id)
        .bind(version_number)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((title, content)) = snapshot else {
            return Err(AppError::NotFound("KB article version".to_string()));
        };

        sqlx::query(
            r#"UPDATE kb_articles
               SET title = $3, content = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(&title)
        .bind(&content)
        .execute(&mut *tx)
        .await?;
        // The restore lands as a fresh version so editing still snapshots
        // on top of it (monotonic numbering preserved).
        Self::snapshot_version(&mut tx, article_id, &title, &content, editor).await?;
        tx.commit().await?;
        self.get_article_inner(tenant_id, article_id, false).await
    }

    /// Record a `helpful` vote for `user_id` on a tenant-scoped article.
    ///
    /// Thin wrapper over [`record_vote`](Self::record_vote) so existing
    /// callers keep a stable name; the toggle / mutual-exclusion semantics
    /// live in `record_vote`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn increment_helpful(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        user_id: Uuid,
    ) -> AppResult<KbArticleFeedbackResponse> {
        self.record_vote(tenant_id, id, user_id, "helpful").await
    }

    /// Record a `not_helpful` vote for `user_id` on a tenant-scoped
    /// article. Thin wrapper over [`record_vote`](Self::record_vote).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn increment_not_helpful(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        user_id: Uuid,
    ) -> AppResult<KbArticleFeedbackResponse> {
        self.record_vote(tenant_id, id, user_id, "not_helpful")
            .await
    }

    /// Record (or toggle) one user's vote on a tenant-scoped article and
    /// return the recomputed tallies plus the caller's resulting vote.
    ///
    /// One vote per user account, mutually exclusive between `helpful` and
    /// `not_helpful`, toggleable. In a single transaction:
    ///
    /// 1. Resolve the article (tenant-scoped) so a missing / wrong-tenant
    ///    article is a clean 404 and FK targets are guaranteed to exist.
    /// 2. Read the user's existing vote, if any.
    /// 3. Toggle: if it equals `vote`, DELETE the row (un-vote); otherwise
    ///    UPSERT to `vote` (insert, or flip an opposite vote in place).
    /// 4. Recompute `helpful` / `not_helpful` as `COUNT(*)` over this
    ///    table for the article (so counts can never exceed the number of
    ///    distinct voters).
    /// 5. Sync the denormalized `kb_articles` counter columns to those
    ///    recomputed values so list / detail reads stay join-free and the
    ///    cache cannot drift.
    ///
    /// `vote` is always one of the two literals the handlers pass; it is
    /// bound as a parameter (never interpolated) and the CHECK constraint
    /// rejects anything else.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn record_vote(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        user_id: Uuid,
        vote: &str,
    ) -> AppResult<KbArticleFeedbackResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Tenant-scoped existence check: 404 if the article is missing or
        // belongs to another tenant.
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM kb_articles WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(article_id)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("KB article".to_string()));
        }

        let existing: Option<String> = sqlx::query_scalar(
            "SELECT vote FROM kb_article_votes WHERE article_id = $1 AND user_id = $2",
        )
        .bind(article_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let my_vote: Option<String> = if existing.as_deref() == Some(vote) {
            // Same vote again -> un-vote (toggle off).
            sqlx::query("DELETE FROM kb_article_votes WHERE article_id = $1 AND user_id = $2")
                .bind(article_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            None
        } else {
            // New vote, or switch from the opposite vote, in one statement.
            sqlx::query(
                r#"INSERT INTO kb_article_votes
                       (tenant_id, article_id, user_id, vote)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (article_id, user_id)
                   DO UPDATE SET vote = EXCLUDED.vote, updated_at = NOW()"#,
            )
            .bind(tenant_id)
            .bind(article_id)
            .bind(user_id)
            .bind(vote)
            .execute(&mut *tx)
            .await?;
            Some(vote.to_string())
        };

        // Recompute both tallies from the votes table (source of truth).
        let (helpful, not_helpful): (i64, i64) = sqlx::query_as(
            r#"SELECT
                   COUNT(*) FILTER (WHERE vote = 'helpful'),
                   COUNT(*) FILTER (WHERE vote = 'not_helpful')
               FROM kb_article_votes
               WHERE article_id = $1"#,
        )
        .bind(article_id)
        .fetch_one(&mut *tx)
        .await?;
        let helpful = helpful as i32;
        let not_helpful = not_helpful as i32;

        // Sync the denormalized caches on kb_articles so list / detail
        // keep showing counts without a join.
        sqlx::query(
            r#"UPDATE kb_articles
               SET helpful_count = $3, not_helpful_count = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(helpful)
        .bind(not_helpful)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(KbArticleFeedbackResponse {
            id: article_id,
            helpful_count: helpful,
            not_helpful_count: not_helpful,
            my_vote,
        })
    }

    /// Read the current tallies for a tenant-scoped article plus the
    /// caller's own vote, without mutating anything. Backs
    /// `GET /kb/articles/{id}/vote` so the client can render the active
    /// thumb state on load.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_article_vote(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<KbArticleFeedbackResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(Uuid, Option<i32>, Option<i32>)> = sqlx::query_as(
            r#"SELECT id, helpful_count, not_helpful_count
               FROM kb_articles
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, helpful, not_helpful)) = row else {
            return Err(AppError::NotFound("KB article".to_string()));
        };

        let my_vote: Option<String> = sqlx::query_scalar(
            "SELECT vote FROM kb_article_votes WHERE article_id = $1 AND user_id = $2",
        )
        .bind(article_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        Ok(KbArticleFeedbackResponse {
            id,
            helpful_count: helpful.unwrap_or(0),
            not_helpful_count: not_helpful.unwrap_or(0),
            my_vote,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_article(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM kb_articles WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KB article".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_article_versions(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbArticleVersionResponse>, u64)> {
        // Verify article belongs to tenant.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(article_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("KB article".to_string()));
        }
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_versions WHERE article_id = $1")
                .bind(article_id)
                .fetch_one(&mut *tx)
                .await?;
        let rows = sqlx::query_as::<_, VersionRow>(
            r#"SELECT id, article_id, version_number, title, content, edited_by_id, created_at
               FROM kb_article_versions WHERE article_id = $1
               ORDER BY version_number DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(article_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Portal single-article read for a specific customer contact. Enforces
    /// the same publish + visibility rules as
    /// [`Self::list_portal_articles_for_company`]: `status = 'published'` AND
    /// (`visibility = 'public'` OR `visibility = 'client_specific'` with the
    /// caller's `company_id` in `company_ids`). A stored-but-not-visible
    /// article returns 404 rather than 403 so the portal never confirms an
    /// article exists outside the contact's scope.
    ///
    /// Does NOT bump `view_count`: the agent-side `get_article` counts staff
    /// reads, and folding portal reads into the same counter would let a
    /// customer inflate a "popular article" signal the operator does not
    /// want the caller to influence. Add a separate portal-read counter if
    /// that signal ever ships.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, id = %id))]
    pub async fn get_portal_article(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        id: Uuid,
    ) -> AppResult<KbArticleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, company_ids, created_at, updated_at
               FROM kb_articles
               WHERE tenant_id = $1
                 AND id = $2
                 AND status = 'published'
                 AND (
                       visibility = 'public'
                    OR (visibility = 'client_specific' AND $3 = ANY(company_ids))
                 )"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("KB article".to_string()))?;
        Ok(row.into())
    }

    /// Portal feed for a specific customer contact (PMS-84 / PMS-32).
    ///
    /// This is the contact-facing query and the only portal-visible feed:
    /// a `client_specific` article is only
    /// returned when the caller's `company_id` is listed in the article's
    /// `company_ids` array. `public` articles are always included. The
    /// `company_id` is taken from the authenticated portal contact's JWT
    /// claim (`CurrentContact.company_id`), so the scoping cannot be
    /// widened by the client.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn list_portal_articles_for_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbArticleResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM kb_articles
               WHERE tenant_id = $1 AND status = 'published'
                 AND (
                       visibility = 'public'
                    OR (visibility = 'client_specific' AND $2 = ANY(company_ids))
                 )"#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, company_ids, created_at, updated_at
               FROM kb_articles
               WHERE tenant_id = $1 AND status = 'published'
                 AND (
                       visibility = 'public'
                    OR (visibility = 'client_specific' AND $2 = ANY(company_ids))
                 )
               ORDER BY updated_at DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-485: list KB articles ordered by how many tickets cite them
    /// as `source_kb_article_id`, restricted to the tenant + a recency
    /// window (`since`). The partial index added in PMS-452 migration
    /// 068 (`(tenant_id, source_kb_article_id) WHERE
    /// source_kb_article_id IS NOT NULL`) keeps the predicate selective.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, limit, since = ?since))]
    pub async fn list_top_ticket_driving_articles(
        &self,
        tenant_id: TenantId,
        since: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> AppResult<Vec<TopTicketDrivingArticleRow>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
            r#"SELECT a.id, a.title, COUNT(t.id)::bigint AS ticket_count
               FROM tickets t
               JOIN kb_articles a ON a.id = t.source_kb_article_id
               WHERE t.tenant_id = $1
                 AND t.source_kb_article_id IS NOT NULL
                 AND t.created_at >= $2
               GROUP BY a.id, a.title
               ORDER BY ticket_count DESC, a.title ASC
               LIMIT $3"#,
        )
        .bind(tenant_id)
        .bind(since)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, title, ticket_count)| TopTicketDrivingArticleRow {
                id,
                title,
                ticket_count,
            })
            .collect())
    }
}

#[derive(sqlx::FromRow)]
struct CatRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    parent_id: Option<Uuid>,
    slug: String,
    visibility: Option<String>,
    sort_order: Option<i32>,
}

impl From<CatRow> for KbCategoryResponse {
    fn from(r: CatRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            parent_id: r.parent_id,
            slug: r.slug,
            visibility: r.visibility.unwrap_or_else(|| "internal".into()),
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ArticleRow {
    id: Uuid,
    title: String,
    slug: String,
    content: String,
    summary: Option<String>,
    category_id: Option<Uuid>,
    visibility: Option<String>,
    status: Option<String>,
    author_id: Uuid,
    view_count: Option<i32>,
    helpful_count: Option<i32>,
    not_helpful_count: Option<i32>,
    published_at: Option<chrono::DateTime<chrono::Utc>>,
    tags: Option<Vec<String>>,
    company_ids: Option<Vec<Uuid>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ArticleRow> for KbArticleResponse {
    fn from(r: ArticleRow) -> Self {
        Self {
            id: r.id,
            title: r.title,
            slug: r.slug,
            content: r.content,
            summary: r.summary,
            category_id: r.category_id,
            visibility: r.visibility.unwrap_or_else(|| "internal".into()),
            status: r.status.unwrap_or_else(|| "draft".into()),
            author_id: r.author_id,
            view_count: r.view_count.unwrap_or(0),
            helpful_count: r.helpful_count.unwrap_or(0),
            not_helpful_count: r.not_helpful_count.unwrap_or(0),
            published_at: r.published_at,
            tags: r.tags.unwrap_or_default(),
            company_ids: r.company_ids.unwrap_or_default(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: Uuid,
    article_id: Uuid,
    version_number: i32,
    title: String,
    content: String,
    edited_by_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<VersionRow> for KbArticleVersionResponse {
    fn from(r: VersionRow) -> Self {
        Self {
            id: r.id,
            article_id: r.article_id,
            version_number: r.version_number,
            title: r.title,
            content: r.content,
            edited_by_id: r.edited_by_id,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// PMS-732: MEASURED DURATION FOR AN ARTICLE
// ============================================================================

/// What the tracked time says a request documented by this article actually
/// takes.
///
/// Every measurement field is `Option` and they move together: a request type
/// nobody has tracked time against reports `null`, not zero. Zero minutes
/// would be a measurement, and putting a confident "0 min" on an article is
/// worse than the hand-written guess this is meant to replace.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArticleMeasuredDuration {
    pub from: chrono::NaiveDate,
    pub to: chrono::NaiveDate,
    /// Tickets with tracked time in the period, across every request type
    /// pointing at this article. The sample the average is drawn from.
    pub ticket_count: Option<i64>,
    pub total_minutes: Option<i64>,
    pub average_minutes: Option<f64>,
}

/// Default window for the article figure: a trailing 90 days.
///
/// Deliberately NOT the calendar month `/reports/request-types` defaults to,
/// because the two answer different questions. The report is period
/// accounting ("what did this month cost"), so a calendar boundary is the
/// right unit. The article figure is an ESTIMATE for the person about to do
/// the work, and an estimate needs a sample: on the 2nd of the month a
/// calendar-month window would report "no data" for almost every article,
/// which is accurate and useless. Both responses state the period they cover,
/// so neither number is ambiguous.
const ARTICLE_DURATION_WINDOW_DAYS: i64 = 90;

impl KbService {
    /// Measured duration for the request types documented by `article_id`.
    ///
    /// Walks time_entries -> tickets -> form_submissions -> form_definitions,
    /// so only tickets that came from a client request submission count. An
    /// ad-hoc ticket in the same category never entered a request form and is
    /// excluded, which is what keeps this a measurement of the request type
    /// rather than of the category.
    pub async fn measured_duration(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        from: Option<chrono::NaiveDate>,
        to: Option<chrono::NaiveDate>,
    ) -> AppResult<ArticleMeasuredDuration> {
        let today = chrono::Utc::now().date_naive();
        let (from, to) = (
            from.unwrap_or_else(|| today - chrono::Duration::days(ARTICLE_DURATION_WINDOW_DAYS)),
            to.unwrap_or(today),
        );

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(article_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("Article".to_string()));
        }

        let (ticket_count, total_minutes): (i64, Option<i64>) = sqlx::query_as(
            r#"SELECT COUNT(DISTINCT te.ticket_id),
                      SUM(te.duration_minutes)::bigint
               FROM form_definitions d
               JOIN form_submissions s
                 ON s.form_definition_id = d.id
                AND s.tenant_id = d.tenant_id
                AND s.ticket_id IS NOT NULL
               JOIN time_entries te
                 ON te.ticket_id = s.ticket_id
                AND te.tenant_id = d.tenant_id
                AND te.date BETWEEN $3 AND $4
               WHERE d.tenant_id = $1 AND d.kb_article_id = $2"#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(from)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let has_data = ticket_count > 0 && total_minutes.is_some();
        Ok(ArticleMeasuredDuration {
            from,
            to,
            ticket_count: has_data.then_some(ticket_count),
            total_minutes: has_data.then(|| total_minutes.unwrap_or(0)),
            average_minutes: has_data
                .then(|| total_minutes.unwrap_or(0) as f64 / ticket_count as f64),
        })
    }
}
