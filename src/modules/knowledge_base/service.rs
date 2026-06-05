//! Knowledge base service.

use uuid::Uuid;

use crate::db::Database;
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

    // PMS-81 categories -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_categories(
        &self,
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbCategoryResponse>, u64)> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM kb_categories WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
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
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_category(
        &self,
        tenant_id: Uuid,
        request: &UpsertKbCategoryRequest,
    ) -> AppResult<KbCategoryResponse> {
        // Per-tenant unique slug (enforced at the app layer; the
        // `uq_kb_categories_tenant_slug` constraint is the DB backstop).
        let dup: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_categories WHERE tenant_id = $1 AND slug = $2)",
        )
        .bind(tenant_id)
        .bind(&request.slug)
        .fetch_one(self.db.pool())
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
        .execute(self.db.pool())
        .await?;
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
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertKbCategoryRequest,
    ) -> AppResult<KbCategoryResponse> {
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
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KbCategory".to_string()));
        }
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
    pub async fn delete_category(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM kb_categories WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KbCategory".to_string()));
        }
        Ok(())
    }

    // PMS-82 / PMS-83 articles + versions -------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_articles(
        &self,
        tenant_id: Uuid,
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
                      published_at, tags, created_at, updated_at
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
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(self.db.pool())
            .await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_article(
        &self,
        tenant_id: Uuid,
        author_id: Uuid,
        request: &CreateKbArticleRequest,
    ) -> AppResult<KbArticleResponse> {
        // Per-tenant unique slug (app-layer check; the
        // `uq_kb_articles_tenant_slug` constraint is the DB backstop).
        let dup: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE tenant_id = $1 AND slug = $2)",
        )
        .bind(tenant_id)
        .bind(&request.slug)
        .fetch_one(self.db.pool())
        .await?;
        if dup {
            return Err(AppError::Conflict(format!(
                "KbArticle slug '{}' already exists",
                request.slug
            )));
        }
        let id = Uuid::new_v4();
        let mut tx = self.db.pool().begin().await?;
        // Stamp published_at when the article is created already
        // published; leave NULL for draft / archived. `NOW()` is applied
        // in SQL only when status = 'published'.
        let publish_now = request.status == "published";
        sqlx::query(
            r#"INSERT INTO kb_articles
               (id, tenant_id, title, slug, content, summary, category_id, visibility,
                status, author_id, tags, published_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                       CASE WHEN $12 THEN NOW() ELSE NULL END)"#,
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
        tx.commit().await?;
        self.get_article(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_article(&self, tenant_id: Uuid, id: Uuid) -> AppResult<KbArticleResponse> {
        let row = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, created_at, updated_at
               FROM kb_articles WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("KbArticle".to_string()))?;
        // Increment view count on read; fire-and-forget if the bump fails.
        let _ = sqlx::query("UPDATE kb_articles SET view_count = view_count + 1 WHERE id = $1")
            .bind(id)
            .execute(self.db.pool())
            .await;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_article(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        editor: Uuid,
        request: &UpdateKbArticleRequest,
    ) -> AppResult<KbArticleResponse> {
        let prior = self.get_article(tenant_id, id).await?;
        let mut tx = self.db.pool().begin().await?;
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
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KbArticle".to_string()));
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
        tx.commit().await?;
        self.get_article(tenant_id, id).await
    }

    /// Append a new monotonic version row for `article_id` inside an open
    /// transaction. Shared by `update_article` (snapshot-on-edit) and
    /// `restore_article_version` (snapshot-on-restore) so the
    /// `MAX(version_number) + 1` numbering stays in one place.
    async fn snapshot_version(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        article_id: Uuid,
        title: &str,
        content: &str,
        editor: Uuid,
    ) -> AppResult<i32> {
        let next: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM kb_article_versions WHERE article_id = $1",
        )
        .bind(article_id)
        .fetch_one(&mut **tx)
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
        .execute(&mut **tx)
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
        tenant_id: Uuid,
        article_id: Uuid,
        version_number: i32,
        editor: Uuid,
    ) -> AppResult<KbArticleResponse> {
        // Confirm the article is in this tenant before touching versions.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(article_id)
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        if !exists {
            return Err(AppError::NotFound("KbArticle".to_string()));
        }

        let snapshot: Option<(String, String)> = sqlx::query_as(
            r#"SELECT title, content FROM kb_article_versions
               WHERE article_id = $1 AND version_number = $2"#,
        )
        .bind(article_id)
        .bind(version_number)
        .fetch_optional(self.db.pool())
        .await?;
        let Some((title, content)) = snapshot else {
            return Err(AppError::NotFound("KbArticleVersion".to_string()));
        };

        let mut tx = self.db.pool().begin().await?;
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
        self.get_article(tenant_id, article_id).await
    }

    /// Record a `helpful` vote for `user_id` on a tenant-scoped article.
    ///
    /// Thin wrapper over [`record_vote`](Self::record_vote) so existing
    /// callers keep a stable name; the toggle / mutual-exclusion semantics
    /// live in `record_vote`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn increment_helpful(
        &self,
        tenant_id: Uuid,
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
        tenant_id: Uuid,
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
        tenant_id: Uuid,
        article_id: Uuid,
        user_id: Uuid,
        vote: &str,
    ) -> AppResult<KbArticleFeedbackResponse> {
        let mut tx = self.db.pool().begin().await?;

        // Tenant-scoped existence check: 404 if the article is missing or
        // belongs to another tenant.
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM kb_articles WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(article_id)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("KbArticle".to_string()));
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
        tenant_id: Uuid,
        article_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<KbArticleFeedbackResponse> {
        let row: Option<(Uuid, Option<i32>, Option<i32>)> = sqlx::query_as(
            r#"SELECT id, helpful_count, not_helpful_count
               FROM kb_articles
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .fetch_optional(self.db.pool())
        .await?;
        let Some((id, helpful, not_helpful)) = row else {
            return Err(AppError::NotFound("KbArticle".to_string()));
        };

        let my_vote: Option<String> = sqlx::query_scalar(
            "SELECT vote FROM kb_article_votes WHERE article_id = $1 AND user_id = $2",
        )
        .bind(article_id)
        .bind(user_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(KbArticleFeedbackResponse {
            id,
            helpful_count: helpful.unwrap_or(0),
            not_helpful_count: not_helpful.unwrap_or(0),
            my_vote,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_article(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM kb_articles WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("KbArticle".to_string()));
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_article_versions(
        &self,
        tenant_id: Uuid,
        article_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbArticleVersionResponse>, u64)> {
        // Verify article belongs to tenant.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(article_id)
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        if !exists {
            return Err(AppError::NotFound("KbArticle".to_string()));
        }
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_versions WHERE article_id = $1")
                .bind(article_id)
                .fetch_one(self.db.pool())
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
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
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
        tenant_id: Uuid,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<KbArticleResponse>, u64)> {
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
        .fetch_one(self.db.pool())
        .await?;

        let rows = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, not_helpful_count,
                      published_at, tags, created_at, updated_at
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
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
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
