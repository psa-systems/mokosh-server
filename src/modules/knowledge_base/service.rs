//! Knowledge base service.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

#[derive(Clone)]
pub struct KbService {
    db: Database,
}

impl KbService {
    pub fn new(db: Database) -> Self { Self { db } }

    // PMS-81 categories -------------------------------------------------------
    pub async fn list_categories(&self, tenant_id: Uuid) -> AppResult<Vec<KbCategoryResponse>> {
        let rows = sqlx::query_as::<_, CatRow>(
            r#"SELECT id, name, description, parent_id, slug, visibility, sort_order
               FROM kb_categories WHERE tenant_id = $1 ORDER BY sort_order, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_category(
        &self, tenant_id: Uuid, request: &UpsertKbCategoryRequest,
    ) -> AppResult<KbCategoryResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO kb_categories
               (id, tenant_id, name, description, parent_id, slug, visibility, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(id).bind(tenant_id).bind(&request.name).bind(&request.description)
        .bind(request.parent_id).bind(&request.slug).bind(&request.visibility).bind(request.sort_order)
        .execute(self.db.pool()).await?;
        Ok(KbCategoryResponse {
            id, name: request.name.clone(), description: request.description.clone(),
            parent_id: request.parent_id, slug: request.slug.clone(),
            visibility: request.visibility.clone(), sort_order: request.sort_order,
        })
    }

    pub async fn update_category(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertKbCategoryRequest,
    ) -> AppResult<KbCategoryResponse> {
        let n = sqlx::query(
            r#"UPDATE kb_categories SET
                  name = $3, description = $4, parent_id = $5, slug = $6,
                  visibility = $7, sort_order = $8, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id).bind(&request.name).bind(&request.description)
        .bind(request.parent_id).bind(&request.slug).bind(&request.visibility).bind(request.sort_order)
        .execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("KbCategory".to_string())); }
        Ok(KbCategoryResponse {
            id, name: request.name.clone(), description: request.description.clone(),
            parent_id: request.parent_id, slug: request.slug.clone(),
            visibility: request.visibility.clone(), sort_order: request.sort_order,
        })
    }

    pub async fn delete_category(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM kb_categories WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("KbCategory".to_string())); }
        Ok(())
    }

    // PMS-82 / PMS-83 articles + versions -------------------------------------
    pub async fn list_articles(
        &self, tenant_id: Uuid, filter: &KbArticleFilter,
    ) -> AppResult<Vec<KbArticleResponse>> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.category_id.is_some() { conditions.push(format!("category_id = ${idx}")); idx += 1; }
        if filter.status.is_some() { conditions.push(format!("status = ${idx}")); idx += 1; }
        if filter.visibility.is_some() { conditions.push(format!("visibility = ${idx}")); idx += 1; }
        if filter.q.is_some() { conditions.push(format!("(title ILIKE ${idx} OR content ILIKE ${idx})")); }
        let where_clause = conditions.join(" AND ");
        let query = format!(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, tags, created_at, updated_at
               FROM kb_articles WHERE {where_clause} ORDER BY updated_at DESC"#
        );
        let mut q = sqlx::query_as::<_, ArticleRow>(&query).bind(tenant_id);
        if let Some(v) = filter.category_id { q = q.bind(v); }
        if let Some(v) = &filter.status { q = q.bind(v); }
        if let Some(v) = &filter.visibility { q = q.bind(v); }
        if let Some(v) = &filter.q { q = q.bind(format!("%{v}%")); }
        let rows = q.fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_article(
        &self, tenant_id: Uuid, author_id: Uuid, request: &CreateKbArticleRequest,
    ) -> AppResult<KbArticleResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.pool().begin().await?;
        sqlx::query(
            r#"INSERT INTO kb_articles
               (id, tenant_id, title, slug, content, summary, category_id, visibility,
                status, author_id, tags)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(id).bind(tenant_id).bind(&request.title).bind(&request.slug).bind(&request.content)
        .bind(&request.summary).bind(request.category_id).bind(&request.visibility).bind(&request.status)
        .bind(author_id).bind(&request.tags)
        .execute(&mut *tx).await?;
        // Seed the first version.
        sqlx::query(
            r#"INSERT INTO kb_article_versions
               (article_id, version_number, title, content, edited_by_id)
               VALUES ($1, 1, $2, $3, $4)"#,
        ).bind(id).bind(&request.title).bind(&request.content).bind(author_id)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        self.get_article(tenant_id, id).await
    }

    pub async fn get_article(&self, tenant_id: Uuid, id: Uuid) -> AppResult<KbArticleResponse> {
        let row = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, tags, created_at, updated_at
               FROM kb_articles WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(id).fetch_optional(self.db.pool()).await?
        .ok_or_else(|| AppError::NotFound("KbArticle".to_string()))?;
        // Increment view count on read; fire-and-forget if the bump fails.
        let _ = sqlx::query("UPDATE kb_articles SET view_count = view_count + 1 WHERE id = $1")
            .bind(id).execute(self.db.pool()).await;
        Ok(row.into())
    }

    pub async fn update_article(
        &self, tenant_id: Uuid, id: Uuid, editor: Uuid, request: &UpdateKbArticleRequest,
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
                updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.title).bind(&request.slug).bind(&request.content)
        .bind(&request.summary).bind(request.category_id).bind(&request.visibility)
        .bind(&request.status).bind(&request.tags)
        .execute(&mut *tx).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("KbArticle".to_string())); }

        // Snapshot the new version when title or content changed.
        let title_changed = request.title.is_some() && request.title.as_ref() != Some(&prior.title);
        let content_changed = request.content.is_some() && request.content.as_ref() != Some(&prior.content);
        if title_changed || content_changed {
            let next: i32 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version_number), 0) + 1 FROM kb_article_versions WHERE article_id = $1",
            ).bind(id).fetch_one(&mut *tx).await?;
            sqlx::query(
                r#"INSERT INTO kb_article_versions
                   (article_id, version_number, title, content, edited_by_id)
                   VALUES ($1, $2, $3, $4, $5)"#,
            )
            .bind(id).bind(next)
            .bind(request.title.as_ref().unwrap_or(&prior.title))
            .bind(request.content.as_ref().unwrap_or(&prior.content))
            .bind(editor)
            .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.get_article(tenant_id, id).await
    }

    pub async fn delete_article(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM kb_articles WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("KbArticle".to_string())); }
        Ok(())
    }

    pub async fn list_article_versions(
        &self, tenant_id: Uuid, article_id: Uuid,
    ) -> AppResult<Vec<KbArticleVersionResponse>> {
        // Verify article belongs to tenant.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kb_articles WHERE id = $1 AND tenant_id = $2)",
        ).bind(article_id).bind(tenant_id).fetch_one(self.db.pool()).await?;
        if !exists { return Err(AppError::NotFound("KbArticle".to_string())); }
        let rows = sqlx::query_as::<_, VersionRow>(
            r#"SELECT id, article_id, version_number, title, content, edited_by_id, created_at
               FROM kb_article_versions WHERE article_id = $1
               ORDER BY version_number DESC"#,
        ).bind(article_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // PMS-84 portal-visible helper -------------------------------------------
    pub async fn list_portal_articles(&self, tenant_id: Uuid) -> AppResult<Vec<KbArticleResponse>> {
        let rows = sqlx::query_as::<_, ArticleRow>(
            r#"SELECT id, title, slug, content, summary, category_id, visibility, status,
                      author_id, view_count, helpful_count, tags, created_at, updated_at
               FROM kb_articles
               WHERE tenant_id = $1 AND status = 'published'
                 AND visibility IN ('public', 'client_specific')
               ORDER BY updated_at DESC"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

#[derive(sqlx::FromRow)]
struct CatRow {
    id: Uuid, name: String, description: Option<String>, parent_id: Option<Uuid>,
    slug: String, visibility: Option<String>, sort_order: Option<i32>,
}

impl From<CatRow> for KbCategoryResponse {
    fn from(r: CatRow) -> Self {
        Self {
            id: r.id, name: r.name, description: r.description, parent_id: r.parent_id,
            slug: r.slug,
            visibility: r.visibility.unwrap_or_else(|| "internal".into()),
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ArticleRow {
    id: Uuid, title: String, slug: String, content: String, summary: Option<String>,
    category_id: Option<Uuid>, visibility: Option<String>, status: Option<String>,
    author_id: Uuid,
    view_count: Option<i32>, helpful_count: Option<i32>,
    tags: Option<Vec<String>>,
    created_at: chrono::DateTime<chrono::Utc>, updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ArticleRow> for KbArticleResponse {
    fn from(r: ArticleRow) -> Self {
        Self {
            id: r.id, title: r.title, slug: r.slug, content: r.content, summary: r.summary,
            category_id: r.category_id,
            visibility: r.visibility.unwrap_or_else(|| "internal".into()),
            status: r.status.unwrap_or_else(|| "draft".into()),
            author_id: r.author_id,
            view_count: r.view_count.unwrap_or(0),
            helpful_count: r.helpful_count.unwrap_or(0),
            tags: r.tags.unwrap_or_default(),
            created_at: r.created_at, updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: Uuid, article_id: Uuid, version_number: i32,
    title: String, content: String, edited_by_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<VersionRow> for KbArticleVersionResponse {
    fn from(r: VersionRow) -> Self {
        Self {
            id: r.id, article_id: r.article_id, version_number: r.version_number,
            title: r.title, content: r.content, edited_by_id: r.edited_by_id,
            created_at: r.created_at,
        }
    }
}
