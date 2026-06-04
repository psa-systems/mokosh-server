-- PMS-128 split: KB categories + articles + versions.

-- ============================================================================
-- KNOWLEDGE BASE
-- ============================================================================

-- KB categories
CREATE TABLE kb_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES kb_categories(id),
    slug VARCHAR(100) NOT NULL,
    visibility VARCHAR(20) DEFAULT 'internal' CHECK (visibility IN ('public', 'internal', 'client_specific')),
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_categories_tenant ON kb_categories(tenant_id);
CREATE INDEX idx_kb_categories_parent ON kb_categories(parent_id);
CREATE INDEX idx_kb_categories_slug ON kb_categories(tenant_id, slug);

-- KB articles
CREATE TABLE kb_articles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    category_id UUID REFERENCES kb_categories(id),
    visibility VARCHAR(20) DEFAULT 'internal' CHECK (visibility IN ('public', 'internal', 'client_specific')),
    company_ids UUID[],
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    author_id UUID NOT NULL REFERENCES users(id),
    -- Engagement
    view_count INTEGER DEFAULT 0,
    helpful_count INTEGER DEFAULT 0,
    not_helpful_count INTEGER DEFAULT 0,
    -- Relations
    related_article_ids UUID[],
    related_ticket_ids UUID[],
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    -- Publishing
    published_at TIMESTAMPTZ,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_articles_tenant ON kb_articles(tenant_id);
CREATE INDEX idx_kb_articles_category ON kb_articles(category_id);
CREATE INDEX idx_kb_articles_status ON kb_articles(tenant_id, status);
CREATE INDEX idx_kb_articles_visibility ON kb_articles(tenant_id, visibility);
CREATE INDEX idx_kb_articles_slug ON kb_articles(tenant_id, slug);
CREATE INDEX idx_kb_articles_content_trgm ON kb_articles USING gin ((title || ' ' || content) gin_trgm_ops);

-- KB article versions
CREATE TABLE kb_article_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    edited_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_versions_article ON kb_article_versions(article_id);
