-- Templated knowledge-base articles, server half.
--
-- An article can declare a small schema of variables (name, label,
-- allowed_values[], default), and the new /kb/articles/{id}/render
-- endpoint renders the article's Markdown against a caller-supplied
-- values map (minijinja with its default `{{ }}` / `{% %}` delimiters).
--
-- Stored on the article row rather than a side table so the schema
-- rides along through version restore and the per-tenant unique slug.
-- The default `[]` means an existing article renders byte-identically
-- to its stored content, which the render path short-circuits on.

ALTER TABLE kb_articles
    ADD COLUMN template_variables JSONB NOT NULL DEFAULT '[]'::jsonb;
