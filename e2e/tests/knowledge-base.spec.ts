import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Knowledge-base CRUD (PMS-155): category -> article, plus the auto-versioning
// path. The module is tenant-gated (RequireKnowledgeBase, default disabled),
// enabled first via the admin settings route. Category and article deletes are
// manager-gated; the E2E admin satisfies that.
//
// Category and article slugs are unique per tenant, so each create uses a fresh
// runSuffix() as the slug. Records are deleted inline (article before its
// category); every delete runs before the asserts so one failure cannot orphan
// the rest.
test.describe('knowledge-base CRUD', () => {
  test('category + article + versioning lifecycle', async ({ request }) => {
    await enableModule(request, 'knowledge_base');

    // Category (manager-gated). slug must be unique per tenant.
    const catName = runSuffix();
    const createCat = await request.post(routes.kbCategories, {
      data: { name: catName, slug: runSuffix(), visibility: 'internal' },
    });
    expect(createCat.status(), `create kb-category failed: ${await createCat.text()}`).toBe(200);
    const category = (await createCat.json()) as { id: string };
    expect(category.id).toBeTruthy();

    const updCat = await request.put(routes.kbCategory(category.id), {
      data: { name: `${catName}-upd`, slug: runSuffix(), visibility: 'public' },
    });
    expect(updCat.status(), `update kb-category failed: ${await updCat.text()}`).toBe(200);

    // Article in the category.
    const artTitle = runSuffix();
    const createArt = await request.post(routes.kbArticles, {
      data: {
        title: artTitle,
        slug: runSuffix(),
        content: 'e2e initial content',
        category_id: category.id,
        status: 'draft',
      },
    });
    expect(createArt.status(), `create kb-article failed: ${await createArt.text()}`).toBe(200);
    const article = (await createArt.json()) as { id: string; title: string };
    expect(article.id).toBeTruthy();

    // GET increments view_count and returns the article.
    const getArt = await request.get(routes.kbArticle(article.id));
    expect(getArt.status()).toBe(200);

    // Update content -> snapshots a second version.
    const updArt = await request.put(routes.kbArticle(article.id), {
      data: { content: 'e2e updated content', status: 'published' },
    });
    expect(updArt.status(), `update kb-article failed: ${await updArt.text()}`).toBe(200);

    const listArt = await request.get(`${routes.kbArticles}?per_page=200`);
    expect(listArt.status()).toBe(200);
    expect(((await listArt.json()) as { data: Array<{ id: string }> }).data.map((a) => a.id)).toContain(
      article.id,
    );

    // Version history: create made v1, the content update made v2.
    const versions = await request.get(routes.kbArticleVersions(article.id));
    expect(versions.status()).toBe(200);
    const versionRows = ((await versions.json()) as { data: Array<{ version_number: number }> }).data;
    expect(versionRows.length).toBeGreaterThanOrEqual(2);

    // Cleanup; article before its category. Run every delete before asserting.
    const cleanup = [
      await request.delete(routes.kbArticle(article.id)),
      await request.delete(routes.kbCategory(category.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
