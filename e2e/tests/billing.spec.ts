import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany, enableModule, today } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Billing CRUD (PMS-155). The module is tenant-gated (RequireBilling, default
// disabled) and write routes also need a finance-capable role (admin
// satisfies it). Enabled first via the admin settings route.
//
// Coverage is shaped by what can be cleaned up. Tax rates and payments both
// have DELETE routes, so they get a full create/read/update(+delete)
// lifecycle. Invoices have NO delete route, so creating one would leave
// permanent residue - exactly the leak PMS-149/PMS-155 set out to avoid - and
// the spec therefore only smoke-reads the invoice list. See the TODO below.
test.describe('billing CRUD', () => {
  test('tax rate + payment lifecycle; invoices read-only', async ({ request }) => {
    await enableModule(request, 'billing');

    // Tax rate: full CRUD (all routes exist, name-tagged, deletable).
    const trName = runSuffix();
    const createTr = await request.post(routes.taxRates, { data: { name: trName, rate: '8.25' } });
    expect(createTr.status(), `create tax-rate failed: ${await createTr.text()}`).toBe(200);
    const taxRate = (await createTr.json()) as { id: string };
    expect(taxRate.id).toBeTruthy();

    const listTr = await request.get(`${routes.taxRates}?per_page=200`);
    expect(listTr.status()).toBe(200);
    expect(((await listTr.json()) as { data: Array<{ id: string }> }).data.map((r) => r.id)).toContain(
      taxRate.id,
    );

    const updTr = await request.put(routes.taxRate(taxRate.id), {
      data: { name: `${trName}-upd`, rate: '9.5' },
    });
    expect(updTr.status(), `update tax-rate failed: ${await updTr.text()}`).toBe(200);

    // Payment against a company (invoice_id is optional; the service only
    // validates it when present). DELETE /payments/{id} exists, so this stays
    // clean: create -> list -> delete.
    const company = await createCompany(request);
    const createPay = await request.post(routes.payments, {
      data: {
        company_id: company.id,
        payment_date: today(),
        amount: '100',
        payment_method: 'check',
        reference_number: runSuffix(),
      },
    });
    expect(createPay.status(), `create payment failed: ${await createPay.text()}`).toBe(200);
    const payment = (await createPay.json()) as { id: string };
    expect(payment.id).toBeTruthy();

    const listPay = await request.get(`${routes.payments}?company_id=${company.id}`);
    expect(listPay.status()).toBe(200);
    expect(((await listPay.json()) as { data: Array<{ id: string }> }).data.map((p) => p.id)).toContain(
      payment.id,
    );

    // Invoices are read-only here. There is no DELETE /invoices route, so the
    // suite must not create one (the record would be permanent residue).
    // TODO(PMS-155 follow-up): once a delete/void-and-purge invoice route
    // lands, add a full invoice create/read/update lifecycle.
    const listInv = await request.get(`${routes.invoices}?company_id=${company.id}&per_page=50`);
    expect(listInv.status(), `list invoices -> ${listInv.status()}`).toBe(200);

    // Cleanup, reverse-dependency order: the payment references the company.
    // Run every delete before asserting so one failure does not abort the rest
    // and orphan the others (the payment has no run-suffixed name to sweep).
    const cleanup = [
      await request.delete(routes.payment(payment.id)),
      await request.delete(routes.taxRate(taxRate.id)),
      await request.delete(routes.company(company.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
