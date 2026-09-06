# Portal single-host cutover (MAPPS-649 / PMS-945)

The portal used to be served from a per-MSP subdomain: every MSP tenant got its own `{slug}.client.<apex>` hostname, mokosh-server resolved the tenant from the incoming Host header, and the SPA's `api_base()` derived the API host by stripping the configured `PORTAL_HOST_SUFFIX`.

That shape retired with MAPPS-649. The portal now lives at one host per instance (typically `portal.<apex>`), and every visitor addresses their Company from the URL path (`/portal/{portal_id}/*`). The Company-scoped `portal_id` (9-digit numeric, minted by `grant_portal_access`) resolves to the Company row, which carries the `tenant_id`; no host-header parsing is involved.

## Operator checklist

Before merging the MAPPS-649 PR:

1. **Email every MSP** the new URL and their Company IDs. Sample copy:

   > Your portal URL has moved to `https://portal.<apex>/portal/login`. Enter your Company ID at the sign-in screen. Bookmarks that point at your old `{slug}.client.<apex>` URL will stop working after {DATE}.

   Pull the Company IDs from `companies.portal_id`; the MSP-side "Copy portal link" button on the Company detail page renders the new URL, so a copy-paste from there is authoritative.

2. **Retire the `PORTAL_HOST_SUFFIX` env** on every deploy.
   - mokosh-server: remove the `PORTAL_HOST_SUFFIX=...` line from your `.env`. The field is gone from the code and cargo will not warn, but it is confusing to leave stale env values around.
   - mokosh-apps OCI image: remove `MOKOSH_PORTAL_HOST_SUFFIX` from the container env; set `MOKOSH_PORTAL_HOST` to the bare host (e.g. `portal.psa.systems`). The entrypoint emits `window.__MOKOSH_CONFIG__.portal_host` from that value.

3. **Update Traefik / DNS**.
   - Add a route for `portal.<apex>` -> mokosh-apps (same container that already serves `msp.<apex>`; the SPA distinguishes staff vs portal routes by URL prefix).
   - Remove the `*.client.<apex>` route and its wildcard TLS certificate. Nothing routes there after the PR merges.
   - Remove the wildcard DNS record (`*.client.<apex>`).

4. **CORS allow-list**: if your `CORS_ORIGIN` includes `*.client.<apex>`, replace with `https://portal.<apex>`.

At merge time (this is the hard cut):

5. Merge the PR. Deploy mokosh-server + mokosh-apps simultaneously.
6. Verify `curl -I https://portal.<apex>/portal/login` returns 200. Verify `curl -I https://someslug.client.<apex>/portal/login` returns NXDOMAIN or a Traefik 404 (whichever your DNS/proxy setup produces).
7. Watch mokosh-server logs for `MAPPS-649: no frontend base URL configured; cannot build portal setup URL`. That warning fires only if `TenantService::with_dispatcher` was not called with a `client_origin` (which points at the SPA host). It should not appear.

## What broke on purpose

- Bookmarks + emailed links that hit `*.client.<apex>` return a DNS or TLS error. No 302 shim is in place; that was the explicit design choice for this ticket to force the URL change into a single dated moment instead of a long-tail migration.
- Any tenant admin who kept a bookmark at `https://{slug}.client.<apex>/portal/set-password?token=...` from an old welcome email will not reach the SPA. The email regeneration path (`resend_admin_welcome`) now emits `{portal_host}/portal/set-password?token=...` shape; run a resend for any admin who reports the broken link.
- The `on_portal_host()` client-side helper now compares `window.location.host` against `runtime_config::portal_host` (a bare host). Its call sites (branding paint, slug-hide, permission-message picker) work unchanged.

## What did not change

- `companies.portal_id` schema + values. Every existing Company keeps its 9-digit portal id; the URL shape on the new host is `/portal/{portal_id}/*`.
- `POST /contact/auth/login { portal_id: i64 }` wire shape.
- `/api/v1/*` route surface, tenant scoping, RLS. Contact-plane requests still resolve the tenant from `CallerContext::Contact.company_id`, exactly as they did on the subdomain path (that resolution never went through the Host header).
- Staff-side URLs (`msp.<apex>`). Only the portal side moves.

## Related tickets

- **MAPPS-650**: rename user-facing "Portal ID" -> "Company ID" and collapse the step-1 landing page. Depends on this cutover (branded step-2 on `portal.<apex>` is easier to reason about once the host is single).
- **PMS-916**: shipped the per-Company opaque identifier + magic-link auth this cutover cashes in.
- **PMS-729**: shipped the original per-MSP subdomain shape this cutover retires.
