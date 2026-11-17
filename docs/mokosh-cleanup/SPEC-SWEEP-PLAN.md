# [spec] umbrella sweep: single-PR plan

Covers all 12 `[spec]` umbrella YT issues for mokosh-server (PMS-1655, 1656,
1658, 1659, 1660, 1661, 1662, 1663, 1664, 1665, 1666, 1669). Each umbrella
is a list of findings produced by the PMS-1592 specification pass; this doc
picks the still-valid, clear-intent ones and tracks them through a single
branch (`integration/2026-11-17-ymd-sweep-2`) that becomes one PR.

"Still-valid" = re-verified against the current main at plan time; findings
already fixed in main are marked `[fixed]` and skipped. "Intent unclear"
findings that need a product decision are left for the issue owner and
marked `[defer]`.

Branch model: the integration branch already has 14 merged fix branches
from the earlier run of this session. New fixes land as direct commits on
top, one per finding, each with its `#PMS-xxxx` footer so YouTrack links
the commit back.

Legend: `[done]` fixed earlier this session, `[do]` planned for this
sweep, `[fixed]` pre-fixed in main, `[defer]` intent unclear.

## PMS-1655 - Configuration registry and boot

- F1 main.rs:624 panic on AppConfig refusal -> return Err like neighbours `[do]`
- F2 VerifierConfig::from_env set-but-invalid silent fallback `[do]`
- F3 oidc_rs::from_values accepts blank issuer/audience `[do]`
- F4 tracing init before `.env` load `[done]` (prior session)
- F5 CLIENT_ORIGIN/HOST/BASE_URL blank-vs-unset `[defer]`
- F6 IP2LOCATION_DB_PATH unreadable warn-and-disable `[defer]`
- F7 .env.example stale prose `[do]` (comment-only sweep)
- F8 config/file.rs load silently ignores unregistered files `[do]`
- F9 bunyip transport failure semantics `[defer]`
- F10 try_refresh lock ordering `[done]` (prior session F4)
- F11 version_check `.build().ok()?` swallow `[do]`
- F12 bad HOST/PORT error message `[do]`
- F13 OUTBOUND_PRIVATE_ALLOWLIST silent CIDR demotion `[defer]`

## PMS-1656 - HTTP interfaces and operator CLI

- F1 branding contact routes middleware `[done]` (prior session)
- F2 sanitize_json_body pre-auth 25 MiB buffer `[defer]` intent unclear
- F3 outbound timeouts billing/contact_sync `[done]` (this session)
- F4 RUST_LOG unparseable silent fallback `[done]` (prior session)
- F5 env file error format `[done]` (prior session)
- F6..F10 all `[defer]` / intent unclear

## PMS-1658 - Auth security controls and identity provider integration

Many waves 1-4 done in prior session + wave-5 this session.

- Wave 5 (bunyip soft_delete race) `[done]` (this session)
- Remaining items covered by earlier waves.

## PMS-1659 - Tenants, platform, members, teams, audit, contact portal

- platform.rs:225-232 ensure_tenant_admin_row swallows 500 `[do]`
- platform.rs:86..471 DB error maps to Unauthorized `[do]`
- tenants/service.rs:2489,2491 TenantRow silent defaults `[do]`
- tenants/identity.rs:72 OrgIdentity branding silent default `[do]`
- tenants/service.rs:292 create_tenant to_value().unwrap_or `[do]`
- tenants/service.rs partial provisioning after tx commit `[defer]` large
- suspend_tenant/activate_tenant rows_affected check `[fixed]` (prior)
- tenants/routes.rs:478-483 get_public_logo blanket 404 `[do]`
- tenants/logo.rs:214-224 read 404 vs I/O error `[do]`
- user_count definitions diverge `[do]`
- Teams F5 clearable description/color `[done]` (this session)
- Teams F6 reactivate-without-name uniqueness probe `[done]` (prior)
- Teams F7 service header + routes.rs 403 vs 404 comment `[do]`
- Audit F1 csv export 100-row clamp `[done]` (this session)
- Audit F2 invitations mail_sent `[done]` (prior)
- Audit F3 invitations archived team log `[done]` (prior)
- contact_portal F1 contact_access_ok swallows DB error `[do]`
- contact_portal F2 middleware session_active DB error `[do]`
- contact_portal F3 notify.dispatch swallowed `[done]` (prior)
- contact_portal F4 magic_link_url in log `[done]` (prior)
- contact_portal F5 branding JSONB silent default `[do]`
- contact_portal F6 notify_access_requested unwrap_or `[do]`
- contact_portal F7 add_cookie HeaderValue::from_str silent `[do]`
- contact_portal F8 reauthenticate empty email label `[defer]`
- contact_portal F9 update_self notification_preferences dropped `[defer]`
- contact_portal F10 success/cancel URL open-redirect `[do]`
- contact_portal F11 payment_methods webhook owner conflict `[defer]`

## PMS-1660 - Billing core, documents, payment providers, delegated issuing

Most done across waves 1-17.

- Waves 8-12 `[done]` (prior session)
- Waves 13-17 `[done]` (this session)
- service.rs:7960,9336-9337 statement NULL write_off_amount `[do]`
- stripe.rs exp_month/exp_year truncation `[done]` (prior)
- stripe.rs:481 refund filter_map silent drop `[done]` (this session)
- paypal.rs:~209 missing expires_in `[done]` (prior)
- Xero/QBO 404 generic wording `[done]` (prior)
- invoice_issuer_credentials.rs parse_blob missing warn `[done]`
- webhook_invoice_issuer.rs signature-check logs `[done]`
- `ignored` vs `refused` distinction on record_gateway_payment `[defer]` large
- Finding 2 decimal_to_minor out-of-range `[do]` (log, don't change signature)
- Finding 6 OAuth blob write-ahead on upsert failure `[defer]` large refactor

## PMS-1661 - Quotes and contracts

- F1 update_line is_taxable `[done]` (prior)
- F2 unknown status -> Draft `[done]` (prior)
- F3 unknown line_type -> Service `[done]` (prior)
- F4 FOR UPDATE on status_of `[done]` (this session)
- F5 sort whitelist `[defer]` intent unclear
- F6 expire_due_contracts renewed never re-expires `[defer]`
- F7 update_contract_item billing_rule derive `[done]` (prior)
- F8 UpsertContractItemRequest unvalidated `[done]` (prior)
- F9 release_hours_in_tx missing balance warn `[done]` (this session)
- F10 consume_hours_in_tx upsert-then-lock `[done]` (prior)
- F11 QuoteDecisionBody notes 2000 char limit `[done]` (prior)
- F12 list_contract_items foreign contract id `[defer]` intent unclear
- F13 create/update_contract FK tenant check `[done]` (prior)
- F14 update_contract end_date >= start_date `[done]` (prior)
- F15 list_quotes `q` ILIKE escape `[done]` (prior)
- F16 ContractRow null status default `[defer]` intent unclear

## PMS-1662 - Time, mileage, expenses, opportunities

- stop_timer worked/billable/day-cap `[do]`
- stop_timer start_time/end_time zone `[do]`
- stop_timer missing time zone silent UTC `[do]`
- approve_timesheet dead `let _` `[do]`
- time/mileage billing_status unwrap_or_default `[do]`
- opportunities load_row no tenant_id filter `[do]`
- opportunities currency byte-length check `[do]`
- opportunities dead `let _ = idx` `[do]`
- expenses audit serialize unwrap_or `[do]`
- expenses pay_bill unknown external_provider silent `[do]`
- Intent unclear: update_time_entry ticket/project COALESCE `[defer]`
- Intent unclear: non-admin user_id rewrite `[defer]`

## PMS-1663 - Contacts and contact sync

Many `[done]` prior session (industry audit, timezone validation, lock capture).

- delete_company 200-with-no-row `[do]`
- delete_site 200-with-no-row `[do]`
- grant_portal_access slug ok().flatten() `[do]`
- grant_portal_access already_credentialled unwrap_or false `[do]`
- send_grant_email logs live secret URL `[done]` (prior session equivalent)
- row conversions unwrap_or_default enums `[do]`
- CompanyRow -> Company branding silent `[do]`
- SiteRow coord parse 0.0 `[do]`
- stray doc/instrument above list_access_requests `[do]`
- resend_portal_invite 400 vs 409 comment `[do]` comment only
- website_probe `let _ =` set_username/set_password `[do]`
- ConnectionRow selected_groups silent default `[do]`
- mark_reconnect_required google-only text `[do]`
- sync.rs apply_fields PhoneType silent coerce `[do]`
- notify_failing recipient-none silent dispatch `[do]`
- file_import.rs load_source storage error `[do]`
- google.rs get error-body unreadable silent `[do]`
- microsoft.rs get odata nextLink host check `[do]`
- icloud.rs apply_membership "Ungrouped" never stamps `[defer]` requires schema/data change
- oauth/microsoft_oauth provider-wrong-wording `[defer]` text audit

## PMS-1664 - Assets, catalog, KB, documentation

- F1 doc on UpdateAssetTemplateRequest `[done]` (this session)
- F2 ILIKE escape `[done]` (prior)
- F3 template foreign-tenant FK `[defer]` intent unclear
- F4 limit clamp `[defer]` documented
- F5 reveal doc path drift `[do]` comment only
- F6 field_changes serialize `[done]` (prior)
- F7 retire case-sensitive `[done]` (prior)
- F8 contact-path report-issue two-tx atomicity `[defer]`
- F9 nil UUID substitute `[done]` (this session)
- F10 create_asset_relationship `[done]` (prior)
- F11 relationship list ORDER BY `[done]` (prior)
- F12 create_credential/configuration items 404 `[done]` (prior)
- F13 asset-type audit `[defer]` intent unclear
- F14 list_assets q `%`/`_` escape `[done]` (prior)
- F15 duplicate-serial scope `[defer]` intent unclear
- F16 dead `let _ = last` `[do]`
- F17 asset-type parent check `[defer]` intent unclear
- F18 kb attachments.rs open_public NotFound vs I/O `[do]`
- F19 ExecutionRow variable_values unwrap_or_default `[do]`
- F20 KB exec "Unknown" starter no-log `[do]`
- F21 KB latest-version RLS-only `[defer]` intent unclear
- F22 KB service.rs template_vars serialize `[do]`
- F23 ArticleRow template_vars from_value `[do]`
- F24 category/article visibility+status free string `[do]`
- F25 update_category/update_article slug uniqueness `[do]`
- F26 measured_duration from>to `[done]` (prior)
- F27 list_comments missing root silent `[defer]` intent unclear
- F28 get_article_vote unwrap_or 0 `[defer]` intent unclear
- F29 doc claims 404 cross-tenant company `[done]` (this session)
- F30 documentation totals discarded `[done]` (prior)

## PMS-1665 - Integrations, RMM, reports, dashboards

Fresh umbrella (not yet touched this session).

- integrations compose status warn log `[do]`
- rmm parse_tactical_agent empty id reject `[do]`
- rmm parse_tactical_alert defaults `[defer]` dead path
- rmm test_connection reachable: true on 401 `[defer]` intent unclear
- rmm severity_rank unknown ranks max `[do]` serious bug
- rmm link_or_create_asset no-asset-type silent Ok `[do]`
- rmm mark_in_progress never expires `[defer]` operational
- rmm create_connection response created_at drift `[do]` minor
- reports time unresolved work_type no-log `[do]`
- reports billing stale company_name comment `[do]` comment only
- reports/custom.rs totals-after-limit `[defer]` intent unclear
- reports/custom.rs out-of-range input clamp `[do]`
- csv_cell formula-prefix injection `[do]` security
- saved_reports/dashboards schedule_get owner check `[do]` leak
- saved_reports materialise_and_enqueue name fallback `[do]`
- saved_reports/dashboards worker tx isolation `[defer]` larger
- saved_reports compiler filters-array silent `[do]`
- saved_reports compiler parse_sort non-array silent `[do]`
- saved_reports compiler coerce_bind_scalar timestamp `[defer]` unverified
- saved_reports compiler BadRequest vs 422 `[do]` label-only
- saved_reports compiler created_by_name COALESCE empty `[do]`
- dashboards CreateSavedDashboardRequest.layout null default `[do]`

## PMS-1666 - Settings, seed, branding, features, data transfer

Fresh umbrella (not yet touched this session).

- seed service existing_task_status_id swallow `[do]`
- seed data.rs demo_tickets filter_map silent `[do]`
- data_transfer seed message count drift `[do]` text
- data_transfer delete-set vs import-set drift `[defer]` design
- data_transfer export lowercase-identifier filter log `[do]`
- status/service.rs backup_for_company try_get decode `[do]`
- status/models.rs UptimeResponse unknown counts `[defer]`
- status IngestStatusRequest.system_name validate `[do]`
- branding/assets.rs read/open 404 vs I/O `[do]`
- branding/mover.rs try_exists unwrap_or false `[do]`
- settings/email.rs selected_kind fallback `[defer]` design
- seed/qa.rs showcase.rs partial dataset `[defer]` design

## PMS-1669 - Migrations and schema comments

- bill_payments payment_method lacks 'paypal' `[defer]` migration decision
- Remaining entries are spec corrections (SPEC prose only, no code
  defect) `[fixed]` by spec update.

Only item here needing code is a new migration widening `bill_payments`.
Skipping until a product decision says whether paypal flows through
expenses or stays receivables-only.

## Branch & PR plan

- Keep going on `integration/2026-11-17-ymd-sweep-2`
- Each finding lands as its own commit with `#PMS-xxxx` footer so YT
  commit-linking still works
- No new feature PRs; nothing landed on individual fix branches, only
  on this integration branch
- Push a single update to the existing PR when all `[do]` findings are
  committed
