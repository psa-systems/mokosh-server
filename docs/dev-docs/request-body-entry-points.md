# Request-body entry points and the PMS-924 sanitizer

Every way a caller's bytes enter this server as a request body, and what
`utils::text::sanitize_json_body` does to each. PMS-924 added that layer to
guarantee "a value that looks the same to a person is the same value in the
database"; this file is the boundary of the guarantee, so a reviewer can see
what is covered without re-deriving it, and so a contributor adding a route
knows which column their route lands in.

The classification is derived from the shape of the code, not from a list of
routes. These four greps produce the whole set; re-run them when adding a body
extractor, and note the count is derivable, so it is deliberately not written
into the table below:

```
rg 'Json\([a-z_]+\): Json<' src/          # JSON extractor handlers
rg ':\s*(axum::)?(body::)?Bytes,' src/    # raw-byte handlers
rg ':\s*Multipart,' src/                  # multipart uploads
rg ': Form<|body: String|: axum::body::Body' src/   # other body extractors
```

## Classification

| Entry point | Where | Body | Verdict |
| --- | --- | --- | --- |
| PSA `Json<T>` handlers (`/api/v1/*`) | `src/modules/*/routes.rs` | JSON | **covered-by-the-layer**. Sanitized before the extractor, at every depth, keys and values. |
| Portal `Json<T>` handlers (`/api/v1/portal/*`) | `src/modules/portal/routes.rs`, `src/modules/tickets/attachments.rs` | JSON | **covered-by-the-layer**. The layer is mounted on the outer router, so it sees the portal nest too; the credential endpoints are covered by the secret-field exemption, not by a path exemption. |
| Public request-form submission (`POST /api/v1/public/request-forms/{token}`) | `src/modules/forms/public_routes.rs` | JSON | **covered-by-the-layer**. This is the unauthenticated surface a client pastes into from an email, so it is the most likely source of a pasted invisible character. |
| Email-to-ticket intake (`POST /api/v1/email-intake`) | `src/modules/email_intake/routes.rs` | JSON | **covered-by-the-layer**. `subject` and `body_text` become a ticket title and description and are sanitized like any other text. `content_base64` is sanitized too and is unaffected in practice: the base64 alphabet contains none of the removed characters, so only edge whitespace can change, which makes decoding more likely to succeed rather than less. |
| Tenant data import (`POST /api/v1/data/import`) | `src/modules/data_transfer/mod.rs` | JSON, 25 MB `DefaultBodyLimit` | **covered-by-the-layer**. `MAX_SANITIZED_JSON_BYTES` is set to that same 25 MB so the largest body the server accepts is still sanitized; a body declaring more is forwarded unbuffered and the route's own limit rejects it. |
| Bunyip account-deleted webhook | `src/modules/auth/bunyip_webhook.rs` | JSON, HMAC over raw bytes | **not-applicable**: rewriting one byte invalidates the `X-Webhook-Signature` and the request 401s. Exempt by prefix in `RAW_BODY_PATHS`. The payload is machine-generated, not typed. |
| Stripe webhook | `src/modules/billing/stripe_webhook.rs` | JSON, HMAC over raw bytes | **not-applicable**, same reason (`Stripe-Signature`). Exempt by prefix. |
| RMM alert ingest (`POST /api/v1/rmm/alerts`) | `src/modules/rmm/routes.rs` | JSON, HMAC over raw bytes | **not-applicable**, same reason (`X-Signature`; PMS-195 already documents why the handler compares against the wire bytes). Exempt by exact path, so the rest of `/api/v1/rmm/*` stays sanitized. |
| Ticket-note attachment upload, agent and portal | `src/modules/tickets/attachments.rs` | `multipart/form-data` | **not-applicable**: an upload is opaque bytes and rewriting one corrupts the file. Not a JSON content type, so it is forwarded byte-identical and never buffered. |
| Tenant logo upload | `src/modules/tenants/routes.rs` | `multipart/form-data` | **not-applicable**, same reason. |
| Credential fields inside any covered body | `SECRET_FIELD_NAMES` in `src/utils/text.rs` | JSON | **fixed-here by exemption**: the subtree under a matching key is skipped at any depth, which is what covers the nested payment-gateway `config` blob. A credential is compared byte for byte against something stored elsewhere, so rewriting one is a failed login with nothing in the log. |
| `validate_phone` | `src/utils/validation.rs` | not a body | **fixed-here**: normalizes before matching its regex, so a value arriving from a path the layer does not cover (a worker, a seeder) behaves the same way. |
| `normalize_phone` / `validate_phone_e164` | `crates/mokosh-types/src/contacts.rs` | not a body | **fixed-here**: the sibling of the above, and the one the contacts and companies DTOs actually run. This is the pair that produced the MAPPS-581 report. |
| Rows written before PMS-924 | the database | not a body | **out of scope, tracked**: the backfill is [PMS-927](https://youtrack.a8n.run/issue/PMS-927), a subtask of PMS-924. Nothing in PMS-924 rewrites an existing row. |

No `Form<T>`, `body: String` or `axum::body::Body` handler exists; if one is
added it lands in the first column and needs a verdict here.

## Adding a route

- A JSON route needs nothing: the layer covers it, which is the point of
  putting it in the router rather than in an extractor.
- A route that HMACs its own raw body needs its prefix in `RAW_BODY_PATHS`, in
  the same change. Without it the signature check starts failing.
- A request field that is a credential needs its name in `SECRET_FIELD_NAMES`,
  in the same change. The list is sorted and binary-searched; a unit test fails
  the build if it stops being sorted and unique.
