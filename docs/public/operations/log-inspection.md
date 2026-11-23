# Log inspection

Mokosh writes structured logs to stdout. A container orchestration layer collects them (docker logs, Loki, CloudWatch, whatever you ship them to). The server has no file logger of its own.

## Log levels

The server respects `RUST_LOG`. The default is `info`.

- `trace`: every request, every SQL statement. Noisy; useful for reproducing a specific flow.
- `debug`: fewer messages per request, still per-request detail. Useful when `info` does not say enough.
- `info`: one line per request (method, path, status, duration) plus notable events (sign-in, document stored, worker started).
- `warn`: something expected went sideways but the server handled it. A warn is not a failure.
- `error`: something failed. Usually paired with a 5xx response or a job that gave up.

A per-module filter works too:
```
RUST_LOG=info,mokosh_server::modules::billing=debug
```

## The request line

Every request at `info` or above carries:

- `method`, `path`, `status`, `duration_ms`.
- `request_id`: a unique id you pass back on a complaint.
- `tenant_id` and `user_id` when known.

A 4xx response carries an error code and message; a 5xx response carries a stack frame summary plus the error code. Both include the `request_id` so a UI "please share this id" bug report is traceable.

## The job runs table

Scheduled jobs (the invoice reminder worker, the contact sync poller, the retention sweep if you run one) write a row to `job_runs` for each run. The row records:

- Job name.
- Started-at and finished-at timestamps.
- Status (`success`, `failed`, `skipped`, `in_progress` while running).
- An error message if it failed.
- A trace id tying the row to the server log.

The SPA's admin surface reads `job_runs` to show a timeline. For an operator, querying the table directly is often faster:

```sql
SELECT started_at, finished_at, status, error_message
  FROM job_runs
  WHERE job_name = 'invoice_reminders'
  ORDER BY started_at DESC
  LIMIT 20;
```

A job that keeps failing shows a pattern in the error messages. A job that stops appearing at all means the scheduler is down (look at the server log for the scheduler's own start line).

## Finding a specific tenant's error

A tenant admin reports "I keep getting 500 on the Clients page". The sequence:

1. Ask for the `request_id` their SPA showed on the error. Most frontends display it; the 500 response body also carries it.
2. Grep the server log for the id:
   ```nu
   docker compose logs server | grep '<the request id>'
   ```
3. The matching line carries the `tenant_id`, `user_id`, path and error code.
4. Follow the surrounding lines (same request id, higher log level) for the stack frame summary.

Without a request id, filter by tenant id and the error code:

```nu
docker compose logs server
  | from json --objects
  | where tenant_id == '<the tenant id>' and level == 'ERROR'
  | last 20
```

## What not to log

- Passwords, API tokens, secrets are never logged. Their fields are redacted at the serializer.
- A SMTP relay password is not logged on `trace`; the SMTP transport logs the connection, not the credential.
- A Stripe webhook body is not logged in full; the signature verification happens before the body is deserialized, so a bad delivery fails at `warn` with only the `event_type`.

If you see a redacted field where you wanted the value, the server is doing the right thing and the value belongs in an audit trail (which does log the operator action that set it), not in the log.

## Log retention

The orchestration layer decides how long to keep log data. The server itself holds no history beyond the process memory; restart the container and the in-process buffer is gone. Audit data persists in the database (the `audit_log` table and the `job_runs` table above); that stays with the database backup.
