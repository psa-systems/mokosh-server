-- Reseed the notification templates migration 023 inserted (PMS-702).
--
-- Two defects made every one of those templates unusable:
--
--   1. The bodies were plain single-quoted literals, so with
--      standard_conforming_strings on the `\n` sequences were stored as a
--      literal backslash + n and the mail arrived as one long line.
--      Migration 021 avoids this with E'...' literals; so does this one.
--   2. Every placeholder was dotted (`{{ticket.number}}`).
--      render_template (src/modules/notifications/service.rs) does a flat
--      `context.get(key)` with no path traversal and re-emits unresolved
--      braces verbatim, so those keys could never resolve.
--
-- Migrations are immutable, so 023 is left alone and the rows are rewritten
-- here. The flat key names below define the contract the dispatch sites for
-- these five events must satisfy (they do not exist yet); they follow the
-- existing ticket.note_added context (ticket_number, ticket_title, content).
--
-- Each UPDATE is guarded on the dotted placeholder still being present, so a
-- row an operator has already customized through the CRUD API is left alone,
-- and re-running is a no-op. No tenant filter: 023 seeds only the default
-- tenant, but any copy of these rows has the same defect.

-- ticket.created (email)
UPDATE notification_templates SET
    subject = 'New Ticket #{{ticket_number}}: {{ticket_title}}',
    body_text = E'A new ticket has been created.\n\nTicket #: {{ticket_number}}\nTitle: {{ticket_title}}\nPriority: {{ticket_priority}}\nCompany: {{company_name}}\n\nDescription:\n{{ticket_description}}\n\nView ticket: {{ticket_url}}',
    body_html = '<h2>New Ticket Created</h2><p><strong>Ticket #:</strong> {{ticket_number}}<br><strong>Title:</strong> {{ticket_title}}<br><strong>Priority:</strong> {{ticket_priority}}<br><strong>Company:</strong> {{company_name}}</p><h3>Description</h3><p>{{ticket_description}}</p><p><a href="{{ticket_url}}">View Ticket</a></p>'
WHERE event_type = 'ticket.created'
  AND channel_type = 'email'
  AND body_text LIKE '%{{ticket.number}}%';

-- ticket.assigned (email)
UPDATE notification_templates SET
    subject = 'Ticket #{{ticket_number}} assigned to you: {{ticket_title}}',
    body_text = E'You have been assigned a ticket.\n\nTicket #: {{ticket_number}}\nTitle: {{ticket_title}}\nPriority: {{ticket_priority}}\nCompany: {{company_name}}\n\nView ticket: {{ticket_url}}',
    body_html = '<h2>Ticket Assigned to You</h2><p><strong>Ticket #:</strong> {{ticket_number}}<br><strong>Title:</strong> {{ticket_title}}<br><strong>Priority:</strong> {{ticket_priority}}<br><strong>Company:</strong> {{company_name}}</p><p><a href="{{ticket_url}}">View Ticket</a></p>'
WHERE event_type = 'ticket.assigned'
  AND channel_type = 'email'
  AND body_text LIKE '%{{ticket.number}}%';

-- ticket.updated (email)
UPDATE notification_templates SET
    subject = 'Ticket #{{ticket_number}} Updated: {{ticket_title}}',
    body_text = E'Ticket #{{ticket_number}} has been updated.\n\nTitle: {{ticket_title}}\nStatus: {{ticket_status}}\n\nLatest Update:\n{{ticket_last_note}}\n\nView ticket: {{ticket_url}}',
    body_html = '<h2>Ticket Updated</h2><p><strong>Ticket #:</strong> {{ticket_number}}<br><strong>Title:</strong> {{ticket_title}}<br><strong>Status:</strong> {{ticket_status}}</p><h3>Latest Update</h3><p>{{ticket_last_note}}</p><p><a href="{{ticket_url}}">View Ticket</a></p>'
WHERE event_type = 'ticket.updated'
  AND channel_type = 'email'
  AND body_text LIKE '%{{ticket.number}}%';

-- invoice.sent (email)
UPDATE notification_templates SET
    subject = 'Invoice #{{invoice_number}} from {{tenant_name}}',
    body_text = E'Please find attached invoice #{{invoice_number}}.\n\nAmount Due: ${{invoice_total}}\nDue Date: {{invoice_due_date}}\n\nThank you for your business.\n\nView invoice: {{invoice_url}}',
    body_html = '<h2>Invoice #{{invoice_number}}</h2><p><strong>Amount Due:</strong> ${{invoice_total}}<br><strong>Due Date:</strong> {{invoice_due_date}}</p><p>Thank you for your business.</p><p><a href="{{invoice_url}}">View & Pay Invoice</a></p>'
WHERE event_type = 'invoice.sent'
  AND channel_type = 'email'
  AND body_text LIKE '%{{invoice.number}}%';

-- payment.received (email)
UPDATE notification_templates SET
    subject = 'Payment Received - Invoice #{{invoice_number}}',
    body_text = E'We have received your payment of ${{payment_amount}} for Invoice #{{invoice_number}}.\n\nThank you for your payment.\n\nView invoice: {{invoice_url}}',
    body_html = '<h2>Payment Received</h2><p>We have received your payment of <strong>${{payment_amount}}</strong> for Invoice #{{invoice_number}}.</p><p>Thank you for your payment.</p>'
WHERE event_type = 'payment.received'
  AND channel_type = 'email'
  AND body_text LIKE '%{{payment.amount}}%';

-- ticket.created (slack)
UPDATE notification_templates SET
    body_text = E':ticket: *New Ticket #{{ticket_number}}*\n>*{{ticket_title}}*\n>Priority: {{ticket_priority}} | Company: {{company_name}}\n><{{ticket_url}}|View Ticket>'
WHERE event_type = 'ticket.created'
  AND channel_type = 'slack'
  AND body_text LIKE '%{{ticket.number}}%';

-- ticket.assigned (slack)
UPDATE notification_templates SET
    body_text = E':point_right: *Ticket #{{ticket_number}} assigned to {{user_name}}*\n>*{{ticket_title}}*\n><{{ticket_url}}|View Ticket>'
WHERE event_type = 'ticket.assigned'
  AND channel_type = 'slack'
  AND body_text LIKE '%{{ticket.number}}%';

-- ticket.sla_breach (slack)
UPDATE notification_templates SET
    body_text = E':rotating_light: *SLA BREACH - Ticket #{{ticket_number}}*\n>*{{ticket_title}}*\n>Due: {{ticket_sla_due_date}}\n><{{ticket_url}}|View Ticket>'
WHERE event_type = 'ticket.sla_breach'
  AND channel_type = 'slack'
  AND body_text LIKE '%{{ticket.number}}%';
