-- Mokosh Server Seed Data
-- This migration creates default configuration data

-- Set the tenant context for seeding
SET app.current_tenant = '00000000-0000-0000-0000-000000000001';

-- ============================================================================
-- DEFAULT TICKET STATUSES
-- ============================================================================

INSERT INTO ticket_statuses (tenant_id, name, color, is_closed, is_default, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'New', '#3B82F6', FALSE, TRUE, 1),
('00000000-0000-0000-0000-000000000001', 'Open', '#10B981', FALSE, FALSE, 2),
('00000000-0000-0000-0000-000000000001', 'In Progress', '#F59E0B', FALSE, FALSE, 3),
('00000000-0000-0000-0000-000000000001', 'Waiting on Client', '#8B5CF6', FALSE, FALSE, 4),
('00000000-0000-0000-0000-000000000001', 'Waiting on Vendor', '#EC4899', FALSE, FALSE, 5),
('00000000-0000-0000-0000-000000000001', 'Scheduled', '#06B6D4', FALSE, FALSE, 6),
('00000000-0000-0000-0000-000000000001', 'Resolved', '#22C55E', TRUE, FALSE, 7),
('00000000-0000-0000-0000-000000000001', 'Closed', '#6B7280', TRUE, FALSE, 8);

-- ============================================================================
-- DEFAULT TICKET PRIORITIES
-- ============================================================================

INSERT INTO ticket_priorities (tenant_id, name, color, icon, sla_multiplier, sort_order, is_default) VALUES
('00000000-0000-0000-0000-000000000001', 'Critical', '#EF4444', 'alert-triangle', 0.25, 1, FALSE),
('00000000-0000-0000-0000-000000000001', 'High', '#F97316', 'arrow-up', 0.50, 2, FALSE),
('00000000-0000-0000-0000-000000000001', 'Medium', '#EAB308', 'minus', 1.00, 3, TRUE),
('00000000-0000-0000-0000-000000000001', 'Low', '#22C55E', 'arrow-down', 2.00, 4, FALSE);

-- ============================================================================
-- DEFAULT TICKET TYPES
-- ============================================================================

INSERT INTO ticket_types (tenant_id, name, description, icon, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'Incident', 'Unplanned interruption to service', 'alert-circle', 1),
('00000000-0000-0000-0000-000000000001', 'Service Request', 'Standard request for service', 'clipboard-list', 2),
('00000000-0000-0000-0000-000000000001', 'Problem', 'Root cause of incidents', 'search', 3),
('00000000-0000-0000-0000-000000000001', 'Change Request', 'Request to modify infrastructure', 'refresh-cw', 4),
('00000000-0000-0000-0000-000000000001', 'Project Task', 'Task related to a project', 'folder', 5),
('00000000-0000-0000-0000-000000000001', 'Alert', 'Automated monitoring alert', 'bell', 6);

-- ============================================================================
-- DEFAULT TICKET CATEGORIES
-- ============================================================================

INSERT INTO ticket_categories (tenant_id, parent_id, name, description, sort_order)
VALUES
('00000000-0000-0000-0000-000000000001', NULL, 'Hardware', 'Hardware-related issues', 1),
('00000000-0000-0000-0000-000000000001', NULL, 'Software', 'Software-related issues', 2),
('00000000-0000-0000-0000-000000000001', NULL, 'Network', 'Network and connectivity issues', 3),
('00000000-0000-0000-0000-000000000001', NULL, 'Security', 'Security-related issues', 4),
('00000000-0000-0000-0000-000000000001', NULL, 'Email', 'Email and communication issues', 5),
('00000000-0000-0000-0000-000000000001', NULL, 'Backup', 'Backup and disaster recovery', 6),
('00000000-0000-0000-0000-000000000001', NULL, 'User Management', 'User accounts and access', 7),
('00000000-0000-0000-0000-000000000001', NULL, 'Other', 'Other issues', 99);

-- Insert subcategories
WITH parent_categories AS (
    SELECT id, name FROM ticket_categories WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND parent_id IS NULL
)
INSERT INTO ticket_categories (tenant_id, parent_id, name, sort_order)
SELECT
    '00000000-0000-0000-0000-000000000001',
    pc.id,
    subcategory,
    row_number() OVER (PARTITION BY pc.name)
FROM parent_categories pc
CROSS JOIN (VALUES
    -- Hardware subcategories
    ('Hardware', 'Desktop/Laptop'),
    ('Hardware', 'Server'),
    ('Hardware', 'Printer'),
    ('Hardware', 'Mobile Device'),
    ('Hardware', 'Peripheral'),
    -- Software subcategories
    ('Software', 'Operating System'),
    ('Software', 'Microsoft 365'),
    ('Software', 'Line of Business App'),
    ('Software', 'Browser'),
    ('Software', 'Antivirus'),
    -- Network subcategories
    ('Network', 'Internet'),
    ('Network', 'VPN'),
    ('Network', 'WiFi'),
    ('Network', 'Firewall'),
    ('Network', 'DNS'),
    -- Security subcategories
    ('Security', 'Malware'),
    ('Security', 'Phishing'),
    ('Security', 'Access Control'),
    ('Security', 'Vulnerability'),
    -- Email subcategories
    ('Email', 'Outlook'),
    ('Email', 'Email Delivery'),
    ('Email', 'Spam/Filtering'),
    ('Email', 'Shared Mailbox')
) AS subs(parent_name, subcategory)
WHERE pc.name = subs.parent_name;

-- ============================================================================
-- DEFAULT TICKET QUEUE
-- ============================================================================

INSERT INTO ticket_queues (tenant_id, name, description, color, is_default, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'Service Desk', 'General service desk queue', '#3B82F6', TRUE, 1),
('00000000-0000-0000-0000-000000000001', 'Escalation', 'Escalated tickets', '#EF4444', FALSE, 2),
('00000000-0000-0000-0000-000000000001', 'Projects', 'Project-related tickets', '#8B5CF6', FALSE, 3);

-- ============================================================================
-- DEFAULT WORK TYPES
-- ============================================================================

INSERT INTO work_types (tenant_id, name, description, default_billable, default_rate, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'Remote Support', 'Remote troubleshooting and support', TRUE, 150.00, 1),
('00000000-0000-0000-0000-000000000001', 'On-Site Support', 'On-site troubleshooting and support', TRUE, 175.00, 2),
('00000000-0000-0000-0000-000000000001', 'Project Work', 'Project implementation work', TRUE, 150.00, 3),
('00000000-0000-0000-0000-000000000001', 'Consultation', 'Consulting and advisory services', TRUE, 200.00, 4),
('00000000-0000-0000-0000-000000000001', 'Travel', 'Travel time', TRUE, 75.00, 5),
('00000000-0000-0000-0000-000000000001', 'Training', 'User training', TRUE, 150.00, 6),
('00000000-0000-0000-0000-000000000001', 'Internal', 'Internal non-billable work', FALSE, 0.00, 7),
('00000000-0000-0000-0000-000000000001', 'After Hours', 'After hours support', TRUE, 225.00, 8),
('00000000-0000-0000-0000-000000000001', 'Emergency', 'Emergency support', TRUE, 300.00, 9);

-- ============================================================================
-- DEFAULT TASK STATUSES
-- ============================================================================

INSERT INTO task_statuses (tenant_id, name, color, is_completed, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'To Do', '#6B7280', FALSE, 1),
('00000000-0000-0000-0000-000000000001', 'In Progress', '#3B82F6', FALSE, 2),
('00000000-0000-0000-0000-000000000001', 'Review', '#F59E0B', FALSE, 3),
('00000000-0000-0000-0000-000000000001', 'Done', '#22C55E', TRUE, 4),
('00000000-0000-0000-0000-000000000001', 'Cancelled', '#EF4444', TRUE, 5);

-- ============================================================================
-- DEFAULT ASSET TYPES
-- ============================================================================

INSERT INTO asset_types (tenant_id, name, icon, parent_type_id, custom_fields_schema) VALUES
('00000000-0000-0000-0000-000000000001', 'Workstation', 'monitor', NULL, '[
    {"name": "operating_system", "type": "select", "label": "Operating System", "options": ["Windows 11", "Windows 10", "macOS", "Linux"]},
    {"name": "ram_gb", "type": "number", "label": "RAM (GB)"},
    {"name": "storage_gb", "type": "number", "label": "Storage (GB)"},
    {"name": "processor", "type": "text", "label": "Processor"}
]'),
('00000000-0000-0000-0000-000000000001', 'Laptop', 'laptop', NULL, '[
    {"name": "operating_system", "type": "select", "label": "Operating System", "options": ["Windows 11", "Windows 10", "macOS", "Linux"]},
    {"name": "ram_gb", "type": "number", "label": "RAM (GB)"},
    {"name": "storage_gb", "type": "number", "label": "Storage (GB)"},
    {"name": "processor", "type": "text", "label": "Processor"}
]'),
('00000000-0000-0000-0000-000000000001', 'Server', 'server', NULL, '[
    {"name": "operating_system", "type": "text", "label": "Operating System"},
    {"name": "ram_gb", "type": "number", "label": "RAM (GB)"},
    {"name": "cpu_cores", "type": "number", "label": "CPU Cores"},
    {"name": "is_virtual", "type": "boolean", "label": "Virtual Machine"},
    {"name": "hypervisor", "type": "text", "label": "Hypervisor"}
]'),
('00000000-0000-0000-0000-000000000001', 'Network Device', 'wifi', NULL, '[
    {"name": "device_type", "type": "select", "label": "Device Type", "options": ["Router", "Switch", "Firewall", "Access Point", "Modem"]},
    {"name": "ip_address", "type": "text", "label": "IP Address"},
    {"name": "firmware_version", "type": "text", "label": "Firmware Version"}
]'),
('00000000-0000-0000-0000-000000000001', 'Printer', 'printer', NULL, '[
    {"name": "printer_type", "type": "select", "label": "Printer Type", "options": ["Laser", "Inkjet", "Label", "Multifunction"]},
    {"name": "ip_address", "type": "text", "label": "IP Address"},
    {"name": "is_network", "type": "boolean", "label": "Network Printer"}
]'),
('00000000-0000-0000-0000-000000000001', 'Mobile Device', 'smartphone', NULL, '[
    {"name": "device_type", "type": "select", "label": "Device Type", "options": ["Smartphone", "Tablet"]},
    {"name": "operating_system", "type": "select", "label": "OS", "options": ["iOS", "Android"]},
    {"name": "phone_number", "type": "text", "label": "Phone Number"}
]'),
('00000000-0000-0000-0000-000000000001', 'Software License', 'key', NULL, '[
    {"name": "license_key", "type": "text", "label": "License Key"},
    {"name": "seats", "type": "number", "label": "Number of Seats"},
    {"name": "license_type", "type": "select", "label": "License Type", "options": ["Perpetual", "Subscription", "Per User", "Per Device"]}
]'),
('00000000-0000-0000-0000-000000000001', 'Cloud Service', 'cloud', NULL, '[
    {"name": "service_url", "type": "text", "label": "Service URL"},
    {"name": "admin_url", "type": "text", "label": "Admin URL"},
    {"name": "subscription_id", "type": "text", "label": "Subscription ID"}
]');

-- ============================================================================
-- DEFAULT BUSINESS HOURS
-- ============================================================================

INSERT INTO business_hours (tenant_id, name, timezone, schedule, is_default) VALUES
('00000000-0000-0000-0000-000000000001', 'Standard Business Hours', 'America/New_York', '{
    "0": null,
    "1": {"start": "08:00", "end": "17:00"},
    "2": {"start": "08:00", "end": "17:00"},
    "3": {"start": "08:00", "end": "17:00"},
    "4": {"start": "08:00", "end": "17:00"},
    "5": {"start": "08:00", "end": "17:00"},
    "6": null
}', TRUE);

-- ============================================================================
-- DEFAULT SLA POLICY
-- ============================================================================

INSERT INTO sla_policies (tenant_id, name, description, business_hours_id, is_default)
SELECT
    '00000000-0000-0000-0000-000000000001',
    'Standard SLA',
    'Default service level agreement',
    id,
    TRUE
FROM business_hours
WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND is_default = TRUE;

-- Insert SLA targets
WITH sla AS (
    SELECT id FROM sla_policies WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND is_default = TRUE
),
priorities AS (
    SELECT id, name FROM ticket_priorities WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
)
INSERT INTO sla_targets (sla_policy_id, priority_id, first_response_hours, resolution_hours, operational_hours)
SELECT
    sla.id,
    p.id,
    CASE p.name
        WHEN 'Critical' THEN 0.5
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 4
        WHEN 'Low' THEN 8
    END,
    CASE p.name
        WHEN 'Critical' THEN 4
        WHEN 'High' THEN 8
        WHEN 'Medium' THEN 24
        WHEN 'Low' THEN 72
    END,
    CASE p.name
        WHEN 'Critical' THEN '24x7'
        ELSE 'business_hours'
    END
FROM sla, priorities p;

-- ============================================================================
-- DEFAULT RATE CARD
-- ============================================================================

INSERT INTO rate_cards (tenant_id, name, description, is_default) VALUES
('00000000-0000-0000-0000-000000000001', 'Standard Rates', 'Default rate card for all clients', TRUE);

-- Insert rate card items
WITH rc AS (
    SELECT id FROM rate_cards WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND is_default = TRUE
),
wt AS (
    SELECT id, name, default_rate FROM work_types WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
)
INSERT INTO rate_card_items (rate_card_id, work_type_id, hourly_rate, after_hours_rate, emergency_rate)
SELECT
    rc.id,
    wt.id,
    wt.default_rate,
    wt.default_rate * 1.5,
    wt.default_rate * 2
FROM rc, wt;

-- ============================================================================
-- DEFAULT KB CATEGORIES
-- ============================================================================

INSERT INTO kb_categories (tenant_id, name, description, slug, visibility, sort_order) VALUES
('00000000-0000-0000-0000-000000000001', 'Getting Started', 'Onboarding and getting started guides', 'getting-started', 'public', 1),
('00000000-0000-0000-0000-000000000001', 'How-To Guides', 'Step-by-step instructions', 'how-to-guides', 'public', 2),
('00000000-0000-0000-0000-000000000001', 'Troubleshooting', 'Common problems and solutions', 'troubleshooting', 'public', 3),
('00000000-0000-0000-0000-000000000001', 'FAQs', 'Frequently asked questions', 'faqs', 'public', 4),
('00000000-0000-0000-0000-000000000001', 'Internal Procedures', 'Internal documentation for technicians', 'internal-procedures', 'internal', 5),
('00000000-0000-0000-0000-000000000001', 'Technical Reference', 'Technical documentation and reference', 'technical-reference', 'internal', 6);

-- ============================================================================
-- DEFAULT TIME ROUNDING RULE
-- ============================================================================

INSERT INTO time_rounding_rules (tenant_id, name, increment_minutes, rounding_method, minimum_minutes, is_default) VALUES
('00000000-0000-0000-0000-000000000001', 'Standard Rounding', 15, 'up', 15, TRUE);

-- ============================================================================
-- DEFAULT TAX RATE
-- ============================================================================

INSERT INTO tax_rates (tenant_id, name, rate, is_default) VALUES
('00000000-0000-0000-0000-000000000001', 'No Tax', 0.0000, TRUE);

-- ============================================================================
-- DEFAULT NOTIFICATION TEMPLATES
-- ============================================================================

INSERT INTO notification_templates (tenant_id, name, event_type, channel_type, subject, body_text, body_html) VALUES
-- Ticket created (Email)
('00000000-0000-0000-0000-000000000001', 'Ticket Created - Email', 'ticket.created', 'email',
    'New Ticket #{{ticket.number}}: {{ticket.title}}',
    'A new ticket has been created.\n\nTicket #: {{ticket.number}}\nTitle: {{ticket.title}}\nPriority: {{ticket.priority}}\nCompany: {{ticket.company_name}}\n\nDescription:\n{{ticket.description}}\n\nView ticket: {{ticket.url}}',
    '<h2>New Ticket Created</h2><p><strong>Ticket #:</strong> {{ticket.number}}<br><strong>Title:</strong> {{ticket.title}}<br><strong>Priority:</strong> {{ticket.priority}}<br><strong>Company:</strong> {{ticket.company_name}}</p><h3>Description</h3><p>{{ticket.description}}</p><p><a href="{{ticket.url}}">View Ticket</a></p>'),

-- Ticket assigned (Email)
('00000000-0000-0000-0000-000000000001', 'Ticket Assigned - Email', 'ticket.assigned', 'email',
    'Ticket #{{ticket.number}} assigned to you: {{ticket.title}}',
    'You have been assigned a ticket.\n\nTicket #: {{ticket.number}}\nTitle: {{ticket.title}}\nPriority: {{ticket.priority}}\nCompany: {{ticket.company_name}}\n\nView ticket: {{ticket.url}}',
    '<h2>Ticket Assigned to You</h2><p><strong>Ticket #:</strong> {{ticket.number}}<br><strong>Title:</strong> {{ticket.title}}<br><strong>Priority:</strong> {{ticket.priority}}<br><strong>Company:</strong> {{ticket.company_name}}</p><p><a href="{{ticket.url}}">View Ticket</a></p>'),

-- Ticket updated (Email)
('00000000-0000-0000-0000-000000000001', 'Ticket Updated - Email', 'ticket.updated', 'email',
    'Ticket #{{ticket.number}} Updated: {{ticket.title}}',
    'Ticket #{{ticket.number}} has been updated.\n\nTitle: {{ticket.title}}\nStatus: {{ticket.status}}\n\nLatest Update:\n{{ticket.last_note}}\n\nView ticket: {{ticket.url}}',
    '<h2>Ticket Updated</h2><p><strong>Ticket #:</strong> {{ticket.number}}<br><strong>Title:</strong> {{ticket.title}}<br><strong>Status:</strong> {{ticket.status}}</p><h3>Latest Update</h3><p>{{ticket.last_note}}</p><p><a href="{{ticket.url}}">View Ticket</a></p>'),

-- Invoice sent (Email)
('00000000-0000-0000-0000-000000000001', 'Invoice Sent - Email', 'invoice.sent', 'email',
    'Invoice #{{invoice.number}} from {{tenant.name}}',
    'Please find attached invoice #{{invoice.number}}.\n\nAmount Due: ${{invoice.total}}\nDue Date: {{invoice.due_date}}\n\nThank you for your business.\n\nView invoice: {{invoice.url}}',
    '<h2>Invoice #{{invoice.number}}</h2><p><strong>Amount Due:</strong> ${{invoice.total}}<br><strong>Due Date:</strong> {{invoice.due_date}}</p><p>Thank you for your business.</p><p><a href="{{invoice.url}}">View & Pay Invoice</a></p>'),

-- Payment received (Email)
('00000000-0000-0000-0000-000000000001', 'Payment Received - Email', 'payment.received', 'email',
    'Payment Received - Invoice #{{invoice.number}}',
    'We have received your payment of ${{payment.amount}} for Invoice #{{invoice.number}}.\n\nThank you for your payment.\n\nView invoice: {{invoice.url}}',
    '<h2>Payment Received</h2><p>We have received your payment of <strong>${{payment.amount}}</strong> for Invoice #{{invoice.number}}.</p><p>Thank you for your payment.</p>');

-- Slack notification templates
INSERT INTO notification_templates (tenant_id, name, event_type, channel_type, subject, body_text) VALUES
('00000000-0000-0000-0000-000000000001', 'Ticket Created - Slack', 'ticket.created', 'slack',
    NULL,
    ':ticket: *New Ticket #{{ticket.number}}*\n>*{{ticket.title}}*\n>Priority: {{ticket.priority}} | Company: {{ticket.company_name}}\n><{{ticket.url}}|View Ticket>'),

('00000000-0000-0000-0000-000000000001', 'Ticket Assigned - Slack', 'ticket.assigned', 'slack',
    NULL,
    ':point_right: *Ticket #{{ticket.number}} assigned to {{user.name}}*\n>*{{ticket.title}}*\n><{{ticket.url}}|View Ticket>'),

('00000000-0000-0000-0000-000000000001', 'SLA Breach - Slack', 'ticket.sla_breach', 'slack',
    NULL,
    ':rotating_light: *SLA BREACH - Ticket #{{ticket.number}}*\n>*{{ticket.title}}*\n>Due: {{ticket.sla_due_date}}\n><{{ticket.url}}|View Ticket>');

-- ============================================================================
-- INITIALIZE SEQUENCES
-- ============================================================================

INSERT INTO ticket_sequences (tenant_id, last_number) VALUES
('00000000-0000-0000-0000-000000000001', 0);

INSERT INTO invoice_sequences (tenant_id, last_number, prefix) VALUES
('00000000-0000-0000-0000-000000000001', 0, 'INV-');

-- ============================================================================
-- MODULE CONFIGURATION
-- ============================================================================

INSERT INTO module_config (tenant_id, module_name, is_enabled, config) VALUES
('00000000-0000-0000-0000-000000000001', 'ticketing', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'time_tracking', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'projects', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'contacts', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'calendar', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'contracts', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'billing', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'assets', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'knowledge_base', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'notifications', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'rmm_integration', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'client_portal', TRUE, '{}'),
('00000000-0000-0000-0000-000000000001', 'reports', TRUE, '{}');
