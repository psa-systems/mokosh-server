# Mokosh server

Mokosh server is a Professional Services Automation (PSA) platform for managed service providers. It is the REST API and persistence layer behind the SPA your technicians and clients use: tenants and users, teams and roles, tickets and time, contacts and companies, invoices and quotes, knowledge base, integrations, and the accounting delegation that keeps books in Xero or QuickBooks.

## Who it is for

- **MSP operators** standing up a self-hosted instance or running a hosted one, who need to configure the stack, invite the first admin, and keep it healthy.
- **MSP admins** inside a tenant, who set up companies, users, teams, billing rules, templates, and feature switches.
- **Technicians** who work tickets, log time, write knowledge base articles, and handle contacts and assets.
- **Clients** who reach the system through the customer portal to file tickets, approve quotes, pay invoices, and read articles shared with them.
- **Developers** integrating against the REST API from an in-house tool or a vertical automation.

## When NOT to use it

- It is not a general CRM. The contact plane assumes an MSP's working relationship with a client's staff; it does not model a marketing lead funnel.
- It is not an IT helpdesk. Tickets are tenant-scoped and assume contracts, SLAs, assets and billing rules behind them; a cheap ticket queue is cheaper elsewhere.
- It does not replace Xero or QuickBooks. It owns invoices on the Mokosh side and can hand them off to either; it does not post journal entries or run GL reports.

## How this documentation is organized

- [Getting started](getting-started.md): stand up the stack with docker compose, fill the minimum environment, sign the first admin in.
- [Configuration](configuration.md): every environment variable the server reads, grouped by subsystem.
- [Tenancy](tenancy.md): tenants, users, teams, roles, and how the contact plane fits in.
- [Authentication](authentication.md): Bunyip as the identity provider, API tokens, two-factor, login approval.
- [API](api.md): the REST surface, grouped by concern.
- [Billing](billing.md): invoices, quotes, prepaid blocks, overdue, write-offs, Xero / QuickBooks delegation.
- [Time tracking](time-tracking.md): entries, timesheets, work days.
- [Documents](documents.md): invoice and quote PDFs, templates, fonts.
- [Knowledge base](knowledge-base.md): articles, versions, comments.
- [Contacts](contacts.md): contact-company mirror, note editing, mail audiences, contact sync.
- [Integrations](integrations.md): Bunyip, Stripe, PayPal, Xero, QuickBooks, Google and Microsoft 365, Infisical.
- [Operations](operations/README.md): backups, upgrades, logs, first-run onboarding, delegated invoicing setup, Postgres security, provider migration.
- [Troubleshooting](troubleshooting.md): five concrete failures and their fix.
