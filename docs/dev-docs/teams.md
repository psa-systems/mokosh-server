# Teams: role model

Written 2026-09-11 as PMS-1162's settled documentation of the reconciliation between team member roles and the app-level RBAC vocabulary.

## Two axes, not one

A team row carries two independent axes of "who is in charge":

- **`Team.manager_id: Option<Uuid>`** — the row's accountable owner. Optional; a team can have no named manager. When set, it names the ONE person the customer of the MSP would name (SLA escalation, budget, hiring).
- **`team_members.role: TEXT`** — either `"leader"` or `"member"`. Any team member can be a leader; this is a display + notification hint, not a permission axis. Multiple leaders per team are permitted.

These are not two names for one thing. A team can have three leaders and no manager (the display + fan-out signal is on but nobody is accountable). Another team can have a manager who is not a member of the team at all (the accountable owner delegates delivery to the members but is not doing the work). The service refuses neither shape.

## The role vocabulary is NOT a permission axis

`team_members.role` never grants a permission. It gates:

- The "Leader" chip the SPA renders next to a member's name.
- Notification fan-out selection (an announcement to "team leaders" reads `team_members WHERE role = 'leader'`; an announcement to "the team" reads every row).

Permission checks read the caller's APP-level role (`super_admin`, `admin`, `manager`, `technician`, `dispatcher`, `sales`, `finance`, in `mokosh_types::auth::UserRole`). That vocabulary already gates every existing tenant-scoped surface. Team member role does not fork it.

## The team-management projection

Team metadata edits (`PUT /teams/{id}`, `DELETE /teams/{id}`) and membership writes (`POST /teams/{id}/members`, `PUT /teams/{id}/members/{user_id}`, `DELETE /teams/{id}/members/{user_id}`) are gated by the projection:

```
allowed = user.role.is_admin() || user.id == team.manager_id
```

That means:

- An **admin** (or **super_admin**) may edit any team.
- The **accountable owner** — the user whose id equals `team.manager_id` — may edit their own team even if their app role is `technician`.
- **Every other user** is refused with 403, including a user whose app role is `Manager` (the CLASS) but whose id is not this specific team's `manager_id`. `UserRole::Manager` is a broad management privilege; it does not auto-grant edit rights on every team in the tenant.

Team CREATION (`POST /teams`) still requires an app-role admin because there is no team row yet for a `manager_id` to hang off.

Read endpoints (`GET /teams`, `GET /teams/{id}`, `GET /teams/{id}/members`) are `RequireAuth`. Any authenticated caller in the tenant reads.

## Notes on the alternatives that were rejected

- **Fold `manager_id` into `role = 'leader'`.** Rejected: the two answer different questions (accountable owner vs. display/notification hint). A one-column collapse loses the multi-leader shape and puts the customer-facing accountability signal on a per-membership axis.
- **Give `UserRole::Manager` team-edit rights across the tenant.** Rejected: makes every Manager an admin of every team, which is not what a Manager IS. A Manager is an app-level role for someone who manages other users' work; that does not imply they are the accountable owner of a specific team.
- **Add a third role vocabulary (`owner`, `admin`, `viewer`) on the team_members row.** Rejected: three parallel vocabularies is worse than two. If the two-value `leader`/`member` is inadequate, replace it — do not add a third.

## Where the tests live

- Service-layer: `tests/teams.rs`, pinning the CRUD, member roster, and validation behaviour.
- HTTP-layer projection guard: `tests/team_management_projection.rs`, pinning that an admin passes without a manager binding, a technician passes only when they are the row's `manager_id`, and `UserRole::Manager` alone is refused.

## Related tickets

- PMS-791 shipped the teams module (closed Done 2026-08-19).
- PMS-804 is the ongoing epic that split PMS-791's remaining work into invites (PMS-1161) and this ticket.
- PMS-513 disabled the SPA invite form's role picker until this reconciliation landed. Its constant `ROLE_ASSIGNMENT_ENABLED` is removed as part of this ticket.
