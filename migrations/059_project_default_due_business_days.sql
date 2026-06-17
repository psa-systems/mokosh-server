-- PMS-345: per-project override of the standard due date.
--
-- The tenant-wide setting `scheduling/default_due_business_days` supplies a
-- default due date (today + N business days) for new tasks that are created
-- without one. This column lets a single project override that tenant default
-- so the standard due date can be "sourced from the project" as well as from
-- the tenant SLA settings.
--
-- NULL = inherit the tenant-wide setting (the common case). A non-NULL value
-- (0..=365, where 0 disables the default for tasks in this project) wins over
-- the tenant setting. The range mirrors the tenant-setting validator.
ALTER TABLE projects
    ADD COLUMN default_due_business_days SMALLINT
        CHECK (default_due_business_days IS NULL
               OR (default_due_business_days >= 0 AND default_due_business_days <= 365));
