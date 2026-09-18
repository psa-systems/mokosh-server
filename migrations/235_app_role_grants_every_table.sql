-- PMS-1265: give the app role every table, whoever created it.
--
-- Staging answered 500 on every contact create and list: `permission denied
-- for table contact_sync_links` (42501) on the app pool. There, migrations run
-- as the owner role `mokosh` and the app pool logs in as `mokosh_app`.
-- `provision_roles` reaches the app role two ways, and neither covered it:
--
--   * `ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator`, which only applies
--     to tables `mokosh_migrator` itself creates;
--   * `GRANT ... ON ALL TABLES` on a full provision (a boot with
--     `MOKOSH_ADMIN_DATABASE_URL`), which only covers tables that existed at
--     that boot.
--
-- So a table another owner created after the last full provision was invisible
-- to the app role. Migrations 210 and 218 grant explicitly for exactly this
-- reason; 201, 202, 213, 214, 220, 221, 225, 228 and 229 did not.
--
-- These are the provisioner's own statements, so a database that already had
-- them changes nothing, and nothing is withheld from the app role on purpose
-- (no REVOKE exists anywhere). From here on each migration that creates a
-- table grants it in the same file; `db::provision::tests::
-- every_new_table_is_granted_to_the_app_role` enforces that.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mokosh_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mokosh_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mokosh_app;
