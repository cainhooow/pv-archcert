-- Integrate the first-run records into the existing ArchCert product.
-- Renames preserve all IDs, hashes, generations, grants, audit and initialization guards.
ALTER TABLE local_instance RENAME TO platform_instance;
ALTER TABLE local_accounts RENAME TO accounts;
ALTER TABLE local_projects RENAME TO project_registry;
ALTER TABLE local_audit RENAME TO provisioning_audit;
ALTER TABLE local_login_budget RENAME TO login_attempt_budget;
