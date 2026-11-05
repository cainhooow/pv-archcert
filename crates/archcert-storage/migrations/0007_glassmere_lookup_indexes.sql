-- Additive operational lookup indexes. Authority bytes, rows and transitions retain
-- their existing meanings. Apply explicitly with migration authority, never panel.
CREATE INDEX glassmere_sources_project_identity ON accepted_sources(project, submission);
CREATE INDEX glassmere_sources_commit ON accepted_sources(project, (source->>'commit'), submission);
CREATE INDEX glassmere_jobs_project_identity ON certification_jobs(project, id);
CREATE INDEX glassmere_jobs_state ON certification_jobs(project, state, id);
CREATE INDEX glassmere_jobs_evaluation ON certification_jobs(project, eligible, state, id)
    WHERE evaluation IS NOT NULL;
CREATE INDEX glassmere_jobs_certificate_payload ON certification_jobs
    (project, (certificate->'issuance'->>'certificate_sha256'), id);
CREATE INDEX glassmere_jobs_certificate_envelope ON certification_jobs
    (project, (certificate->'artifact'->>'sha256'), id);
CREATE INDEX glassmere_artifacts_digest ON artifacts((reference->>'sha256'), job);
CREATE INDEX glassmere_sessions_project_identity ON ironcrest_sessions(project, id);
CREATE INDEX glassmere_semantic_digest ON ironcrest_evidence((reference->>'sha256'), session);
CREATE INDEX glassmere_release_digest ON release_evidence
    (project, (reference->>'sha256'), invocation, role);
CREATE INDEX glassmere_release_certificate ON release_invocations
    (project, (admission->'input'->'certified_source'->>'certificate_sha256'), invocation);
CREATE INDEX glassmere_job_audit ON audit_events(job, sequence);
CREATE INDEX glassmere_release_audit ON release_audit(project, sequence);
CREATE INDEX glassmere_jobs_commit ON certification_jobs
    (project, (inputs->'source'->>'commit'), id);
CREATE INDEX glassmere_sessions_commit ON ironcrest_sessions
    (project, (pin->'source'->>'commit'), id);
CREATE INDEX glassmere_release_commit ON release_invocations
    (project, (admission->'input'->'certified_source'->'source'->>'commit'), invocation);
