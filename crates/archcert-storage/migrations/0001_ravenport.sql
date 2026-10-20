-- Authority-owned schema. Run explicitly with migration authority.
CREATE TABLE repository_grants (
    project text NOT NULL,
    repository text NOT NULL,
    actor text NOT NULL,
    PRIMARY KEY (project, repository, actor)
);
CREATE TABLE accepted_sources (
    submission text PRIMARY KEY,
    project text NOT NULL,
    repository text NOT NULL,
    source jsonb NOT NULL
);
CREATE TABLE certification_jobs (
    id text PRIMARY KEY,
    project text NOT NULL,
    repository text NOT NULL,
    actor text NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    inputs jsonb NOT NULL CHECK (octet_length(inputs::text) <= 100000),
    state text NOT NULL CHECK (state IN ('QUEUED','RUNNING','EVALUATING','SIGNING','COMPLETED','NOT_ELIGIBLE','INCONCLUSIVE')),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    evaluation jsonb,
    eligible boolean,
    issuance jsonb,
    certificate jsonb,
    UNIQUE(project, repository, actor, idempotency_key),
    CHECK (inputs->>'project' = project AND inputs->>'repository' = repository AND inputs->>'actor' = actor),
    CHECK ((state = 'COMPLETED') = (certificate IS NOT NULL)),
    CHECK (state NOT IN ('SIGNING','COMPLETED') OR (eligible IS TRUE AND evaluation IS NOT NULL AND issuance IS NOT NULL))
);
CREATE INDEX certification_queue ON certification_jobs(created_at, id) WHERE state = 'QUEUED';
CREATE TABLE certification_attempts (
    id text PRIMARY KEY,
    job text NOT NULL REFERENCES certification_jobs(id),
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
    worker text NOT NULL CHECK (length(worker) BETWEEN 1 AND 128),
    token text NOT NULL,
    state text NOT NULL CHECK (state IN ('LEASED','RUNNING','EVIDENCE_READY','COMPLETED','FAILED','LOST')),
    leased_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    lease_until bigint NOT NULL,
    ended_at bigint,
    failure text CHECK (failure IN ('TARGET_FAILURE','POLICY_FAILURE','INFRASTRUCTURE_FAILURE','WORKER_LOSS','PERSISTENCE_FAILURE','SIGNING_FAILURE','VERIFICATION_FAILURE','OPERATOR_CANCELLATION')),
    evidence jsonb,
    UNIQUE(job, ordinal),
    CHECK (lease_until > leased_at AND lease_until <= leased_at + 3600),
    CHECK ((state IN ('LEASED','RUNNING')) = (ended_at IS NULL))
);
CREATE UNIQUE INDEX exclusive_active_attempt ON certification_attempts(job) WHERE state IN ('LEASED','RUNNING');
CREATE TABLE artifacts (
    job text NOT NULL REFERENCES certification_jobs(id),
    attempt text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('EXECUTION','EVALUATION','CERTIFICATE','BUNDLE','MANIFEST')),
    reference jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('STAGING','AVAILABLE')),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    PRIMARY KEY(job, attempt, kind),
    CHECK ((reference->>'size')::bigint BETWEEN 1 AND 67108864),
    CHECK (reference->>'sha256' ~ '^[0-9a-f]{64}$')
);
CREATE TABLE audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job text NOT NULL REFERENCES certification_jobs(id),
    attempt text,
    event text NOT NULL,
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))
);
CREATE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable authority record'; END $$;
CREATE TRIGGER append_only_audit BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER immutable_source BEFORE UPDATE OR DELETE ON accepted_sources FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE FUNCTION guard_job_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id,NEW.project,NEW.repository,NEW.actor,NEW.idempotency_key,NEW.inputs,NEW.created_at)
       IS DISTINCT FROM (OLD.id,OLD.project,OLD.repository,OLD.actor,OLD.idempotency_key,OLD.inputs,OLD.created_at)
       OR (OLD.evaluation IS NOT NULL AND NEW.evaluation IS DISTINCT FROM OLD.evaluation)
       OR (OLD.eligible IS NOT NULL AND NEW.eligible IS DISTINCT FROM OLD.eligible)
       OR (OLD.issuance IS NOT NULL AND NEW.issuance IS DISTINCT FROM OLD.issuance)
       OR (OLD.certificate IS NOT NULL AND NEW.certificate IS DISTINCT FROM OLD.certificate)
    THEN RAISE EXCEPTION 'immutable job binding'; END IF;
    IF OLD.state IN ('COMPLETED','NOT_ELIGIBLE','INCONCLUSIVE') THEN RAISE EXCEPTION 'terminal job'; END IF;
    IF NEW.state <> OLD.state AND NOT (
      (OLD.state='QUEUED' AND NEW.state='RUNNING') OR
      (OLD.state='RUNNING' AND NEW.state IN ('QUEUED','EVALUATING','INCONCLUSIVE')) OR
      (OLD.state='EVALUATING' AND NEW.state IN ('SIGNING','NOT_ELIGIBLE','INCONCLUSIVE')) OR
      (OLD.state='SIGNING' AND NEW.state IN ('COMPLETED','INCONCLUSIVE'))
    ) THEN RAISE EXCEPTION 'invalid job transition'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER validated_job_update BEFORE UPDATE ON certification_jobs FOR EACH ROW EXECUTE FUNCTION guard_job_update();
CREATE FUNCTION guard_attempt_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id,NEW.job,NEW.ordinal,NEW.worker,NEW.token,NEW.leased_at)
       IS DISTINCT FROM (OLD.id,OLD.job,OLD.ordinal,OLD.worker,OLD.token,OLD.leased_at)
       OR OLD.state IN ('COMPLETED','FAILED','LOST')
       OR (OLD.evidence IS NOT NULL AND NEW.evidence IS DISTINCT FROM OLD.evidence)
    THEN RAISE EXCEPTION 'immutable attempt binding'; END IF;
    IF NEW.state <> OLD.state AND NOT (
       (OLD.state='LEASED' AND NEW.state IN ('RUNNING','LOST','FAILED')) OR
       (OLD.state='RUNNING' AND NEW.state IN ('EVIDENCE_READY','LOST','FAILED')) OR
       (OLD.state='EVIDENCE_READY' AND NEW.state='COMPLETED')
    ) THEN RAISE EXCEPTION 'invalid attempt transition'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER validated_attempt_update BEFORE UPDATE ON certification_attempts FOR EACH ROW EXECUTE FUNCTION guard_attempt_update();
CREATE FUNCTION guard_artifact_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.job,NEW.attempt,NEW.kind,NEW.reference,NEW.created_at) IS DISTINCT FROM (OLD.job,OLD.attempt,OLD.kind,OLD.reference,OLD.created_at)
      OR OLD.state <> 'STAGING' OR NEW.state <> 'AVAILABLE'
    THEN RAISE EXCEPTION 'immutable artifact binding'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER immutable_artifact BEFORE UPDATE ON artifacts FOR EACH ROW EXECUTE FUNCTION guard_artifact_update();
