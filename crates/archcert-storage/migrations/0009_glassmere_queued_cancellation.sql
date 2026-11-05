-- ADR 0054: narrowly activate the reserved operator-cancellation reason.
-- Historical migrations and generic job transitions remain unchanged.
-- Parent-row locking excludes worker admission while cancellation is checked.
CREATE OR REPLACE FUNCTION guard_job_update() RETURNS trigger LANGUAGE plpgsql AS $$
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
      (OLD.state='QUEUED' AND NEW.state='INCONCLUSIVE'
       -- A missing reason must be FALSE, never SQL UNKNOWN inside NOT(...).
       AND NEW.failure IS NOT DISTINCT FROM 'OPERATOR_CANCELLATION'
       AND OLD.failure IS NULL
       AND NEW.evaluation IS NULL AND NEW.evaluation_at IS NULL
       AND NEW.eligible IS NULL AND NEW.issuance IS NULL AND NEW.certificate IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM certification_attempts a
         LEFT JOIN attempt_runtime r ON r.attempt=a.id
         WHERE a.job=OLD.id AND (
           a.state <> 'LOST' OR a.failure IS DISTINCT FROM 'WORKER_LOSS'
           OR a.evidence IS NOT NULL
           OR r.attempt IS NULL OR NOT r.fenced OR r.cleanup <> 'SUCCEEDED'
         )
       )) OR
      (OLD.state='QUEUED' AND NEW.state='RUNNING') OR
      (OLD.state='RUNNING' AND NEW.state IN ('QUEUED','EVALUATING','INCONCLUSIVE')) OR
      (OLD.state='EVALUATING' AND NEW.state IN ('SIGNING','NOT_ELIGIBLE','INCONCLUSIVE')) OR
      (OLD.state='SIGNING' AND NEW.state IN ('COMPLETED','INCONCLUSIVE'))
    ) THEN RAISE EXCEPTION 'invalid job transition'; END IF;
    RETURN NEW;
END $$;
