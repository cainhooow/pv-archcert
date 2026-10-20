-- Runtime control is separate from execution and certification verdict semantics.
CREATE UNIQUE INDEX attempt_job_identity ON certification_attempts(job,id);
CREATE TABLE attempt_runtime (
    attempt text PRIMARY KEY,
    job text NOT NULL,
    binding jsonb NOT NULL CHECK (octet_length(binding::text) <= 16384),
    fenced boolean NOT NULL DEFAULT false,
    cleanup text NOT NULL DEFAULT 'PENDING'
      CHECK (cleanup IN ('NOT_REQUIRED','PENDING','IN_PROGRESS','SUCCEEDED','FAILED','BLOCKED')),
    FOREIGN KEY(job,attempt) REFERENCES certification_attempts(job,id),
    CHECK (cleanup <> 'SUCCEEDED' OR fenced)
);
CREATE FUNCTION guard_runtime_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.attempt,NEW.job,NEW.binding) IS DISTINCT FROM (OLD.attempt,OLD.job,OLD.binding)
       OR (OLD.fenced AND NOT NEW.fenced)
       OR (OLD.cleanup='SUCCEEDED' AND NEW.cleanup <> 'SUCCEEDED')
    THEN RAISE EXCEPTION 'immutable runtime authority'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER immutable_runtime_binding BEFORE UPDATE ON attempt_runtime
FOR EACH ROW EXECUTE FUNCTION guard_runtime_update();
