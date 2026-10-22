-- Canonical M6 is separate from the historical ironcrest review lifecycle.
CREATE TABLE release_invocations (
    project TEXT NOT NULL,
    invocation TEXT NOT NULL CHECK (invocation ~ '^[0-9a-f]{64}$'),
    admission JSONB NOT NULL,
    claim_a TEXT,
    claim_b TEXT,
    PRIMARY KEY (project, invocation)
);

CREATE TABLE release_evidence (
    project TEXT NOT NULL,
    invocation TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN (
        'INPUT', 'SOURCE_CERTIFICATE', 'ARTIFACT_A', 'RESULT_A',
        'ARTIFACT_B', 'RESULT_B', 'REPRODUCIBILITY', 'PERMIT_PAYLOAD', 'PERMIT_ENVELOPE'
    )),
    reference JSONB NOT NULL,
    available BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (project, invocation, role),
    FOREIGN KEY (project, invocation) REFERENCES release_invocations(project, invocation)
);

CREATE TABLE release_audit (
    sequence BIGSERIAL PRIMARY KEY,
    project TEXT NOT NULL,
    invocation TEXT NOT NULL,
    event TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (project, invocation) REFERENCES release_invocations(project, invocation)
);

CREATE FUNCTION immutable_release_input() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.project IS DISTINCT FROM OLD.project
       OR NEW.invocation IS DISTINCT FROM OLD.invocation
       OR NEW.admission IS DISTINCT FROM OLD.admission
       OR (OLD.claim_a IS NOT NULL AND NEW.claim_a IS DISTINCT FROM OLD.claim_a)
       OR (OLD.claim_b IS NOT NULL AND NEW.claim_b IS DISTINCT FROM OLD.claim_b) THEN
        RAISE EXCEPTION 'immutable release admission or claim';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER release_input_immutable BEFORE UPDATE ON release_invocations
    FOR EACH ROW EXECUTE FUNCTION immutable_release_input();

CREATE FUNCTION immutable_release_reference() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.project IS DISTINCT FROM OLD.project
       OR NEW.invocation IS DISTINCT FROM OLD.invocation
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.reference IS DISTINCT FROM OLD.reference
       OR (OLD.available AND NOT NEW.available) THEN
        RAISE EXCEPTION 'immutable release reference';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER release_reference_immutable BEFORE UPDATE ON release_evidence
    FOR EACH ROW EXECUTE FUNCTION immutable_release_reference();

CREATE FUNCTION retain_release_history() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'release history is append-only';
END;
$$;
CREATE TRIGGER retain_release_input BEFORE DELETE ON release_invocations
    FOR EACH ROW EXECUTE FUNCTION retain_release_history();
CREATE TRIGGER retain_release_evidence BEFORE DELETE ON release_evidence
    FOR EACH ROW EXECUTE FUNCTION retain_release_history();
CREATE TRIGGER retain_release_audit BEFORE UPDATE OR DELETE ON release_audit
    FOR EACH ROW EXECUTE FUNCTION retain_release_history();
