-- Independent pre-admission metadata. Historical jobs/attempts are unchanged.
CREATE TABLE ironcrest_sessions (
    id text PRIMARY KEY,
    project text NOT NULL,
    pin jsonb NOT NULL CHECK (octet_length(pin::text) <= 100000),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    invocation text,
    review_timestamp bigint,
    CHECK (pin->>'project' = project),
    CHECK ((invocation IS NULL) = (review_timestamp IS NULL))
);
CREATE TABLE ironcrest_evidence (
    session text NOT NULL REFERENCES ironcrest_sessions(id),
    role text NOT NULL CHECK (role IN ('AUTHORITY_PROFILE','KNOWLEDGE','IMPACT','REQUEST','REVIEW','GATE','CHALLENGE_PLAN','CHALLENGE_RESULT')),
    reference jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('STAGING','AVAILABLE')),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    PRIMARY KEY(session, role),
    CHECK ((reference->>'size')::bigint BETWEEN 1 AND 33554432),
    CHECK (reference->>'sha256' ~ '^[0-9a-f]{64}$')
);
CREATE FUNCTION guard_ironcrest_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id,NEW.project,NEW.pin,NEW.created_at) IS DISTINCT FROM (OLD.id,OLD.project,OLD.pin,OLD.created_at)
       OR OLD.invocation IS NOT NULL OR NEW.invocation IS NULL OR NEW.review_timestamp IS NULL
    THEN RAISE EXCEPTION 'immutable Ironcrest session'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER immutable_ironcrest_session BEFORE UPDATE ON ironcrest_sessions FOR EACH ROW EXECUTE FUNCTION guard_ironcrest_session();
CREATE TRIGGER retain_ironcrest_session BEFORE DELETE ON ironcrest_sessions FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE FUNCTION guard_ironcrest_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.session,NEW.role,NEW.reference,NEW.created_at) IS DISTINCT FROM (OLD.session,OLD.role,OLD.reference,OLD.created_at)
       OR OLD.state <> 'STAGING' OR NEW.state <> 'AVAILABLE'
    THEN RAISE EXCEPTION 'immutable Ironcrest evidence'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER immutable_ironcrest_evidence BEFORE UPDATE ON ironcrest_evidence FOR EACH ROW EXECUTE FUNCTION guard_ironcrest_evidence();
CREATE TRIGGER retain_ironcrest_evidence BEFORE DELETE ON ironcrest_evidence FOR EACH ROW EXECUTE FUNCTION reject_mutation();
