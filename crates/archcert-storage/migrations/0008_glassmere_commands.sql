-- Private operational coordination, not policy authority or M10 transparency.
-- Existing grants do not implicitly enable any new operation.
CREATE TABLE control_command_grants (
    project text NOT NULL,
    repository text NOT NULL,
    actor text NOT NULL,
    authority_context text NOT NULL CHECK (authority_context ~ '^[0-9a-f]{64}$'),
    operation text NOT NULL CHECK (operation IN (
        'REQUEST_CERTIFICATION', 'REQUEST_RELEASE_BUILD',
        'REQUEST_RELEASE_READINESS_EVALUATION', 'CANCEL_ELIGIBLE_JOB', 'RETRY_ELIGIBLE_JOB'
    )),
    PRIMARY KEY (project, repository, actor, authority_context, operation),
    FOREIGN KEY (project, repository, actor) REFERENCES repository_grants(project, repository, actor)
        ON DELETE CASCADE
);

CREATE TABLE control_commands (
    id text PRIMARY KEY,
    project text NOT NULL,
    repository text NOT NULL,
    actor text NOT NULL,
    authority_context text NOT NULL CHECK (authority_context ~ '^[0-9a-f]{64}$'),
    operation text NOT NULL,
    request jsonb NOT NULL CHECK (octet_length(request::text) <= 262144),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'REQUESTED' CHECK (
        state IN ('REQUESTED', 'PROCESSING', 'APPLIED', 'REJECTED', 'INCONCLUSIVE')
    ),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    dispatches integer NOT NULL DEFAULT 0 CHECK (dispatches >= 0),
    dispatcher text CHECK (length(dispatcher) BETWEEN 1 AND 128),
    token text,
    lease_until bigint,
    outcome jsonb CHECK (octet_length(outcome::text) <= 262144),
    UNIQUE (project, repository, actor, intent_sha256),
    UNIQUE (id, project, repository, actor),
    CHECK ((state = 'PROCESSING') =
        (dispatcher IS NOT NULL AND token IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK ((state IN ('APPLIED', 'REJECTED', 'INCONCLUSIVE')) = (outcome IS NOT NULL)),
    CHECK (outcome IS NULL OR outcome->>'state' = state),
    CHECK (request->>'schema' = '1'
        AND request->'scope'->>'project' = project
        AND request->'scope'->>'repository' = repository
        AND request->'scope'->>'actor' = actor
        AND request->>'authority_context' = authority_context
        AND request->'action'->>'kind' = operation)
);
CREATE INDEX control_command_queue ON control_commands(created_at, id)
    WHERE state IN ('REQUESTED', 'PROCESSING');

CREATE TABLE control_command_keys (
    project text NOT NULL,
    repository text NOT NULL,
    actor text NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    command text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (project, repository, actor, idempotency_key),
    FOREIGN KEY (command, project, repository, actor)
        REFERENCES control_commands(id, project, repository, actor)
);

CREATE TABLE control_command_audit (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    command text NOT NULL REFERENCES control_commands(id),
    event text NOT NULL CHECK (event IN (
        'CommandRequested', 'RetryKeyBound', 'CommandClaimed',
        'CommandRenewed', 'CommandApplied', 'CommandRejected', 'CommandInconclusive'
    )),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))
);
CREATE TRIGGER retain_control_command_keys BEFORE UPDATE OR DELETE ON control_command_keys
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER retain_control_command_audit BEFORE UPDATE OR DELETE ON control_command_audit
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER retain_control_commands BEFORE DELETE ON control_commands
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE FUNCTION guard_control_command_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.project, NEW.repository, NEW.actor, NEW.authority_context,
        NEW.operation, NEW.request, NEW.request_sha256, NEW.intent_sha256, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.project, OLD.repository, OLD.actor, OLD.authority_context,
        OLD.operation, OLD.request, OLD.request_sha256, OLD.intent_sha256, OLD.created_at)
       OR OLD.state IN ('APPLIED', 'REJECTED', 'INCONCLUSIVE') THEN
        RAISE EXCEPTION 'immutable control command';
    END IF;

    IF NEW.state = 'PROCESSING' THEN
        IF NEW.lease_until <= floor(extract(epoch FROM clock_timestamp()))
           OR NEW.lease_until > floor(extract(epoch FROM clock_timestamp())) + 300 THEN
            RAISE EXCEPTION 'invalid control command lease bound';
        END IF;

        IF NEW.token IS DISTINCT FROM OLD.token THEN
            IF NEW.dispatches <> OLD.dispatches + 1
               OR (OLD.state = 'PROCESSING'
                   AND OLD.lease_until > floor(extract(epoch FROM clock_timestamp()))) THEN
                RAISE EXCEPTION 'invalid control command takeover';
            END IF;
        ELSIF OLD.state <> 'PROCESSING'
              OR NEW.dispatches <> OLD.dispatches
              OR NEW.dispatcher IS DISTINCT FROM OLD.dispatcher
              OR OLD.lease_until <= floor(extract(epoch FROM clock_timestamp())) THEN
            RAISE EXCEPTION 'invalid control command renewal';
        END IF;
    ELSIF NEW.state NOT IN ('APPLIED', 'REJECTED', 'INCONCLUSIVE')
          OR OLD.state <> 'PROCESSING'
          OR OLD.lease_until <= floor(extract(epoch FROM clock_timestamp()))
          OR NEW.dispatches <> OLD.dispatches THEN
        RAISE EXCEPTION 'invalid control command transition';
    END IF;

    RETURN NEW;
END $$;
CREATE TRIGGER validated_control_command_update BEFORE UPDATE ON control_commands
    FOR EACH ROW EXECUTE FUNCTION guard_control_command_update();
