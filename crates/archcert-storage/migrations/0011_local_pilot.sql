-- Local identity authority is separate from source, execution and signing.
CREATE TABLE local_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    instance text NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('UNINITIALIZED','SETUP_PENDING','INITIALIZED','RECOVERY_REQUIRED')),
    projection_pending boolean NOT NULL DEFAULT true,
    setup_hash text,
    setup_until bigint,
    CHECK ((state = 'SETUP_PENDING') = (setup_hash IS NOT NULL AND setup_until IS NOT NULL))
);

CREATE TABLE local_accounts (
    id text PRIMARY KEY,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    email text NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254 AND email = lower(email)),
    password_hash text NOT NULL,
    panel_credential text NOT NULL CHECK (length(panel_credential) = 64),
    role text NOT NULL CHECK (role IN ('VIEWER','OPERATOR','REVIEWER','ADMINISTRATOR')),
    generation text NOT NULL CHECK (length(generation) = 64),
    enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE local_projects (
    id text PRIMARY KEY,
    owner text NOT NULL REFERENCES local_accounts(id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description text NOT NULL CHECK (length(description) <= 2000),
    repository text NOT NULL UNIQUE,
    public_key text NOT NULL,
    device text NOT NULL UNIQUE,
    actor text NOT NULL UNIQUE,
    legacy_hash text NOT NULL,
    request_key text NOT NULL,
    UNIQUE(owner, request_key)
);

CREATE TABLE local_audit (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor text NOT NULL,
    event text NOT NULL,
    entity text NOT NULL,
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))
);
CREATE TRIGGER append_only_local_audit BEFORE UPDATE OR DELETE ON local_audit
FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE FUNCTION guard_local_initialization() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.instance <> OLD.instance
       OR (OLD.state = 'INITIALIZED' AND NEW.state NOT IN ('INITIALIZED','RECOVERY_REQUIRED'))
       OR (OLD.state = 'RECOVERY_REQUIRED' AND NEW.state <> 'RECOVERY_REQUIRED')
    THEN RAISE EXCEPTION 'initialization cannot reopen'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER monotonic_local_initialization BEFORE UPDATE ON local_instance
FOR EACH ROW EXECUTE FUNCTION guard_local_initialization();
CREATE TRIGGER retain_local_initialization BEFORE DELETE ON local_instance
FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TABLE local_login_budget (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    window_start timestamptz NOT NULL DEFAULT clock_timestamp(),
    used integer NOT NULL DEFAULT 0
);
INSERT INTO local_login_budget(singleton) VALUES (true);
