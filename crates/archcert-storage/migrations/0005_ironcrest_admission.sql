-- Create-only linkage. Existing job inputs and historical evidence stay unchanged.
CREATE TABLE ironcrest_admissions (
    session text PRIMARY KEY REFERENCES ironcrest_sessions(id),
    job text NOT NULL UNIQUE REFERENCES certification_jobs(id),
    binding jsonb NOT NULL CHECK (octet_length(binding::text) <= 100000),
    created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    CHECK (session = job),
    CHECK (binding->>'id' = session)
);
CREATE TRIGGER immutable_ironcrest_admission BEFORE UPDATE OR DELETE ON ironcrest_admissions
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
