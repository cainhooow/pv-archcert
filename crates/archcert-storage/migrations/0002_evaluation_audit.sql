-- Durable phase timestamps and failure taxonomy do not alter immutable job inputs.
ALTER TABLE certification_jobs ADD COLUMN evaluation_at bigint;
ALTER TABLE certification_jobs ADD COLUMN failure text CHECK (failure IN (
    'TARGET_FAILURE','POLICY_FAILURE','INFRASTRUCTURE_FAILURE','WORKER_LOSS',
    'PERSISTENCE_FAILURE','SIGNING_FAILURE','VERIFICATION_FAILURE','OPERATOR_CANCELLATION'
));
