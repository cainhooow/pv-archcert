-- ADR 0056: historical keys remain immutable; only known no-effect rejection
-- permits a fresh action with another key. Uncertainty never authorizes repetition.
ALTER TABLE control_commands
    DROP CONSTRAINT control_commands_project_repository_actor_intent_sha256_key;

CREATE UNIQUE INDEX control_command_live_intent
    ON control_commands(project, repository, actor, intent_sha256)
    WHERE state <> 'REJECTED';
