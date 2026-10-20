# ADR-0011: Hostile execution plane boundary

Status: Accepted for Milestone 3. Historical ADRs are unchanged.

Target files, commands, toolchains, build scripts, tests and descendants are
hostile. The control plane does not execute them in its process or on the host.
Only a source-only RunnerInput plus an authority ExecutionProfile and structural
ExecutionCommand enters execution. No signer, database, source store, materializer,
Git credential or source cleanup lease crosses the port.

Source preparation remains passive. Execution starts only after isolated source
reconstruction and stopped-container policy checks. Execution outcomes describe
observations, never PASS/FAIL certification. A zero exit means process success
only. No signing, AI interpretation, validation-plan discovery or policy evaluator
is introduced. `archcert.toml` can describe requested profiles/argv, with unknown
security fields rejected; it cannot supply runtime authority settings.

The runtime/controller and image supply chain are trusted infrastructure. A
compromised runtime invalidates these guarantees. This is engineering
self-validation, not independent certification or proof against container escapes.
