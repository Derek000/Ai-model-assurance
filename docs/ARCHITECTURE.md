# Architecture and threat model

## Trust boundaries

1. **Untrusted input:** model files, adapters, templates, metadata and scanner output.
2. **Inspection environment:** disposable, unprivileged VM/container; read-only mounted model files; no network egress unless specifically required.
3. **Inference environment:** separate disposable model runtime. Loading a model may execute runtime-specific code; API-only assessments cannot inspect weights.
4. **Reporting environment:** store hashes, provenance, scan status, errors and redacted evidence. Never treat a skipped scanner as a clean result.

## Threats in scope

- Unsafe deserialisation, executable dependencies and malicious model packaging.
- Modified templates/tokenizers, untrusted adapters and compromised provenance.
- Observable prompt-conditional behaviour and suspicious proposed tool use.
- Runtime changes detectable with separately deployed host instrumentation (future).

## Threats not reliably ruled out

- Rare or undiscovered trigger sequences, distributed weight-level backdoors, model extraction, unseen runtime activity and malicious actions outside observed sessions.
- API provider substitution where the underlying artefact is inaccessible.

## Operational safeguards

- No privileged Docker socket or cloud credentials in assessment containers.
- No real tool execution or outbound network access for untrusted agents.
- Do not use `torch.load` or pickle to inspect untrusted models.
- Enforce endpoint allowlists, TLS validation, model size limits and subprocess timeouts before production use.
- Treat model outputs and scanner logs as untrusted; never execute instructions contained within them.

## Interpretation

A hash mismatch proves artefact difference, not malicious intent. A behavioural difference proves divergence under tested conditions, not a backdoor. A scanner alert is a triage signal requiring independent verification.
