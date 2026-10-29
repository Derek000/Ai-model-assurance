# Development roadmap

This is a research tool, not a model-safety certification service. Progress is measured against reproducible, labelled fixtures and published detection metrics.

## v0.1 — baseline (implemented)
- File inventory, hashes, configuration heuristics, optional external scanner execution.
- Ollama and OpenAI-compatible endpoint probes, baseline comparison and JSON evidence.
- Unit tests and CI.

## v0.2 — defensive hardening
- Strict scan profiles, bounded resource consumption, timeouts and safer subprocess environment.
- Scanner version detection, output parsing, and explicit `not_run` / `error` / `finding` distinctions.
- Provenance manifests, pinned upstream hashes and model/configuration/tokenizer fingerprinting.
- Sanitised reporting, redaction, SARIF and HTML summaries.

## v0.3 — behavioural research
- Versioned prompt corpus, deterministic repeat runs and confidence intervals.
- Trigger mutation/minimisation and controlled false-positive measurement.
- Mocked tool invocation observation with no live infrastructure credentials.

## v0.4 — infrastructure integrations
- Read-only discovery of local Ollama, llama.cpp, vLLM and container deployments.
- Explicitly authorised Kubernetes and VM inventory adapters.
- Correlated process/file/network telemetry collected by an isolated observer.

## v0.5 — neural forensics (experimental)
- Optional native-checkpoint weight delta and tokenizer embedding comparison.
- Activation tracing and causal intervention on supported architectures.
- Documented limitations for quantised GGUF and inaccessible API weights.

## Release gates
- Tests, lint, dependency review, threat model and documented test coverage.
- Reproducible benign and deliberately modified fixtures with licence clearance.
- Publish false-positive rate, measured recall and environment limitations before security claims.
