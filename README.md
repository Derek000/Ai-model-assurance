# AI Model Assurance — experimental v0.1

Offline-first, auditable AI model artefact and inference assessment toolkit for GGUF/Ollama, PyTorch, Safetensors and OpenAI-compatible inference endpoints. **It is not a backdoor detector with proven recall and does not certify model safety.**

## Why

Model repositories can contain unsafe serialisation, executable code, modified templates, compromised dependencies and poisoned model weights. Static scanners detect some file-level hazards; inference testing identifies only observed behaviours. This project combines both and explicitly records limitations.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
```

Optional scanners, installed separately and run in a disposable, network-restricted container:

```bash
python -m pip install modelaudit modelscan
# clamscan: install from your distribution packages
```

Verify CLI flags against your pinned installed tool versions before enabling optional scanners. These tools are not bundled and may change interfaces.

## Examples

**File-only (does not load model):**

```bash
model-assure --path /srv/quarantine/model --scanners modelaudit,modelscan,clamscan --output reports/file.json
```

**Local Ollama:**

```bash
model-assure --backend ollama --model llama3.2:latest --output reports/ollama.json
```

**Combined assessment with paired baseline:**

```bash
model-assure --path /srv/quarantine/model --backend ollama --model candidate:latest --baseline-model trusted:latest --scanners modelaudit,modelscan --output reports/combined.json
```

**Local OpenAI-compatible endpoint (e.g. llama.cpp server, vLLM, LM Studio):**

```bash
model-assure --backend openai-compatible --endpoint http://127.0.0.1:8000 --model my-model --output reports/api.json
```

Remote endpoints require `--allow-remote`; only use controlled endpoints. **This version does not support authentication headers or TLS pinning.** Avoid sending sensitive prompts or connecting to public endpoints.

## Stages and interpretation

1. File inventory and SHA-256 hashes. Symlinks are skipped; bounded file count.
2. Configuration heuristics. Text references are triage indicators, not proof of malicious code.
3. Optional ModelAudit, ModelScan and ClamAV execution. Raw results are captured; nonzero exit codes are **not** interpreted as confirmed compromise. Validate scanner reports separately.
4. Controlled inference probes: baseline, lexical, lexical variant, simulated date, asserted role, hypothetical tool. These are example probes, **not exhaustive trigger discovery**.
5. Optional paired baseline comparison (exact response equality only; changes are not necessarily malicious).
6. JSON evidence and explicit coverage limitations. No clean certificate is issued.

## Safety boundaries

- Never load untrusted pickle/PyTorch files in the host interpreter.
- Execute external scanners in a disposable unprivileged container/VM with network egress denied and model directory mounted read-only.
- Do not run candidate model inference on a trusted production host. Ollama is not a sandbox.
- Do not connect models to real shells, credential stores, infrastructure APIs or network tools during assessment.
- API calls may load and execute a model **inside the external runtime**; isolate that runtime separately.
- Keep raw model and output reports private; prompts and responses may contain sensitive material.
- This tool does not collect syscall traces, detect exfiltration, perform weight-level analysis or instrument neural activations.
- Review all findings manually and validate with trusted source digests.

## Future roadmap

- Provenance: signed model manifest and upstream digest verification.
- Parsers: GGUF metadata, Safetensors header validation and tokenizer diffs.
- Real trigger search: mutation, minimisation, stochastic repetition, false-positive controls.
- Tool-call tracing with mocked agent interfaces; eBPF/Falco capture from isolated host.
- Optional weight delta analysis and activation instrumentation on native checkpoints.
- Normalised scanner SARIF and evidence severity, signed attestations and policy gates.
- Container and Kubernetes discovery adapters with explicit authorisation.
- Authenticated OpenAI-compatible endpoints, timeouts and redirect restrictions.

## References

- https://github.com/promptfoo/modelaudit
- https://github.com/protectai/modelscan
- https://github.com/trailofbits/fickling
- https://github.com/NVIDIA/garak
- https://huggingface.co/docs/hub/security-pickle
- https://github.com/huggingface/transformers/blob/main/SECURITY.md
- https://docs.ollama.com/api
- https://atlas.mitre.org/
- https://genai.owasp.org/

## Contributing

Submit issues with a reproducible, non-sensitive test fixture and expected/actual outcomes. Never upload proprietary model weights, credentials or sensitive prompts. Contributions should include unit tests and avoid automatically executing untrusted artefacts.

## Project documentation

- [Safe quick start](docs/QUICKSTART.md)
- [Architecture and threat model](docs/ARCHITECTURE.md)
- [Development roadmap](ROADMAP.md)
- [References and further reading](docs/REFERENCES.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)