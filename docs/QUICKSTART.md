# Quick start and safe evaluation

## Prerequisites

Python 3.10+; a disposable Linux VM recommended; optional Ollama server in an isolated environment. The optional external scanners are separate installations.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
model-assure --help
```

## Offline file inventory

```bash
model-assure --path /srv/quarantine/candidate --output file-report.json
```

## Optional static scanners

```bash
model-assure --path /srv/quarantine/candidate --scanners modelaudit,modelscan,clamscan --output scanner-report.json
```

Run optional scanners only inside a disposable, network-restricted environment. Check their installed versions and supported flags; scanner failures must not be interpreted as clean results.

## Ollama assessment

```bash
model-assure --backend ollama --endpoint http://127.0.0.1:11434 --model candidate:latest --output ollama-report.json
```

## Paired comparison

```bash
model-assure --backend ollama --model candidate:latest --baseline-model trusted:latest --output compare-report.json
```

A trusted baseline must actually be independently verified; merely naming a model `trusted` does not establish trust.

## Reading results

Review inventory, scanner execution status, raw alerts, probe results and limitations together. This is a test observation report, not a certificate that a model is safe.
