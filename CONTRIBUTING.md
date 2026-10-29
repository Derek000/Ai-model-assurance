# Contributing

Open an issue describing the threat model, expected behaviour, test fixture and reproducible steps. Keep fixtures synthetic and non-sensitive. Include automated tests with code changes. Avoid adding execution of untrusted model files, live shell tools or network-enabled agents to CI. Document tool versions, timeouts and false-positive risks.

Development: `python -m pip install -e '.[dev]' && pytest -q`.
