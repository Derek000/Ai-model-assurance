# Refusal integrity and directional-weight analysis

## Why

Abliteration commonly refers to altering weight matrices to attenuate a learned refusal-associated representation. It is distinct from a hidden conditional backdoor, unsafe deserialisation or a malicious runtime dependency. Refusal-direction removal may be implemented by orthogonal projection, but labels such as "abliterated" do not prove a particular procedure was applied.

## Who

Model publishers, security evaluators, AI platform operators and research teams assessing provenance, safety-control drift and potential model tampering.

## Assessment procedure

1. Establish the exact upstream checkpoint, licence, revision, architecture, quantisation, tokenizer and inference template. Record immutable hashes.
2. Perform ordinary static scanning and inventory. No neural safety claim follows from a clean static scan.
3. If possible, use a matched trusted baseline through the same inference engine. Run `--refusal-integrity` and review each recorded response manually. Probe categories are intentionally small and are **not** comprehensive.
4. For native Safetensors, obtain a validated, independently sourced refusal direction for each target matrix. Save 1D arrays in a NumPy NPZ keyed by exact tensor name. Never load pickled directions.
5. Run paired weight analysis. For each matrix W and unit direction u, report E(W,u)=||Wu||²/||W||²_F. A near-zero candidate E compared with the baseline suggests depletion of the selected input direction. This is one specific orientation; other techniques may alter row directions, intermediate representations or several layers.
6. Investigate alternative causes: benign fine-tuning, low-rank adapters, pruning, quantisation, architecture changes and mistaken reference direction.
7. Report coverage, uncertain results, reference trust, model modifications and deployment risk separately.

## Limitations and controls

- Refusal is not a universal measure of safety, and a model can refuse while revealing unsafe content.
- The heuristic does not evaluate whether a request was actually unsafe, and can produce both false positives and false negatives.
- A safety policy difference is not necessarily an attack.
- Direction vectors are not universal between architectures, checkpoints, layers or tokenisers.
- A high projection ratio does not exclude abliteration using other directions or techniques.
- An extremely low ratio can arise naturally or through non-malicious operations.
- Matching files by path and tensor key is necessary but not sufficient to establish tensor equivalence.
- No automatic certification of 'safe', 'malicious' or 'abliterated' is issued.

## Relevant research

- Arditi et al., *Refusal in Language Models Is Mediated by a Single Direction* (2024): https://arxiv.org/abs/2406.11763
- Zou et al., *Representation Engineering: A Top-Down Approach to AI Transparency* (2023): https://arxiv.org/abs/2310.01405
- Turner et al., *Activation Addition: Steering Language Models Without Optimization* (2023): https://arxiv.org/abs/2308.10248
- MITRE ATLAS: https://atlas.mitre.org/
- OWASP GenAI Security Project: https://genai.owasp.org/

These are methodology references, not proof of a particular named model's provenance or modification history.
