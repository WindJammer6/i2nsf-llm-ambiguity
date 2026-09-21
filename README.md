# Clarification-Guided Intent Ambiguity Resolution for LLM-Based Security Policy Generation

Paper:

Overleafs (only accessible by the authors):

- https://www.overleaf.com/project/6a9a6951e4c4a85262fd581e (6-page version)
- https://www.overleaf.com/project/6aa98af03883a326132d282d (8-page version)

Experimental raw runs and results: [Link to be added]

## Abstract

Large language models (LLMs) can generate structured security policies from natural-language intents, but ambiguous intents may cause them to introduce unverified assumptions that do not reflect the user's intended behavior. This project implements Structured Prompt Ensembling with Human-in-the-Loop (SPE+HL), a clarification-guided ambiguity-resolution framework for generating I2NSF Consumer-Facing Interface (CFI) policies. SPE produces schema-constrained intermediate policies and deterministically converts them into YANG-compliant XML documents. SPE+HL compares independently generated policy realizations, uses disagreement in behavior-relevant fields to generate targeted clarification questions, and incorporates the user's answers into clarified policy generation.

The framework is evaluated on a synthetic benchmark of 50 security intents under initially empty and pre-registered Security Controller datastore settings. The evaluation measures YANG syntax validity, Disagreement Score (DS), and Scenario Alignment Score (SAS) using GPT-4o-mini and Gemini 3.5 Flash Lite.

This project can seen as to succeed these papers:

- [Security Policy Generation for Cloud-Based Security Services using Large Language Model](http://iotlab.skku.edu/publications/domestic-conference/KICS-2025-Winter-LLM-Based-Security-Policy-Generation.pdf), with [source code](https://github.com/jaehoonpauljeong/Data-Modeling-Group-2-Project).
- [A Hallucination Mitigation Scheme in Security Policy Generation with Large Language Models](http://iotlab.skku.edu/publications/domestic-conference/KICS-2026-Winter-LLM-AntiHallucination.pdf), with [source code](https://github.com/WindJammer6/37.-A-Hallucination-Mitigation-Scheme-in-Security-Policy-Generation-with-Large-Language-Models).

Much thanks to [Jaehoon (Paul) Jeong](https://scholar.google.co.uk/citations?user=_co9LWUAAAAJ&hl=en) for advising this project.

## Table of Contents

1. [Framework](#framework)
2. [Repository Structure](#repository-structure)
3. [Benchmark](#benchmark)
4. [Installation](#installation)
5. [Running the Experiments](#running-the-experiments)
6. [Evaluation](#evaluation)
7. [Results](#results)
8. [Sources](#sources)

## Framework

SPE+HL consists of three stages:

1. **Initial policy generation:** SPE independently generates multiple I2NSF CFI XML policy realizations from the same natural-language intent.
2. **Targeted clarification:** Differences among behavior-relevant policy fields are used to generate targeted clarification questions. The resulting question-answer interaction constitutes the human-in-the-loop stage.
3. **Clarified policy generation:** SPE regenerates the policies using the original intent and clarification answers.

The SPE policy-generation pipeline contains four stages:

1. **Prompt ensembling:** Specialized LLM prompts extract event and action requirements, conditions, datastore references, and policy metadata.
2. **Constrained decoding:** Provider-native structured output produces a typed intermediate JSON representation constrained to the supported I2NSF CFI fields.
3. **Datastore-object retrieval:** In the pre-registered setting, generated references are matched to existing endpoint-group and threat-prevention objects using category-constrained Top-1 embedding retrieval.
4. **Deterministic conversion:** The intermediate representation and datastore objects are converted into a CFI XML policy without further LLM generation.

## Repository Structure

- `spe_hl.py`: SPE+HL orchestration, disagreement measurement, targeted clarification, simulated feedback, syntax validation, and scenario-alignment evaluation.
- `spe_prompt_ensembling.py`: intent restatement and specialized requirement-extraction prompts.
- `spe_empty_datastore.py`: SPE pipeline for an initially empty datastore.
- `spe_pre_registered_datastore.py`: SPE pipeline for a pre-registered datastore.
- `helpers/`: LLM-provider integration, structured policy schemas, deterministic XML conversion, and datastore-object retrieval.
- `baselines/`: Schema-Guided and Prompt Ensembling implementations used in the syntactic-correctness comparison.
- `scripts/`: entry points for the syntactic-correctness, main ambiguity-resolution, and hyperparameter experiments.
- `dataset/`: benchmark intents, held-out scenario cards, expected policies, alignment slots, and the pre-registered datastore.
- `tests/`: SAS implementation and I2NSF YANG modules used by `yanglint`.

## Benchmark

The benchmark contains 50 intentionally ambiguous natural-language security intents. Each intent is accompanied by:

- a held-out scenario card describing the simulated user's intended behavior;
- an expected I2NSF CFI XML policy document;
- behavior-relevant alignment slots used to calculate SAS.

The pre-registered datastore contains controlled endpoint-group and threat-prevention objects used by the retrieval setting.

## Installation

Python 3.11 is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

The experiments require [`yanglint`](https://github.com/CESNET/libyang) from libyang. Ensure that `yanglint` is available on `PATH` before running the experiment scripts.

Configure the model credentials through environment variables:

```bash
export OPENAI_API_KEY="your-key"
export GEMINI_API_KEY="your-key"
```

On Windows PowerShell:

```powershell
$env:OPENAI_API_KEY="your-key"
$env:GEMINI_API_KEY="your-key"
```

The source files contain only non-secret placeholder values. Do not commit real API credentials.

## Running the Experiments

Run commands from the repository root.

### Syntactic Correctness

```bash
python scripts/run_syntactic_correctness.py \
  --variants schema_guided_3_shot prompt_ensembling_3_shot structured_prompt_ensembling_0_shot_empty
```

### Ambiguity Reduction and Scenario Alignment

The main experiment uses five candidate policies and permits up to three clarification questions:

```bash
python scripts/run_main_experiment.py --n 5 --k 3
```

This evaluates GPT-4o-mini and Gemini 3.5 Flash Lite under both datastore settings.

### Hyperparameter Testing

Run the core grid:

```bash
python scripts/run_hyperparameter_testing.py --grid-profile core
```

Run the extension grid by providing the directory produced by the core run:

```bash
python scripts/run_hyperparameter_testing.py \
  --grid-profile extension \
  --baseline-parent "path/to/core-run"
```

Generated experiment artifacts are written under `experiments/`. The raw runs are intentionally not included in this repository.

## Evaluation

- **YANG syntax validity:** XML documents are validated against the I2NSF CFI and monitoring-interface YANG modules using `yanglint`.
- **Disagreement Score (DS):** measures variation among independently generated policies over supported behavior-bearing leaf fields.
- **Scenario Alignment Score (SAS):** measures how closely each generated policy matches the expected behavior represented by the corresponding ground-truth policy.

## Results

Across the evaluated LLMs and datastore settings, targeted clarification reduces policy disagreement and improves alignment with the expected scenario while preserving YANG syntax validity. SPE achieves 100% syntax validity in the syntactic-correctness experiment through schema-constrained generation and deterministic XML conversion.

The complete raw runs and machine-readable result artifacts will be made available through the experimental-results link at the beginning of this README.

## Sources

- [I2NSF Consumer-Facing Interface YANG Data Model](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-consumer-facing-interface-dm/)
- [I2NSF Framework (RFC 8329)](https://www.rfc-editor.org/rfc/rfc8329)
- [libyang and yanglint](https://github.com/CESNET/libyang)
- [OpenAI Python SDK](https://github.com/openai/openai-python)
- [Google Gen AI Python SDK](https://github.com/googleapis/python-genai)
