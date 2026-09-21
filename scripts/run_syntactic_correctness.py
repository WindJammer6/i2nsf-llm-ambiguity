"""Run the four-arm, 50-intent syntactic-correctness experiment."""
from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import time
import traceback
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import spe_hl as main3
from helpers import llm_client as policy_llm
import spe_empty_datastore as structured_empty

EXPERIMENT_ROOT = PROJECT_DIR / "experiments" / "syntactic correctness"
DATASET_PATH = PROJECT_DIR / "dataset" / "intents.csv"
MODEL = "gpt-4o-mini"
TRANSIENT_MARKERS = (
    "ratelimiterror",
    "apiconnectionerror",
    "apitimeouterror",
    "serviceunavailable",
    "connection reset",
    "temporarily unavailable",
    "status code: 429",
    "status code: 500",
    "status code: 502",
    "status code: 503",
    "status code: 504",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load baseline module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configure_baseline_client(module) -> None:
    from openai import OpenAI

    module.client = OpenAI(api_key=policy_llm.get_openai_api_key())


def load_variants() -> dict[str, Callable[[str], str]]:
    zero = load_module("schema_guided_0_shot", PROJECT_DIR / "baselines" / "schema_guided_0_shot.py")
    one = load_module("schema_guided_1_shot", PROJECT_DIR / "baselines" / "schema_guided_1_shot.py")
    three = load_module("schema_guided_3_shot", PROJECT_DIR / "baselines" / "schema_guided_3_shot.py")
    ensemble = load_module("prompt_ensembling_0_shot", PROJECT_DIR / "baselines" / "prompt_ensembling_0_shot.py")
    ensemble_one = load_module("prompt_ensembling_1_shot", PROJECT_DIR / "baselines" / "prompt_ensembling_1_shot.py")
    ensemble_three = load_module("prompt_ensembling_3_shot", PROJECT_DIR / "baselines" / "prompt_ensembling_3_shot.py")
    for module in (zero, one, three, ensemble, ensemble_one, ensemble_three):
        configure_baseline_client(module)
    policy_llm.configure_policy_model(MODEL)
    return {
        "schema_guided_0_shot": lambda intent: zero.generate_policy(intent, MODEL),
        "schema_guided_1_shot": lambda intent: one.generate_policy(intent, MODEL),
        "schema_guided_3_shot": lambda intent: three.generate_policy(intent, MODEL),
        "prompt_ensembling_0_shot": ensemble.main,
        "prompt_ensembling_1_shot": ensemble_one.main,
        "prompt_ensembling_3_shot": ensemble_three.main,
        "structured_prompt_ensembling_0_shot_empty": lambda intent: structured_empty.main(
            policy_intent=intent,
            clarification_context=None,
            clarification_context_kind="qa",
        ),
    }

def load_intents(limit: int | None = None) -> list[str]:
    with DATASET_PATH.open(newline="", encoding="utf-8-sig") as handle:
        intents = [row["intent"] for row in csv.DictReader(handle) if row.get("intent")]
    return intents if limit is None else intents[:limit]


def is_transient_error(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in TRANSIENT_MARKERS)


def call_with_transport_retries(generator: Callable[[str], str], intent: str, attempts: int = 3) -> tuple[str | None, str, str | None]:
    logs = []
    for attempt in range(1, attempts + 1):
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                response = generator(intent)
            logs.append(buffer.getvalue())
            return response, "\n".join(logs), None
        except Exception:
            error = traceback.format_exc()
            logs.append(buffer.getvalue() + f"\n[ATTEMPT {attempt} EXCEPTION]\n{error}")
            if attempt >= attempts or not is_transient_error(error):
                return None, "\n".join(logs), error
            time.sleep(2 ** attempt)
    return None, "\n".join(logs), "Generation exhausted retries."


def failure_category(result: dict) -> str:
    if result.get("generation_error"):
        return "generation failure"
    output = result.get("yanglint_output", "")
    for line in output.splitlines():
        if "libyang err" in line.lower():
            message = line.split(":", 1)[-1].strip()
            message = re.sub(r"\s*\(Schema location.*", "", message)
            message = re.sub(r'"/tmp/[^\"]+"', '"<temporary-policy>"', message)
            return message or "libyang validation error"
    if output.strip():
        return output.splitlines()[0].strip()[:240]
    return "unknown validation failure"


def run_one(variant: str, generator: Callable[[str], str], intent_index: int, intent: str, intent_dir: Path) -> dict:
    intent_dir.mkdir(parents=True, exist_ok=True)
    (intent_dir / "intent.txt").write_text(intent, encoding="utf-8")
    trace_dir = intent_dir / "policy_generation_trace"
    previous_trace = os.environ.get("POLICY_GENERATION_TRACE_DIR")
    os.environ["POLICY_GENERATION_TRACE_DIR"] = str(trace_dir)
    try:
        raw, generation_log, generation_error = call_with_transport_retries(generator, intent)
    finally:
        if previous_trace is None:
            os.environ.pop("POLICY_GENERATION_TRACE_DIR", None)
        else:
            os.environ["POLICY_GENERATION_TRACE_DIR"] = previous_trace

    (intent_dir / "raw_response.txt").write_text(raw or "", encoding="utf-8")
    (intent_dir / "generation.log").write_text(generation_log, encoding="utf-8")
    result = {
        "variant": variant,
        "model": MODEL,
        "intent_index": intent_index,
        "intent": intent,
        "generated": raw is not None,
        "passed": False,
        "generation_error": generation_error,
        "yanglint_output": "",
    }
    if raw is not None:
        xml = main3.extract_policy_xml(raw)
        xml_path = intent_dir / "generated_policy.xml"
        xml_path.write_text(xml, encoding="utf-8")
        validation = main3.validate_policy_file(xml_path)
        result["passed"] = validation["passed"]
        result["yanglint_output"] = validation["output"]
        result["yanglint_returncode"] = validation["returncode"]
    else:
        result["yanglint_output"] = generation_error or "Generation failed before producing a policy."
        result["yanglint_returncode"] = None
    (intent_dir / "yanglint.log").write_text(result["yanglint_output"], encoding="utf-8")
    if not result["passed"]:
        result["failure_category"] = failure_category(result)
    (intent_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def load_completed_result(intent_dir: Path, intent: str) -> dict | None:
    path = intent_dir / "result.json"
    if not path.exists():
        return None
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if result.get("intent") != intent:
        return None
    if result.get("generated") and not (intent_dir / "generated_policy.xml").exists():
        return None
    return result


def write_variant_outputs(variant_dir: Path, results: list[dict]) -> dict:
    with (variant_dir / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["intent_index", "intent", "generated", "passed", "failure_category", "yanglint_returncode"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            writer.writerow({key: result.get(key, "") for key in fields})
    failures = Counter(result.get("failure_category", "") for result in results if not result.get("passed"))
    summary = {
        "variant": results[0]["variant"] if results else variant_dir.name,
        "model": MODEL,
        "total": len(results),
        "generated": sum(1 for result in results if result.get("generated")),
        "passed": sum(1 for result in results if result.get("passed")),
        "failed": sum(1 for result in results if not result.get("passed")),
        "accuracy": (sum(1 for result in results if result.get("passed")) / len(results)) if results else None,
        "failure_categories": dict(failures.most_common()),
    }
    (variant_dir / "aggregate_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def write_readme(run_dir: Path, summaries: list[dict], smoke: bool) -> None:
    lines = [
        "# Syntactic Correctness Experiment",
        "",
        f"Run folder: `{run_dir}`",
        f"Model: `{MODEL}`",
        f"Dataset: `{DATASET_PATH}`",
        f"Dataset SHA-256: `{sha256_file(DATASET_PATH)}`",
        "Normalization: Markdown fences and surrounding prose only; no XML repair.",
        "Validation: yanglint with the I2NSF CFI and monitoring modules.",
        f"Smoke run excluded from primary results: `{str(smoke).lower()}`",
        "",
        "## Results",
        "",
        "| Variant | Generated | Passed | Failed | Accuracy |",
        "|---|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        accuracy = "n/a" if summary["accuracy"] is None else f"{summary['accuracy'] * 100:.2f}%"
        lines.append(f"| {summary['variant']} | {summary['generated']} | {summary['passed']} | {summary['failed']} | {accuracy} |")
    lines.extend(["", "## Failure Categories", ""])
    for summary in summaries:
        lines.append(f"### {summary['variant']}")
        if not summary["failure_categories"]:
            lines.append("No failures.")
        else:
            for category, count in summary["failure_categories"].items():
                affected = []
                for result_path in sorted((run_dir / summary["variant"]).glob("intent_*/result.json")):
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                    if result.get("failure_category") == category:
                        affected.append(f"{result['intent_index']:03d}")
                lines.append(f"- {count} x `{category}`; intents: {', '.join(affected)}")
        lines.append("")
    lines.extend([
        "## Reproduction",
        "",
        "```bash",
        "python3 scripts/run_syntactic_correctness.py",
        "```",
        "",
        "Resume this exact run:",
        "",
        "```bash",
        f"python3 scripts/run_syntactic_correctness.py --resume-dir \"{run_dir}\"",
        "```",
    ])
    content = "\n".join(lines) + "\n"
    (run_dir / "README.md").write_text(content, encoding="utf-8")
    if not smoke:
        (EXPERIMENT_ROOT / "README.md").write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume-dir", type=Path, default=None)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--variants", nargs="*", default=None, help="Run only the named registered variants")
    args = parser.parse_args()
    main3.require_yanglint()
    available_variants = load_variants()
    selected_names = args.variants or list(available_variants)
    unknown = sorted(set(selected_names) - set(available_variants))
    if unknown:
        raise ValueError(f"Unknown syntactic variants: {', '.join(unknown)}")
    variants = {name: available_variants[name] for name in selected_names}
    intents = load_intents(1 if args.smoke else args.limit)
    if args.resume_dir:
        run_dir = args.resume_dir.resolve()
    else:
        prefix = "smoke" if args.smoke else "run"
        run_dir = EXPERIMENT_ROOT / f"{prefix}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "experiment_type": "syntactic correctness",
        "model": MODEL,
        "intent_count": len(intents),
        "dataset": str(DATASET_PATH),
        "dataset_sha256": sha256_file(DATASET_PATH),
        "smoke": args.smoke,
        "variants": list(variants),
    }
    config_path = run_dir / "experiment_config.json"
    if config_path.exists():
        existing = json.loads(config_path.read_text(encoding="utf-8"))
        if existing != config:
            raise ValueError("Resume configuration does not match the existing syntactic run.")
    else:
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    summaries = []
    for variant, generator in variants.items():
        print(f"\n=== {variant} ===", flush=True)
        variant_dir = run_dir / variant
        variant_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for index, intent in enumerate(intents, start=1):
            intent_dir = variant_dir / f"intent_{index:03d}"
            completed = load_completed_result(intent_dir, intent)
            if completed is not None:
                print(f"[{variant}] skip intent {index}/{len(intents)}", flush=True)
                results.append(completed)
                continue
            print(f"[{variant}] intent {index}/{len(intents)}", flush=True)
            results.append(run_one(variant, generator, index, intent, intent_dir))
            write_variant_outputs(variant_dir, results)
        summaries.append(write_variant_outputs(variant_dir, results))
        write_readme(run_dir, summaries, args.smoke)
    print(json.dumps({"run_dir": str(run_dir), "summaries": summaries}, indent=2))


if __name__ == "__main__":
    main()
