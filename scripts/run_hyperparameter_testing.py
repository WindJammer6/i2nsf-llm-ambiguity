from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import spe_hl as main3


EXPERIMENT_ROOT = PROJECT_DIR / "experiments" / "hyperparameter testing"
PIPELINE_NAME = "pre-registered-top1"
POLICY_MODEL = "gpt-4o-mini"
N_VALUES = (3, 5, 7, 10)
K_VALUES = (1, 3, 5, 7)
HYPERPARAMETER_GRID = tuple((n, k) for n in N_VALUES for k in K_VALUES)
EXPECTED_INTENTS = 50
EXPECTED_SLOTS = 43
EPSILON = 1e-12


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def slug_for(n: int, k: int) -> str:
    return f"n_{n:02d}_k_{k:02d}"


def validate_inputs(grid: tuple[tuple[int, int], ...]) -> dict[str, Any]:
    if not grid:
        raise RuntimeError("The hyperparameter grid is empty.")
    if len(grid) != len(set(grid)):
        raise RuntimeError("The hyperparameter grid contains duplicate configurations.")
    if any(n <= 0 or k <= 0 for n, k in grid):
        raise RuntimeError("All hyperparameter values must be positive integers.")

    intents = main3.load_intents()
    if len(intents) != EXPECTED_INTENTS:
        raise RuntimeError(f"Expected {EXPECTED_INTENTS} intents, found {len(intents)}.")

    missing_cards: list[int] = []
    malformed_slots: list[str] = []
    for intent_index in range(1, EXPECTED_INTENTS + 1):
        try:
            main3.load_scenario_card(intent_index, main3.SCENARIO_CARD_DIR)
        except FileNotFoundError:
            missing_cards.append(intent_index)

        slot_path = main3.SCENARIO_ALIGNMENT_DIR / f"intent_{intent_index:03d}_slots.json"
        if not slot_path.exists():
            malformed_slots.append(f"intent {intent_index}: missing file")
            continue
        payload = read_json(slot_path)
        slots = payload.get("slots", {})
        if payload.get("slot_count") != EXPECTED_SLOTS or len(slots) != EXPECTED_SLOTS:
            malformed_slots.append(
                f"intent {intent_index}: slot_count={payload.get('slot_count')}, actual={len(slots)}"
            )

    if missing_cards:
        raise RuntimeError(f"Missing hidden scenario cards for intents: {missing_cards}")
    if malformed_slots:
        raise RuntimeError("Alignment slot verification failed: " + "; ".join(malformed_slots))

    main3.require_yanglint()
    if PIPELINE_NAME not in main3.PIPELINE_MODULES:
        raise RuntimeError(f"Pipeline {PIPELINE_NAME!r} is not registered in main3.")

    return {
        "intent_count": len(intents),
        "hidden_scenario_card_count": EXPECTED_INTENTS,
        "alignment_file_count": EXPECTED_INTENTS,
        "slots_per_intent": EXPECTED_SLOTS,
        "pipeline": PIPELINE_NAME,
        "policy_model": POLICY_MODEL,
        "configuration_count": len(grid),
        "n_values": sorted({n for n, _ in grid}),
        "k_values": sorted({k for _, k in grid}),
        "grid": [{"n": n, "k": k} for n, k in grid],
        "verified_at": now_iso(),
    }


def build_manifest(
    parent_dir: Path,
    *,
    smoke: bool,
    grid: tuple[tuple[int, int], ...],
) -> dict[str, Any]:
    configurations = [{"n": n, "k": k, "slug": slug_for(n, k)} for n, k in grid]
    return {
        "experiment_type": "hyperparameter testing",
        "design": "one-intent smoke test" if smoke else "complete 4x4 hyperparameter grid",
        "parent_dir": str(parent_dir.resolve()),
        "policy_model": POLICY_MODEL,
        "pipeline": PIPELINE_NAME,
        "datastore_setting": "pre-registered top-1 cosine similarity",
        "embedding_model": "text-embedding-3-small",
        "intent_count": 1 if smoke else EXPECTED_INTENTS,
        "independent_repetition_count": 1,
        "artifact_reuse_across_configurations": False,
        "smoke": smoke,
        "configuration_count": len(configurations),
        "n_values": sorted({item["n"] for item in configurations}),
        "k_values": sorted({item["k"] for item in configurations}),
        "configurations": configurations,
        "created_at": now_iso(),
    }


def load_or_create_parent(
    resume_dir: Path | None,
    *,
    smoke: bool,
    grid: tuple[tuple[int, int], ...],
) -> tuple[Path, dict[str, Any]]:
    EXPERIMENT_ROOT.mkdir(parents=True, exist_ok=True)
    if resume_dir is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if smoke:
            prefix = "smoke_gpt4o_mini_pre_registered_n10_k7"
        else:
            prefix = "gpt4o_mini_pre_registered_full_grid"
        parent_dir = EXPERIMENT_ROOT / f"{prefix}_{timestamp}"
        parent_dir.mkdir(parents=True, exist_ok=False)
        manifest = build_manifest(
            parent_dir,
            smoke=smoke,
            grid=grid,
        )
        write_json(parent_dir / "experiment_manifest.json", manifest)
        return parent_dir, manifest

    parent_dir = resume_dir.resolve()
    manifest_path = parent_dir / "experiment_manifest.json"
    if not manifest_path.exists():
        parent_dir.mkdir(parents=True, exist_ok=True)
        manifest = build_manifest(
            parent_dir,
            smoke=smoke,
            grid=grid,
        )
        write_json(manifest_path, manifest)
        return parent_dir, manifest
    manifest = read_json(manifest_path)
    expected = build_manifest(
        parent_dir,
        smoke=smoke,
        grid=grid,
    )
    keys = [
        "experiment_type", "design", "policy_model", "pipeline", "datastore_setting",
        "embedding_model", "intent_count", "independent_repetition_count",
        "artifact_reuse_across_configurations", "smoke", "configuration_count",
        "n_values", "k_values", "configurations",
    ]
    mismatches = [key for key in keys if manifest.get(key) != expected.get(key)]
    if mismatches:
        raise RuntimeError(f"Resume manifest mismatch for: {', '.join(mismatches)}")
    return parent_dir, manifest

def arm_is_complete(arm_dir: Path, n: int, intent_count: int) -> bool:
    aggregate_path = arm_dir / "aggregate_summary.json"
    if not aggregate_path.exists():
        return False
    aggregate = read_json(aggregate_path)
    if not aggregate.get("complete") or aggregate.get("intent_count") != intent_count:
        return False
    for intent_index in range(1, intent_count + 1):
        intent_dir = arm_dir / f"intent_{intent_index:03d}"
        if not main3._intent_result_is_complete(intent_dir, n):
            return False
    return True


def classify_delta(value: float | None) -> str | None:
    if value is None:
        return None
    if value > EPSILON:
        return "improved"
    if value < -EPSILON:
        return "worsened"
    return "unchanged"


def analyze_configuration(parent_dir: Path, n: int, k: int, intent_count: int) -> dict[str, Any]:
    arm_dir = parent_dir / slug_for(n, k)
    if not arm_is_complete(arm_dir, n, intent_count):
        raise RuntimeError(f"Configuration is incomplete: {arm_dir}")

    question_counts: list[int] = []
    before_ds: list[float] = []
    after_ds: list[float] = []
    before_sas: list[float] = []
    after_sas: list[float] = []
    before_syntax_passed = 0
    before_syntax_failed = 0
    after_syntax_passed = 0
    after_syntax_failed = 0
    before_policy_count = 0
    after_policy_count = 0
    ds_counts = {"improved": 0, "unchanged": 0, "worsened": 0}
    sas_counts = {"improved": 0, "unchanged": 0, "worsened": 0}

    for intent_index in range(1, intent_count + 1):
        intent_dir = arm_dir / f"intent_{intent_index:03d}"
        summary = read_json(intent_dir / "summary.json")
        questions_artifact = read_json(intent_dir / "clarification_questions.json")
        qa_artifact = read_json(intent_dir / "simulated_qa.json")
        if isinstance(questions_artifact, list):
            questions = questions_artifact
        elif isinstance(questions_artifact, dict) and isinstance(questions_artifact.get("questions"), list):
            questions = questions_artifact["questions"]
        else:
            raise RuntimeError(f"Unrecognized questions artifact shape: {intent_dir}")
        if not isinstance(qa_artifact, (list, dict)):
            raise RuntimeError(f"Unrecognized simulated Q&A artifact shape: {intent_dir}")
        if len(questions) > k:
            raise RuntimeError(f"Intent {intent_index} generated {len(questions)} questions with k={k}.")
        question_counts.append(len(questions))

        before_policy_count += len(list((intent_dir / "before_policies").glob("*.xml")))
        after_policy_count += len(list((intent_dir / "after_policies").glob("*.xml")))
        before_syntax_passed += int(summary["before_syntax"]["passed"])
        before_syntax_failed += int(summary["before_syntax"]["failed"])
        after_syntax_passed += int(summary["after_syntax"]["passed"])
        after_syntax_failed += int(summary["after_syntax"]["failed"])

        before_ds.append(float(summary["before_disagreement_score"]))
        after_ds.append(float(summary["after_disagreement_score"]))
        before_sas.append(float(summary["before_alignment_score"]))
        after_sas.append(float(summary["after_alignment_score"]))

        ds_label = classify_delta(float(summary["disagreement_delta"]))
        sas_label = classify_delta(float(summary["alignment_delta"]))
        if ds_label is not None:
            ds_counts[ds_label] += 1
        if sas_label is not None:
            sas_counts[sas_label] += 1

    expected_policy_count = intent_count * n
    if before_policy_count != expected_policy_count or after_policy_count != expected_policy_count:
        raise RuntimeError(
            f"{arm_dir} has {before_policy_count} before and {after_policy_count} after policies; "
            f"expected {expected_policy_count} each."
        )

    def average(values: list[float | int]) -> float:
        return sum(values) / len(values)

    before_total = before_syntax_passed + before_syntax_failed
    after_total = after_syntax_passed + after_syntax_failed
    state = read_json(parent_dir / "run_state.json") if (parent_dir / "run_state.json").exists() else {}
    arm_state = state.get("configurations", {}).get(slug_for(n, k), {})

    return {
        "n": n,
        "k": k,
        "average_actual_clarification_questions": average(question_counts),
        "maximum_actual_clarification_questions": max(question_counts),
        "before_syntax_passed": before_syntax_passed,
        "before_syntax_failed": before_syntax_failed,
        "before_syntax_percentage": 100.0 * before_syntax_passed / before_total,
        "after_syntax_passed": after_syntax_passed,
        "after_syntax_failed": after_syntax_failed,
        "after_syntax_percentage": 100.0 * after_syntax_passed / after_total,
        "before_disagreement_score": average(before_ds),
        "after_disagreement_score": average(after_ds),
        "disagreement_reduction": average(before_ds) - average(after_ds),
        "before_sas": average(before_sas),
        "after_sas": average(after_sas),
        "sas_gain": average(after_sas) - average(before_sas),
        "ds_improved_intents": ds_counts["improved"],
        "ds_unchanged_intents": ds_counts["unchanged"],
        "ds_worsened_intents": ds_counts["worsened"],
        "sas_improved_intents": sas_counts["improved"],
        "sas_unchanged_intents": sas_counts["unchanged"],
        "sas_worsened_intents": sas_counts["worsened"],
        "before_policy_count": before_policy_count,
        "after_policy_count": after_policy_count,
        "total_policy_generation_count": before_policy_count + after_policy_count,
        "runtime_seconds": arm_state.get("runtime_seconds"),
        "run_dir": str(arm_dir.resolve()),
        "pareto_optimal": False,
    }


def mark_pareto(rows: list[dict[str, Any]]) -> None:
    for candidate in rows:
        dominated = False
        for other in rows:
            if candidate is other:
                continue
            no_worse = (
                other["after_disagreement_score"] <= candidate["after_disagreement_score"]
                and other["after_sas"] >= candidate["after_sas"]
            )
            strictly_better = (
                other["after_disagreement_score"] < candidate["after_disagreement_score"]
                or other["after_sas"] > candidate["after_sas"]
            )
            if no_worse and strictly_better:
                dominated = True
                break
        candidate["pareto_optimal"] = not dominated


def fmt(value: Any, digits: int = 6) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def grouped_trends(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    values = sorted({int(row[key]) for row in rows})
    output = []
    for value in values:
        selected = [row for row in rows if int(row[key]) == value]
        output.append({
            key: value,
            "mean_after_ds": sum(row["after_disagreement_score"] for row in selected) / len(selected),
            "mean_after_sas": sum(row["after_sas"] for row in selected) / len(selected),
            "mean_after_syntax_percentage": sum(row["after_syntax_percentage"] for row in selected) / len(selected),
            "mean_actual_cq": sum(row["average_actual_clarification_questions"] for row in selected) / len(selected),
        })
    return output


def write_readme(
    parent_dir: Path,
    rows: list[dict[str, Any]],
    complete: bool,
) -> None:
    lines = [
        "# GPT-4o-Mini Hyperparameter Testing",
        "",
        f"Status: **{'complete' if complete else 'in progress'}**",
        "",
        "Each configuration is an independent pre-registered-datastore run over 50 intents. "
        "No before policies, clarification artifacts, after policies, or metrics are reused across configurations.",
        "",
        "## Primary Results",
        "",
        "| n | k | Avg. CQ | After syntax (%) | After DS | After SAS | Pareto |",
        "|---:|---:|---:|---:|---:|---:|:---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['n']} | {row['k']} | {fmt(row['average_actual_clarification_questions'], 3)} "
            f"| {fmt(row['after_syntax_percentage'], 2)} | {fmt(row['after_disagreement_score'])} "
            f"| {fmt(row['after_sas'])} | {'yes' if row['pareto_optimal'] else 'no'} |"
        )

    lines.extend([
        "",
        "## Full Metrics",
        "",
        "| n | k | Before syntax | After syntax | Before DS | After DS | DS reduction | Before SAS | After SAS | SAS gain | DS I/U/W | SAS I/U/W | Policies | Runtime (s) |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|---:|---:|",
    ])
    for row in rows:
        before_total = row["before_syntax_passed"] + row["before_syntax_failed"]
        after_total = row["after_syntax_passed"] + row["after_syntax_failed"]
        lines.append(
            f"| {row['n']} | {row['k']} | {row['before_syntax_passed']}/{before_total} "
            f"| {row['after_syntax_passed']}/{after_total} | {fmt(row['before_disagreement_score'])} "
            f"| {fmt(row['after_disagreement_score'])} | {fmt(row['disagreement_reduction'])} "
            f"| {fmt(row['before_sas'])} | {fmt(row['after_sas'])} | {fmt(row['sas_gain'])} "
            f"| {row['ds_improved_intents']}/{row['ds_unchanged_intents']}/{row['ds_worsened_intents']} "
            f"| {row['sas_improved_intents']}/{row['sas_unchanged_intents']}/{row['sas_worsened_intents']} "
            f"| {row['total_policy_generation_count']} | {fmt(row['runtime_seconds'], 1)} |"
        )

    if rows:
        lines.extend(["", "## Trends", "", "Averages grouped by `n`:", ""])
        for trend in grouped_trends(rows, "n"):
            lines.append(
                f"- n={trend['n']}: after DS {fmt(trend['mean_after_ds'])}, after SAS "
                f"{fmt(trend['mean_after_sas'])}, syntax {fmt(trend['mean_after_syntax_percentage'], 2)}%, "
                f"actual CQ {fmt(trend['mean_actual_cq'], 3)}."
            )
        lines.extend(["", "Averages grouped by `k`:", ""])
        for trend in grouped_trends(rows, "k"):
            lines.append(
                f"- k={trend['k']}: after DS {fmt(trend['mean_after_ds'])}, after SAS "
                f"{fmt(trend['mean_after_sas'])}, syntax {fmt(trend['mean_after_syntax_percentage'], 2)}%, "
                f"actual CQ {fmt(trend['mean_actual_cq'], 3)}."
            )
        pareto = [f"(n={row['n']}, k={row['k']})" for row in rows if row["pareto_optimal"]]
        lines.extend(["", "## Pareto Frontier", "", ", ".join(pareto)])

    lines.extend([
        "",
        "## Configuration",
        "",
        "- Policy, clarification-question, and simulator model: `gpt-4o-mini`",
        "- Datastore: pre-registered, deterministic top-1 cosine similarity",
        "- Embeddings: OpenAI `text-embedding-3-small`",
        "- Intents: 50",
        "- Independent repetitions per configuration: 1",
        "- Strict SAS semantics and existing DS implementation retained",
        "- Provider retries apply equally to before and after policy slots",
        "",
        "## Reproduction",
        "",
        "```bash",
        f"python scripts/run_hyperparameter_testing.py --resume-dir \"{parent_dir.resolve()}\"",
        f"python scripts/run_hyperparameter_testing.py --analyze-only --resume-dir \"{parent_dir.resolve()}\"",
        "```",
        "",
        "Machine-readable results are in `hyperparameter_results.csv` and `hyperparameter_results.json`.",
    ])
    (parent_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_grid_rows(
    parent_dir: Path,
    grid: tuple[tuple[int, int], ...],
    intent_count: int = EXPECTED_INTENTS,
) -> list[dict[str, Any]]:
    rows = []
    for n, k in grid:
        arm_dir = parent_dir / slug_for(n, k)
        if arm_is_complete(arm_dir, n, intent_count):
            rows.append(analyze_configuration(parent_dir, n, k, intent_count))
    rows.sort(key=lambda row: (row["n"], row["k"]))
    return rows


def write_parent_results(
    parent_dir: Path,
    grid: tuple[tuple[int, int], ...],
    *,
    require_complete: bool,
) -> list[dict[str, Any]]:
    rows = collect_grid_rows(parent_dir, grid)
    mark_pareto(rows)
    complete = len(rows) == len(grid)
    payload = {
        "complete": complete,
        "n_values": sorted({n for n, _ in grid}),
        "k_values": sorted({k for _, k in grid}),
        "completed_configuration_count": len(rows),
        "expected_configuration_count": len(grid),
        "generated_at": now_iso(),
        "rows": rows,
        "trends_by_n": grouped_trends(rows, "n") if rows else [],
        "trends_by_k": grouped_trends(rows, "k") if rows else [],
        "pareto_configurations": [
            {"n": row["n"], "k": row["k"]} for row in rows if row["pareto_optimal"]
        ],
    }
    write_json(parent_dir / "hyperparameter_results.json", payload)
    write_csv(parent_dir / "hyperparameter_results.csv", rows)
    write_readme(parent_dir, rows, complete)
    if require_complete and not complete:
        raise RuntimeError(f"Only {len(rows)}/{len(grid)} configurations are complete.")
    return rows


def run_smoke() -> Path:
    smoke_grid = ((10, 7),)
    validation = validate_inputs(smoke_grid)
    parent_dir, _ = load_or_create_parent(
        None,
        smoke=True,
        grid=smoke_grid,
    )
    write_json(parent_dir / "input_validation.json", validation)
    arm_dir = parent_dir / "n_10_k_07"
    main3.run_batch_experiment(
        n=10,
        k=7,
        limit=1,
        pipeline_name=PIPELINE_NAME,
        scenario_card_dir=main3.SCENARIO_CARD_DIR,
        policy_model=POLICY_MODEL,
        resume_dir=arm_dir,
    )
    if not arm_is_complete(arm_dir, 10, 1):
        raise RuntimeError("Excluded one-intent n=10/k=7 smoke experiment did not complete.")
    questions_artifact = read_json(arm_dir / "intent_001" / "clarification_questions.json")
    questions = questions_artifact.get("questions", []) if isinstance(questions_artifact, dict) else questions_artifact
    if not isinstance(questions, list) or len(questions) > 7:
        raise RuntimeError("Smoke experiment exceeded k=7 clarification questions.")
    print(f"Smoke experiment complete: {parent_dir}")
    return parent_dir


def run_grid(resume_dir: Path | None) -> Path:
    grid = HYPERPARAMETER_GRID
    validation = validate_inputs(grid)
    parent_dir, manifest = load_or_create_parent(
        resume_dir,
        smoke=False,
        grid=grid,
    )
    write_json(parent_dir / "input_validation.json", validation)

    state_path = parent_dir / "run_state.json"
    state = read_json(state_path) if state_path.exists() else {
        "parent_dir": str(parent_dir.resolve()),
        "created_at": manifest["created_at"],
        "configuration_count": len(grid),
        "configurations": {},
    }

    for n, k in grid:
        slug = slug_for(n, k)
        arm_dir = parent_dir / slug
        arm_state = state["configurations"].setdefault(slug, {"n": n, "k": k})
        if arm_is_complete(arm_dir, n, EXPECTED_INTENTS):
            arm_state["status"] = "complete"
            arm_state.setdefault("completed_at", now_iso())
            write_json(state_path, state)
            print(f"Skipping complete configuration {slug}")
            continue

        arm_state["status"] = "running"
        arm_state.setdefault("started_at", now_iso())
        invocation_start = time.perf_counter()
        write_json(state_path, state)
        print(f"Starting independent configuration {slug}: n={n}, k={k}")
        try:
            main3.run_batch_experiment(
                n=n,
                k=k,
                limit=None,
                pipeline_name=PIPELINE_NAME,
                scenario_card_dir=main3.SCENARIO_CARD_DIR,
                policy_model=POLICY_MODEL,
                resume_dir=arm_dir,
            )
        except BaseException as exc:
            elapsed = time.perf_counter() - invocation_start
            arm_state["runtime_seconds"] = float(arm_state.get("runtime_seconds", 0.0)) + elapsed
            arm_state["status"] = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
            arm_state["last_error"] = repr(exc)
            arm_state["updated_at"] = now_iso()
            write_json(state_path, state)
            write_parent_results(parent_dir, grid, require_complete=False)
            raise

        elapsed = time.perf_counter() - invocation_start
        arm_state["runtime_seconds"] = float(arm_state.get("runtime_seconds", 0.0)) + elapsed
        arm_state["status"] = "complete"
        arm_state["completed_at"] = now_iso()
        arm_state.pop("last_error", None)
        write_json(state_path, state)
        write_parent_results(parent_dir, grid, require_complete=False)

    state["complete"] = True
    state["completed_at"] = now_iso()
    write_json(state_path, state)
    write_parent_results(parent_dir, grid, require_complete=True)
    print(f"Complete 4x4 hyperparameter grid finished: {parent_dir}")
    return parent_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the complete 4x4 GPT-4o-mini n/k hyperparameter experiment."
    )
    parser.add_argument("--resume-dir", type=Path, default=None, help="Resume an existing grid parent directory")
    parser.add_argument("--smoke", action="store_true", help="Run one excluded n=10, k=7, one-intent smoke experiment")
    parser.add_argument("--verify-only", action="store_true", help="Verify inputs and local validation dependencies only")
    parser.add_argument("--analyze-only", action="store_true", help="Reconstruct reports from completed artifacts")
    args = parser.parse_args()

    selected_modes = sum((args.smoke, args.verify_only, args.analyze_only))
    if selected_modes > 1:
        parser.error("Choose at most one of --smoke, --verify-only, or --analyze-only.")
    if args.smoke and args.resume_dir is not None:
        parser.error("--smoke creates a new excluded run and cannot be combined with --resume-dir.")
    if args.analyze_only and args.resume_dir is None:
        parser.error("--analyze-only requires --resume-dir.")

    if args.verify_only:
        print(json.dumps(validate_inputs(HYPERPARAMETER_GRID), indent=2))
        return
    if args.smoke:
        run_smoke()
        return
    if args.analyze_only:
        parent_dir = args.resume_dir.resolve()
        write_parent_results(parent_dir, HYPERPARAMETER_GRID, require_complete=False)
        print(f"Rebuilt reports in: {parent_dir}")
        return
    run_grid(args.resume_dir)


if __name__ == "__main__":
    main()
