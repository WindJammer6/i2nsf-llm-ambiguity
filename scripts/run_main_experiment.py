"""Run and analyze the four-arm ambiguity/alignment experiment matrix."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import spe_hl as main3

EXPERIMENT_ROOT = PROJECT_DIR / "experiments" / "ambiguity and alignment"
ARMS = [
    ("empty_gpt_4o_mini", "empty", "gpt-4o-mini"),
    ("pre_registered_gpt_4o_mini", "pre-registered-top1", "gpt-4o-mini"),
    ("empty_gemini_3_5_flash_lite", "empty", "gemini-3.5-flash-lite"),
    ("pre_registered_gemini_3_5_flash_lite", "pre-registered-top1", "gemini-3.5-flash-lite"),
]
MODEL_NOTE = (
    "Google returned 404 for both gemini-2.5-flash and gemini-2.5-flash-lite because they are unavailable "
    "to new users. The alternate-model arms therefore use the pinned gemini-3.5-flash-lite model, verified "
    "with Generate Content structured output, and must not be reported as Gemini 2.5 results."
)
GROUPS = [
    "Event",
    "Firewall Source",
    "Firewall Destination",
    "Firewall Transport / Port / ICMP",
    "DDoS",
    "Payload / Anti-virus",
    "URL Category",
    "Voice",
    "Time Context",
    "Application Context",
    "Device-Type Context",
    "Users Context",
    "Geographic Location Context",
    "Threat Feed",
    "Primary Action",
    "Secondary Logging Action",
]


def classify_ds_path(path: str) -> str:
    value = re.sub(r"\[\d+\]", "", path.lower())
    rules = [
        ("Event", ".event."),
        ("Firewall Source", ".condition.firewall.source"),
        ("Firewall Destination", ".condition.firewall.destination"),
        ("Firewall Transport / Port / ICMP", ".condition.firewall.transport-layer-protocol"),
        ("Firewall Transport / Port / ICMP", ".condition.firewall.range-port-number"),
        ("Firewall Transport / Port / ICMP", ".condition.firewall.icmp"),
        ("DDoS", ".condition.ddos"),
        ("Payload / Anti-virus", ".condition.payload"),
        ("Payload / Anti-virus", ".condition.anti-virus"),
        ("URL Category", ".condition.url-category"),
        ("Voice", ".condition.voice"),
        ("Time Context", ".condition.context.time"),
        ("Application Context", ".condition.context.application"),
        ("Device-Type Context", ".condition.context.device-type"),
        ("Users Context", ".condition.context.users"),
        ("Geographic Location Context", ".condition.context.geographic-location"),
        ("Threat Feed", ".condition.threat-feed"),
        ("Primary Action", ".action.primary-action"),
        ("Secondary Logging Action", ".action.secondary-action"),
    ]
    for group, marker in rules:
        if marker in value:
            return group
    raise ValueError(f"Unexpected DS path outside the behavioral category mapping: {path}")


def ds_path_to_slot(path: str) -> str:
    normalized = re.sub(r"\[\d+\]", "", path)
    return "/" + normalized.replace(".", "/")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def average(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def accumulate_ds(intent_dirs: list[Path], side: str) -> tuple[dict[str, float], dict[str, float], list[str]]:
    group_per_intent: list[dict[str, float]] = []
    slot_per_intent: list[dict[str, float]] = []
    for intent_dir in intent_dirs:
        data = read_json(intent_dir / f"{side}_disagreement.json")
        denominator = data.get("num_fields", 0)
        group_values: dict[str, float] = defaultdict(float)
        slot_values: dict[str, float] = defaultdict(float)
        if denominator:
            for item in data.get("field_results", []):
                contribution = float(item["disagreement"]) / denominator
                group = classify_ds_path(item["path"])
                group_values[group] += contribution
                slot_values[ds_path_to_slot(item["path"])] += contribution
        group_per_intent.append(group_values)
        slot_per_intent.append(slot_values)
    group_keys = set(GROUPS) | {key for values in group_per_intent for key in values}
    slot_keys = {key for values in slot_per_intent for key in values}
    groups = {key: sum(values.get(key, 0.0) for values in group_per_intent) / len(group_per_intent) for key in group_keys}
    slots = {key: sum(values.get(key, 0.0) for values in slot_per_intent) / len(slot_per_intent) for key in slot_keys}
    return groups, slots, []


def accumulate_sas(intent_dirs: list[Path], side: str) -> tuple[dict[str, dict], dict[str, dict]]:
    group_stats: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    slot_stats: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    policy_count = 0
    for intent_dir in intent_dirs:
        alignment = read_json(intent_dir / f"{side}_alignment.json")
        for policy in alignment.get("results", []):
            if policy.get("score") is None:
                continue
            policy_count += 1
            denominator = int(policy.get("score_denominator", 0))
            statuses = [
                ("match", policy.get("matches", [])),
                ("mismatch", policy.get("mismatches", [])),
                ("missing", policy.get("missing", [])),
                ("prohibited", policy.get("prohibited_behavior", [])),
            ]
            for status, items in statuses:
                for item in items:
                    group = item.get("source_group") or "Unmapped"
                    path = item["path"]
                    group_stats[group][status] += 1
                    slot_stats[path][status] += 1
                    if status == "match" and denominator:
                        group_stats[group]["contribution_sum"] += 1 / denominator
                        slot_stats[path]["contribution_sum"] += 1 / denominator
    def finalize(stats: dict[str, dict[str, float]]) -> dict[str, dict]:
        result = {}
        for key, values in stats.items():
            opportunities = values["match"] + values["mismatch"] + values["missing"] + values["prohibited"]
            result[key] = {
                "contribution": values["contribution_sum"] / policy_count if policy_count else None,
                "accuracy": values["match"] / opportunities if opportunities else None,
                "matches": int(values["match"]),
                "mismatches": int(values["mismatch"]),
                "missing": int(values["missing"]),
                "prohibited_violations": int(values["prohibited"]),
                "opportunities": int(opportunities),
                "policy_count": policy_count,
            }
        return result
    return finalize(group_stats), finalize(slot_stats)


def read_summary_rows(arm_dir: Path) -> list[dict[str, str]]:
    with (arm_dir / "summary.csv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def intent_change_counts(rows: list[dict[str, str]], key: str, good_positive: bool) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        raw = row.get(key)
        if raw in (None, ""):
            continue
        value = float(raw)
        effective = value if good_positive else -value
        if effective > 1e-12:
            counts["improved"] += 1
        elif effective < -1e-12:
            counts["worsened"] += 1
        else:
            counts["unchanged"] += 1
    return {name: counts[name] for name in ("improved", "unchanged", "worsened")}


def load_ground_truth_slot_groups() -> dict[str, str]:
    slot_file = main3.SCENARIO_ALIGNMENT_DIR / "intent_001_slots.json"
    slots = read_json(slot_file)["slots"]
    return {path: spec.get("source_group") or "Unmapped" for path, spec in slots.items()}


def analyze_arm(slug: str, arm_dir: Path) -> dict[str, Any]:
    intent_dirs = sorted(path for path in arm_dir.glob("intent_*" ) if path.is_dir())
    aggregate = read_json(arm_dir / "aggregate_summary.json")
    rows = read_summary_rows(arm_dir)
    before_ds_groups, before_ds_slots, before_unmapped = accumulate_ds(intent_dirs, "before")
    after_ds_groups, after_ds_slots, after_unmapped = accumulate_ds(intent_dirs, "after")
    before_sas_groups, before_sas_slots = accumulate_sas(intent_dirs, "before")
    after_sas_groups, after_sas_slots = accumulate_sas(intent_dirs, "after")

    group_rows = []
    for group in GROUPS + (["Unmapped"] if "Unmapped" in before_ds_groups or "Unmapped" in after_ds_groups else []):
        before_sas = before_sas_groups.get(group, {})
        after_sas = after_sas_groups.get(group, {})
        group_rows.append({
            "arm": slug,
            "field_group": group,
            "before_ds_contribution": before_ds_groups.get(group, 0.0),
            "after_ds_contribution": after_ds_groups.get(group, 0.0),
            "ds_reduction_contribution": before_ds_groups.get(group, 0.0) - after_ds_groups.get(group, 0.0),
            "before_sas_contribution": before_sas.get("contribution", 0.0),
            "after_sas_contribution": after_sas.get("contribution", 0.0),
            "sas_gain_contribution": (after_sas.get("contribution") or 0.0) - (before_sas.get("contribution") or 0.0),
            "before_sas_accuracy": before_sas.get("accuracy"),
            "after_sas_accuracy": after_sas.get("accuracy"),
            "before_matches": before_sas.get("matches", 0),
            "after_matches": after_sas.get("matches", 0),
            "before_mismatches": before_sas.get("mismatches", 0),
            "after_mismatches": after_sas.get("mismatches", 0),
            "before_missing": before_sas.get("missing", 0),
            "after_missing": after_sas.get("missing", 0),
            "before_prohibited_violations": before_sas.get("prohibited_violations", 0),
            "after_prohibited_violations": after_sas.get("prohibited_violations", 0),
        })

    slot_group_map = load_ground_truth_slot_groups()
    slot_paths = sorted(set(slot_group_map) | set(before_ds_slots) | set(after_ds_slots) | set(before_sas_slots) | set(after_sas_slots))
    slot_rows = []
    for path in slot_paths:
        before_sas = before_sas_slots.get(path, {})
        after_sas = after_sas_slots.get(path, {})
        slot_rows.append({
            "arm": slug,
            "path": path,
            "field_group": slot_group_map.get(path, classify_slot_group(path)),
            "before_ds_contribution": before_ds_slots.get(path, 0.0),
            "after_ds_contribution": after_ds_slots.get(path, 0.0),
            "ds_reduction_contribution": before_ds_slots.get(path, 0.0) - after_ds_slots.get(path, 0.0),
            "before_sas_contribution": before_sas.get("contribution", 0.0),
            "after_sas_contribution": after_sas.get("contribution", 0.0),
            "sas_gain_contribution": (after_sas.get("contribution") or 0.0) - (before_sas.get("contribution") or 0.0),
            "before_sas_accuracy": before_sas.get("accuracy"),
            "after_sas_accuracy": after_sas.get("accuracy"),
            "before_matches": before_sas.get("matches", 0),
            "after_matches": after_sas.get("matches", 0),
            "before_mismatches": before_sas.get("mismatches", 0),
            "after_mismatches": after_sas.get("mismatches", 0),
            "before_missing": before_sas.get("missing", 0),
            "after_missing": after_sas.get("missing", 0),
            "before_prohibited_violations": before_sas.get("prohibited_violations", 0),
            "after_prohibited_violations": after_sas.get("prohibited_violations", 0),
        })
    return {
        "slug": slug,
        "run_dir": str(arm_dir),
        "aggregate": aggregate,
        "ds_change_counts": intent_change_counts(rows, "disagreement_delta", good_positive=True),
        "sas_change_counts": intent_change_counts(rows, "alignment_delta", good_positive=True),
        "group_rows": group_rows,
        "slot_rows": slot_rows,
        "unmapped_ds_paths": sorted(set(before_unmapped) | set(after_unmapped)),
    }


def classify_slot_group(path: str) -> str:
    dotted = path.strip("/").replace("/", ".")
    return classify_ds_path(dotted)


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: Any, percent: bool = False) -> str:
    if value is None:
        return "n/a"
    number = float(value)
    return f"{number * 100:.2f}%" if percent else f"{number:.6f}"


def write_analysis(matrix_dir: Path, analyses: list[dict], smoke: bool) -> None:
    group_rows = [row for analysis in analyses for row in analysis["group_rows"]]
    slot_rows = [row for analysis in analyses for row in analysis["slot_rows"]]
    write_csv(matrix_dir / "field_contributions_16_groups.csv", group_rows)
    write_csv(matrix_dir / "field_contributions_43_slots.csv", slot_rows)
    payload = {analysis["slug"]: analysis for analysis in analyses}
    (matrix_dir / "field_contributions.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Ambiguity and Scenario Alignment Experiments",
        "",
        f"Matrix folder: `{matrix_dir}`",
        "Design: 50 intents, five before policies, up to three clarification questions, one simulated Q&A set, and five after policies.",
        "DS reduction is `before - after`; positive values are improvements.",
        "SAS gain is `after - before`; positive values are improvements.",
        "Pre-registered retrieval uses deterministic top-1 cosine similarity with fixed OpenAI `text-embedding-3-small` embeddings.",
        f"Model availability note: {MODEL_NOTE}",
        f"Smoke run excluded from primary results: `{str(smoke).lower()}`",
        "",
        "## Overall Results",
        "",
        "| Arm | Before syntax | After syntax | Before DS | After DS | DS reduction | Before SAS | After SAS | SAS gain | DS I/U/W | SAS I/U/W |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for analysis in analyses:
        aggregate = analysis["aggregate"]
        ds_counts = analysis["ds_change_counts"]
        sas_counts = analysis["sas_change_counts"]
        lines.append(
            f"| {analysis['slug']} | {aggregate['total_before_syntax_passed']}/{aggregate['intent_count'] * aggregate['n']} | "
            f"{aggregate['total_after_syntax_passed']}/{aggregate['intent_count'] * aggregate['n']} | "
            f"{fmt(aggregate['average_before_disagreement'])} | {fmt(aggregate['average_after_disagreement'])} | "
            f"{fmt(aggregate['average_disagreement_delta'])} | {fmt(aggregate['average_before_alignment'], True)} | "
            f"{fmt(aggregate['average_after_alignment'], True)} | {fmt(aggregate['average_alignment_delta'], True)} | "
            f"{ds_counts['improved']}/{ds_counts['unchanged']}/{ds_counts['worsened']} | "
            f"{sas_counts['improved']}/{sas_counts['unchanged']}/{sas_counts['worsened']} |"
        )
    lines.extend([
        "",
        "`I/U/W` means improved/unchanged/worsened intents.",
        "",
        "## 16 Behavioral-Group Contributions",
        "",
        "DS columns are weighted contributions that sum to overall DS. SAS columns are weighted matched-slot contributions that sum to average SAS.",
    ])
    for analysis in analyses:
        lines.extend([
            "",
            f"### {analysis['slug']}",
            "",
            "| Field group | Before DS | After DS | DS reduction | Before SAS | After SAS | SAS gain | Before/after SAS accuracy | Missing B/A | Prohibited B/A |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for row in analysis["group_rows"]:
            lines.append(
                f"| {row['field_group']} | {fmt(row['before_ds_contribution'])} | {fmt(row['after_ds_contribution'])} | "
                f"{fmt(row['ds_reduction_contribution'])} | {fmt(row['before_sas_contribution'], True)} | "
                f"{fmt(row['after_sas_contribution'], True)} | {fmt(row['sas_gain_contribution'], True)} | "
                f"{fmt(row['before_sas_accuracy'], True)}/{fmt(row['after_sas_accuracy'], True)} | "
                f"{row['before_missing']}/{row['after_missing']} | "
                f"{row['before_prohibited_violations']}/{row['after_prohibited_violations']} |"
            )
        if analysis["unmapped_ds_paths"]:
            lines.append("")
            lines.append("Unmapped DS paths: " + ", ".join(f"`{path}`" for path in analysis["unmapped_ds_paths"]))

    lines.extend(["", "## 43-Slot Appendix", ""])
    for analysis in analyses:
        lines.extend([
            f"### {analysis['slug']}",
            "",
            "| Slot | Group | DS B/A/reduction | SAS B/A/gain | Accuracy B/A | Missing B/A | Prohibited B/A |",
            "|---|---|---:|---:|---:|---:|---:|",
        ])
        for row in analysis["slot_rows"]:
            lines.append(
                f"| `{row['path']}` | {row['field_group']} | "
                f"{fmt(row['before_ds_contribution'])}/{fmt(row['after_ds_contribution'])}/{fmt(row['ds_reduction_contribution'])} | "
                f"{fmt(row['before_sas_contribution'], True)}/{fmt(row['after_sas_contribution'], True)}/{fmt(row['sas_gain_contribution'], True)} | "
                f"{fmt(row['before_sas_accuracy'], True)}/{fmt(row['after_sas_accuracy'], True)} | "
                f"{row['before_missing']}/{row['after_missing']} | "
                f"{row['before_prohibited_violations']}/{row['after_prohibited_violations']} |"
            )
        lines.append("")
    lines.extend([
        "## Reproduction",
        "",
        "```bash",
        "python3 scripts/run_main_experiment.py",
        "```",
        "",
        "Resume this matrix:",
        "",
        "```bash",
        f"python3 scripts/run_main_experiment.py --resume-dir \"{matrix_dir}\"",
        "```",
    ])
    content = "\n".join(lines) + "\n"
    (matrix_dir / "README.md").write_text(content, encoding="utf-8")
    if not smoke:
        (EXPERIMENT_ROOT / "README.md").write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()
    n = 1 if args.smoke else args.n
    limit = 1 if args.smoke else args.limit
    if args.resume_dir:
        matrix_dir = args.resume_dir.resolve()
    else:
        prefix = "smoke_matrix" if args.smoke else "matrix"
        matrix_dir = EXPERIMENT_ROOT / f"{prefix}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    matrix_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = matrix_dir / "matrix_manifest.json"
    manifest = {
        "n": n,
        "k": args.k,
        "limit": limit,
        "smoke": args.smoke,
        "arms": [{"slug": slug, "pipeline": pipeline, "model": model} for slug, pipeline, model in ARMS],
        "model_note": MODEL_NOTE,
        "disagreement_metric_version": main3.DS_METRIC_VERSION,
    }
    if manifest_path.exists():
        existing = read_json(manifest_path)
        if existing != manifest:
            raise ValueError("Resume matrix configuration does not match the existing manifest.")
    else:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if not args.analyze_only:
        for slug, pipeline, model in ARMS:
            print(f"\n=== {slug} ===", flush=True)
            main3.run_batch_experiment(
                n=n,
                k=args.k,
                limit=limit,
                pipeline_name=pipeline,
                scenario_card_dir=main3.SCENARIO_CARD_DIR,
                policy_model=model,
                resume_dir=matrix_dir / slug,
            )
    analyses = [analyze_arm(slug, matrix_dir / slug) for slug, _, _ in ARMS]
    write_analysis(matrix_dir, analyses, args.smoke)
    print(json.dumps({"matrix_dir": str(matrix_dir), "arms": [analysis["aggregate"] for analysis in analyses]}, indent=2))


if __name__ == "__main__":
    main()
