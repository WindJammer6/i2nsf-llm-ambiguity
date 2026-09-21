import argparse
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

import spe_empty_datastore as prompt_ensembling_pipeline_empty_datastore
import spe_pre_registered_datastore as prompt_ensembling_pipeline_pre_registered_datastore_top1
from tests import scenario_alignment
from helpers import datastore_object_retrieval as datastore_retrieval
from helpers import llm_client as policy_llm


PROJECT_DIR = Path(__file__).resolve().parent
DATASET_DIR = PROJECT_DIR / "dataset"
AMBIGUITY_ALIGNMENT_EXPERIMENT_DIR = PROJECT_DIR / "experiments" / "ambiguity and alignment"
DATASET_PATH = DATASET_DIR / "intents.csv"
SCENARIO_CARD_DIR = DATASET_DIR / "hidden_scenario_cards"
SCENARIO_ALIGNMENT_DIR = DATASET_DIR / "ground_truth" / "alignment_slots"
FIELD_CLASSIFICATION_PATH = DATASET_DIR / "ground_truth" / "field_schema" / "i2nsf_cfi_field_classification.csv"
PIPELINE_MODULES = {
    "empty": prompt_ensembling_pipeline_empty_datastore,
    "pre-registered-top1": prompt_ensembling_pipeline_pre_registered_datastore_top1,
}
PIPELINE_EXPERIMENT_PREFIXES = {
    "empty": "empty_datastore_structured_experiment",
    "pre-registered-top1": "pre_registered_datastore_top1_structured_experiment",
}

YANG_MODULES_DIR = PROJECT_DIR / "tests" / "yang-modules"
YANG_SCHEMA = YANG_MODULES_DIR / "ietf-i2nsf-cons-facing-interface@2023-05-15.yang"
YANG_MONITORING_SCHEMA = YANG_MODULES_DIR / "ietf-i2nsf-monitoring-interface@2022-06-01.yang"
MISSING_VALUE = "<NOT_APPLICABLE>"
METADATA_LEAF_NAMES = {
    "language",
    "priority",
    "priority-order",
    "priority-usage",
    "resolution-strategy",
}
DS_METRIC_VERSION = "behavioral-leaf-whitelist-v2"
BEHAVIORAL_DS_PATHS = frozenset(
    path.strip("/").replace("/", ".")
    for path in scenario_alignment.load_rule_slot_paths(FIELD_CLASSIFICATION_PATH)
)
POLICY_GENERATION_TRANSPORT_ATTEMPTS = 5
POLICY_GENERATION_RETRY_BASE_SECONDS = 10


def _is_retryable_generation_failure(captured_output: str) -> bool:
    """Return true only for failures where the provider did not return a policy."""
    lowered = captured_output.lower()
    retryable_markers = (
        "429",
        "500 internal",
        "502 bad gateway",
        "503 unavailable",
        "504 gateway",
        "connection error",
        "connection reset",
        "deadline exceeded",
        "high demand",
        "rate limit",
        "resource_exhausted",
        "service unavailable",
        "temporarily unavailable",
        "timeout",
        "timed out",
    )
    return any(marker in lowered for marker in retryable_markers)

def call_llm(system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 2048) -> str:
    """Route controller calls through the selected GPT or Gemini experiment arm."""
    return policy_llm.generate_text(
        system_prompt,
        user_prompt,
        temperature=temperature,
        max_output_tokens=max_tokens,
    )

def tee(message: str, logger: logging.Logger):
    print(message)
    logger.info(message)


def log_block(logger: logging.Logger, title: str, content: str):
    logger.info("\n" + "=" * 80)
    logger.info(title)
    logger.info("=" * 80)
    logger.info((content or "").rstrip())
    logger.info("=" * 80 + "\n")


def setup_logger(log_path: Path, logger_name: str) -> logging.Logger:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    return logger


def setup_single_run_logging() -> tuple[Path, Path, Path, logging.Logger]:
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = AMBIGUITY_ALIGNMENT_EXPERIMENT_DIR / run_timestamp
    before_dir = run_dir / "before_policies"
    after_dir = run_dir / "after_policies"
    before_dir.mkdir(parents=True, exist_ok=True)
    after_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logger(run_dir / "run.log", "main3_clarifygpt_single")
    return run_dir, before_dir, after_dir, logger


def setup_experiment_logging(
    pipeline_name: str,
    policy_model: str,
    resume_dir: Path | None = None,
) -> tuple[Path, logging.Logger]:
    model_slug = re.sub(r"[^a-z0-9]+", "_", policy_model.lower()).strip("_")
    if resume_dir is not None:
        experiment_dir = resume_dir.resolve()
        experiment_dir.mkdir(parents=True, exist_ok=True)
    else:
        run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        prefix = PIPELINE_EXPERIMENT_PREFIXES.get(pipeline_name, f"{pipeline_name}_experiment")
        experiment_dir = AMBIGUITY_ALIGNMENT_EXPERIMENT_DIR / f"{prefix}_{model_slug}_{run_timestamp}"
        experiment_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logger(experiment_dir / "experiment.log", f"main3_{pipeline_name}_{model_slug}_experiment")
    return experiment_dir, logger


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_tree(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_experiment_config(
    *,
    pipeline_name: str,
    policy_model: str,
    n: int,
    k: int,
    scenario_card_dir: Path,
) -> dict:
    retrieval_config = datastore_retrieval.retrieval_experiment_config()
    retrieval_config["enabled_for_pipeline"] = pipeline_name.startswith("pre-registered")
    selected_model = policy_llm.get_policy_generation_config()
    return {
        "experiment_type": "ambiguity and alignment",
        "pipeline": pipeline_name,
        "policy_generation": selected_model,
        "structured_output_enabled": True,
        "clarification_and_simulation": {
            "provider": selected_model["provider"],
            "model": selected_model["model"],
            "uses_selected_experiment_model": True,
            "clarification_temperature": 0.2,
            "simulator_temperature": 0.7,
        },
        "retrieval_and_embedding": retrieval_config,
        "dataset": str(DATASET_PATH),
        "dataset_sha256": sha256_file(DATASET_PATH),
        "scenario_cards_sha256": sha256_tree(scenario_card_dir),
        "alignment_slots_sha256": sha256_tree(SCENARIO_ALIGNMENT_DIR),
        "disagreement_metric": {
            "version": DS_METRIC_VERSION,
            "field_source": str(FIELD_CLASSIFICATION_PATH),
            "field_count": len(BEHAVIORAL_DS_PATHS),
        },
        "scenario_card_dir": str(scenario_card_dir),
        "n": n,
        "k": k,
        "comparison_control": (
            "The selected experiment model performs policy generation, clarification-question generation, "
            "and simulated answers. Pre-registered retrieval is deterministic top-1 cosine similarity. "
            "The OpenAI embedding provider/model, datastore contents, prompts, and metrics remain fixed."
        ),
    }

def extract_policy_xml(raw_policy: str) -> str:
    """
    Remove Markdown fences and surrounding prose while preserving the generated
    datastore and policy sections. The output keeps endpoint-groups,
    threat-prevention, and i2nsf-cfi-policy sections when the LLM produced them.
    """
    text = raw_policy.strip()
    text = re.sub(r"^```(?:xml)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)

    declaration_match = re.search(r"<\?xml[^>]*\?>", text, flags=re.IGNORECASE)
    declaration = declaration_match.group(0).strip() if declaration_match else '<?xml version="1.0" encoding="UTF-8"?>'

    section_names = ["endpoint-groups", "threat-prevention", "i2nsf-cfi-policy"]
    sections = []
    for section_name in section_names:
        match = re.search(
            rf"(<{section_name}\b[\s\S]*?</{section_name}>)",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            sections.append(match.group(1).strip())

    if sections:
        return declaration + "\n" + "\n\n".join(sections)

    first_xml = re.search(r"<\?xml[^>]*\?>|<(endpoint-groups|threat-prevention|i2nsf-cfi-policy)\b", text, flags=re.IGNORECASE)
    if first_xml:
        return text[first_xml.start():].strip()
    return text.strip()


def generate_one_policy(
    intent: str,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    generation_trace_dir: Path | None = None,
    pipeline_module=prompt_ensembling_pipeline_empty_datastore,
) -> tuple[str | None, str]:
    buffer = io.StringIO()
    previous_trace_dir = os.environ.get("POLICY_GENERATION_TRACE_DIR")
    try:
        if generation_trace_dir is not None:
            generation_trace_dir.mkdir(parents=True, exist_ok=True)
            os.environ["POLICY_GENERATION_TRACE_DIR"] = str(generation_trace_dir)
        with contextlib_redirect_stdout(buffer):
            raw_policy = pipeline_module.main(
                policy_intent=intent,
                clarification_context=clarification_context,
                clarification_context_kind=clarification_context_kind,
            )
        captured_output = buffer.getvalue()
        return extract_policy_xml(raw_policy), captured_output
    except Exception:
        captured_output = buffer.getvalue()
        captured_output += "\n\n[EXCEPTION]\n"
        captured_output += traceback.format_exc()
        return None, captured_output
    finally:
        if previous_trace_dir is None:
            os.environ.pop("POLICY_GENERATION_TRACE_DIR", None)
        else:
            os.environ["POLICY_GENERATION_TRACE_DIR"] = previous_trace_dir


class contextlib_redirect_stdout:
    def __init__(self, target):
        self.target = target
        self.old = None

    def __enter__(self):
        self.old = sys.stdout
        sys.stdout = self.target
        return self.target

    def __exit__(self, exc_type, exc, tb):
        sys.stdout = self.old
        return False


def generate_n_policies(
    intent: str,
    n: int,
    policies_dir: Path,
    logger: logging.Logger,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    label: str = "policy",
    trace_root_dir: Path | None = None,
    trace_label: str | None = None,
    pipeline_module=prompt_ensembling_pipeline_empty_datastore,
) -> tuple[list[str], list[str]]:
    policies = []
    generation_traces = []

    for i in range(n):
        policy_index = i + 1
        tee(f"Generating {label} {policy_index}/{n}...", logger)
        generation_trace_dir = None
        if trace_root_dir is not None:
            directory_label = trace_label or label.replace(" ", "_")
            generation_trace_dir = trace_root_dir / f"{directory_label}_{policy_index:03d}"
        captured_attempts = []
        xml_policy = None
        for transport_attempt in range(1, POLICY_GENERATION_TRANSPORT_ATTEMPTS + 1):
            xml_policy, captured_output = generate_one_policy(
                intent,
                clarification_context=clarification_context,
                clarification_context_kind=clarification_context_kind,
                generation_trace_dir=generation_trace_dir,
                pipeline_module=pipeline_module,
            )
            captured_attempts.append(
                f"[TRANSPORT ATTEMPT {transport_attempt}/{POLICY_GENERATION_TRANSPORT_ATTEMPTS}]\n"
                f"{captured_output}"
            )
            if xml_policy is not None:
                break
            if not _is_retryable_generation_failure(captured_output):
                break
            if transport_attempt < POLICY_GENERATION_TRANSPORT_ATTEMPTS:
                delay = POLICY_GENERATION_RETRY_BASE_SECONDS * transport_attempt
                tee(
                    f"[WARN] Transient provider failure for {label} {policy_index}; "
                    f"retrying the same policy slot in {delay}s "
                    f"({transport_attempt}/{POLICY_GENERATION_TRANSPORT_ATTEMPTS}).",
                    logger,
                )
                time.sleep(delay)

        captured_output = "\n\n".join(captured_attempts)

        log_block(logger, f"CAPTURED OUTPUT - {label.upper()} {policy_index}", captured_output)
        if generation_trace_dir is not None:
            generation_traces.append(str(generation_trace_dir))

        if xml_policy is None:
            tee(f"[WARN] Failed to generate {label} {policy_index}. See log.", logger)
            continue

        policy_path = policies_dir / f"policy_{policy_index:03d}.xml"
        policy_path.write_text(xml_policy, encoding="utf-8")
        policies.append(xml_policy)
        tee(f"Saved {label} {policy_index} to: {policy_path}", logger)

    return policies, generation_traces


CLARIFY_SYSTEM = """
You are a clarification-question generator for an I2NSF security policy system.

You will be given:
- the original user intent
- a behavioral disagreement summary, grouped by category (e.g. source, destination, time, action,
  event, logging, threshold, threat-feed, url/application, location), computed across n generated
  XML policies produced from that same intent
- a maximum target number k

Each category includes a disagreement score between 0 and 1 (higher means the generated policies
disagreed more on that category) and the distinct values observed across the generated policies.

Your task:
Using the disagreement summary, generate up to k clarification questions that would help the policy author
resolve the most important ambiguous fields.

Rules:
- Generate up to k questions.
- Use the disagreement scores to prioritize: categories with higher disagreement are more likely to need a clarification question
- Each question must ask about only one issue.
- The questions should be clear, concise, and answerable from the policy author's operational intent.
- Do not mention XML, YANG, schema paths, JSON, leafrefs, or I2NSF internal field names.
- Do not ask about formatting differences, policy names, rule names, namespaces, or indentation.

Return ONLY valid JSON in this format:
{
  "questions": [
    {"question": "...", "reason": "..."}
  ]
}
"""


SIMULATOR_SYSTEM = """
You are simulating the user who wrote a natural-language security policy intent.

You will receive:
- the original user intent
- a hidden user scenario card describing what the user really wants
- clarification questions from a policy-generation system

Answer each clarification question using only the hidden scenario card.

The hidden scenario card also contains a "Ground Truth" section. Treat that section as authoritative. If the prose scenario and Ground Truth seem different, prefer the Ground Truth.

Answering rules:
- Give concise, realistic answers from the user's operational intent.
- If the Ground Truth clearly specifies the answer, state it directly.
- If the question asks about a field or behavior marked "Not applicable" in Ground Truth, do not answer only "not applicable".
  Instead say: "No such requirement is specified; omit this from the policy."
- If the question offers multiple choices, choose only the option supported by the hidden scenario card.
- Do not add behavior beyond the hidden scenario card.
- Do not introduce XML, YANG, schema paths, datastore object names, field names, or implementation details unless the scenario card itself states them.
- If the scenario card names a concrete object, site, group, location, schedule, action, or logging requirement, preserve that wording.

Return ONLY valid JSON in this format:
{
  "answers": [
    {"question": "...", "answer": "..."}
  ]
}
"""


def parse_json_response(raw: str, fallback: dict) -> dict:
    raw_clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(raw_clean)
    except json.JSONDecodeError:
        return fallback


CATEGORY_PATH_RULES = [
    ("location", "geographic-location"),
    ("source", "firewall.source"),
    ("destination", "firewall.destination"),
    ("time", "context.time"),
    ("logging", "secondary-action"),
    ("logging", "log-action"),
    ("action", "primary-action"),
    ("threshold", "ddos"),
    ("threshold", "rate-limit"),
    ("transport", "firewall.transport-layer-protocol"),
    ("transport", "firewall.range-port-number"),
    ("transport", "firewall.icmp"),
    ("threat-feed", "threat-feed"),
    ("url-application", "url-category"),
    ("url-application", "context.application"),
    ("event", "event."),
    ("payload", "payload"),
    ("payload", "anti-virus"),
    ("voice", "voice"),
    ("device-type", "device-type"),
    ("users", "context.users"),
]


def categorize_disagreement_path(path: str) -> str:
    lowered = path.lower()
    for category, marker in CATEGORY_PATH_RULES:
        if marker in lowered:
            return category
    return "other"


def summarize_disagreement_by_category(disagreement: dict) -> dict:
    """Group per-field disagreement results into coarse behavioral categories."""
    categories: dict[str, dict] = {}
    for item in disagreement.get("field_results", []):
        category = categorize_disagreement_path(item["path"])
        if category == "other":
            raise ValueError(f"Behavioral DS path has no clarification category: {item['path']}")
        entry = categories.setdefault(category, {"disagreement": 0.0, "fields": []})
        entry["fields"].append({
            "path": item["path"],
            "disagreement": item["disagreement"],
            "values": item["values"],
        })
        entry["disagreement"] = max(entry["disagreement"], item["disagreement"])

    for entry in categories.values():
        entry["fields"].sort(key=lambda field: field["disagreement"], reverse=True)

    return dict(sorted(categories.items(), key=lambda kv: kv[1]["disagreement"], reverse=True))


def generate_clarification_questions_from_disagreement(
    intent: str,
    category_summary: dict,
    k: int,
    logger: logging.Logger,
) -> dict:
    user_prompt = f"""
Original user intent:
{intent}

Maximum number of clarification questions allowed:
{k}

Behavioral disagreement summary (by category):
{json.dumps(category_summary, indent=2)}
"""

    log_block(logger, "CLARIFICATION SYSTEM PROMPT", CLARIFY_SYSTEM)
    log_block(logger, "CLARIFICATION USER PROMPT", user_prompt)
    tee("Calling LLM to generate clarification questions...", logger)

    raw = call_llm(CLARIFY_SYSTEM, user_prompt, temperature=0.2, max_tokens=2048)
    log_block(logger, "RAW CLARIFICATION LLM RESPONSE", raw)

    fallback = {"questions": [{"question": raw, "reason": "Raw fallback because JSON parsing failed."}]}
    questions = parse_json_response(raw, fallback)
    questions["questions"] = questions.get("questions", [])[:k]
    return questions

def strip_qa_reason_for_pipeline(qa_pairs: list[dict]) -> list[dict]:
    """Keep only question/answer pairs in the context passed to policy generation."""
    stripped = []
    for pair in qa_pairs:
        stripped.append({
            "question": pair.get("question", ""),
            "answer": pair.get("answer", ""),
        })
    return stripped
def generate_simulated_answers(
    intent: str,
    scenario_card: str,
    questions: dict,
    logger: logging.Logger,
    qa_index: int,
) -> list[dict]:
    question_list = questions.get("questions", [])
    user_prompt = f"""
Original user intent:
{intent}

Hidden user scenario card:
{scenario_card}

Clarification questions:
{json.dumps(question_list, indent=2)}
"""

    log_block(logger, f"SIMULATOR USER PROMPT - Q&A SET {qa_index}", user_prompt)
    tee(f"Calling simulator LLM for Q&A set {qa_index}...", logger)

    raw = call_llm(SIMULATOR_SYSTEM, user_prompt, temperature=0.7, max_tokens=2048)
    log_block(logger, f"RAW SIMULATOR RESPONSE - Q&A SET {qa_index}", raw)

    fallback = {
        "answers": [
            {"question": q.get("question", ""), "answer": raw}
            for q in question_list
        ]
    }
    parsed = parse_json_response(raw, fallback)

    answers_by_question = {
        item.get("question", ""): item.get("answer", "")
        for item in parsed.get("answers", [])
    }

    qa_pairs = []
    for q in question_list:
        question_text = q.get("question", "")
        qa_pairs.append({
            "question": question_text,
            "reason": q.get("reason", ""),
            "answer": answers_by_question.get(question_text, ""),
        })

    return qa_pairs


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def find_cfi_policy_root(xml_root):
    if local_name(xml_root.tag) == "i2nsf-cfi-policy":
        return xml_root
    for elem in xml_root.iter():
        if local_name(elem.tag) == "i2nsf-cfi-policy":
            return elem
    return None


def child_tag_counts(elem):
    counts = Counter()
    for child in list(elem):
        counts[local_name(child.tag)] += 1
    return counts


def flatten_xml_leaves(elem, path=""):
    leaves = {}
    tag = local_name(elem.tag)
    current_path = f"{path}.{tag}" if path else tag
    children = list(elem)

    if not children:
        leaves[current_path] = elem.text.strip() if elem.text else ""
        return leaves

    counts = child_tag_counts(elem)
    seen = Counter()

    for child in children:
        child_tag = local_name(child.tag)
        if counts[child_tag] > 1:
            idx = seen[child_tag]
            seen[child_tag] += 1
            child_path = f"{current_path}.{child_tag}[{idx}]"
            leaves.update(flatten_xml_leaves_with_existing_path(child, child_path))
        else:
            leaves.update(flatten_xml_leaves(child, current_path))

    return leaves


def flatten_xml_leaves_with_existing_path(elem, current_path):
    leaves = {}
    children = list(elem)

    if not children:
        leaves[current_path] = elem.text.strip() if elem.text else ""
        return leaves

    counts = child_tag_counts(elem)
    seen = Counter()

    for child in children:
        child_tag = local_name(child.tag)
        if counts[child_tag] > 1:
            idx = seen[child_tag]
            seen[child_tag] += 1
            child_path = f"{current_path}.{child_tag}[{idx}]"
        else:
            child_path = f"{current_path}.{child_tag}"
        leaves.update(flatten_xml_leaves_with_existing_path(child, child_path))

    return leaves


def load_cfi_policy_leaves(xml_path: Path):
    xml_text = xml_path.read_text(encoding="utf-8-sig")
    xml_text = re.sub(r"<\?xml[^>]*\?>", "", xml_text, count=1, flags=re.IGNORECASE).strip()

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        root = ET.fromstring(f"<policy-artifacts>{xml_text}</policy-artifacts>")

    cfi_root = find_cfi_policy_root(root)
    if cfi_root is None:
        raise ValueError("No <i2nsf-cfi-policy> section found.")
    return flatten_xml_leaves(cfi_root)


def load_named_policies(policies_dir: Path):
    policies = []
    for xml_path in sorted(policies_dir.glob("*.xml")):
        leaves = load_cfi_policy_leaves(xml_path)
        policies.append((xml_path.name, leaves))
    return policies


def is_metadata_path(path: str) -> bool:
    """
    Exclude metadata leaves that do not affect network behavior in the
    single-rule, English-only experiment setting. Event fields remain included.
    """
    normalized_path = path.replace("[0]", "")
    leaf_name = normalized_path.rsplit(".", 1)[-1]

    if normalized_path in {"i2nsf-cfi-policy.name", "i2nsf-cfi-policy.rules.name"}:
        return True

    return leaf_name in METADATA_LEAF_NAMES


def normalize_disagreement_path(path: str) -> str:
    """Normalize repeated-list indices before matching schema leaf paths."""
    return re.sub(r"\[\d+\]", "", path)


def is_behavioral_disagreement_path(path: str) -> bool:
    """Return whether a flattened XML path is a supported behavior-bearing leaf."""
    return normalize_disagreement_path(path) in BEHAVIORAL_DS_PATHS

def compute_disagreement_score(named_policies):
    if len(named_policies) < 2:
        return {
            "metric_version": DS_METRIC_VERSION,
            "num_policies": len(named_policies),
            "num_fields": 0,
            "score": None,
            "field_results": [],
        }

    all_paths = sorted(
        path
        for path in {path for _, leaves in named_policies for path in leaves}
        if is_behavioral_disagreement_path(path)
    )
    field_results = []
    num_policies = len(named_policies)

    for path in all_paths:
        values = [leaves.get(path, MISSING_VALUE) for _, leaves in named_policies]
        counts = Counter(values)
        most_common_value, most_common_count = counts.most_common(1)[0]
        disagreement = 1.0 - (most_common_count / num_policies)
        field_results.append({
            "path": path,
            "disagreement": disagreement,
            "values": dict(counts),
            "most_common_value": most_common_value,
            "most_common_count": most_common_count,
        })

    overall_score = sum(item["disagreement"] for item in field_results) / len(field_results) if field_results else 0.0
    field_results.sort(key=lambda item: item["disagreement"], reverse=True)
    return {
        "metric_version": DS_METRIC_VERSION,
        "num_policies": num_policies,
        "num_fields": len(field_results),
        "score": overall_score,
        "field_results": field_results,
    }


def compute_disagreement_for_dir(policies_dir: Path, output_prefix: Path) -> dict:
    try:
        named_policies = load_named_policies(policies_dir)
        result = compute_disagreement_score(named_policies)
    except Exception as exc:
        result = {"error": str(exc), "num_policies": 0, "num_fields": 0, "score": None, "field_results": []}

    output_prefix.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    with output_prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "disagreement", "most_common_value", "most_common_count", "value_counts"])
        writer.writeheader()
        for item in result.get("field_results", []):
            writer.writerow({
                "path": item["path"],
                "disagreement": item["disagreement"],
                "most_common_value": item["most_common_value"],
                "most_common_count": item["most_common_count"],
                "value_counts": json.dumps(item["values"], ensure_ascii=False),
            })
    return result


def require_yanglint():
    if shutil.which("yanglint") is None:
        raise RuntimeError("yanglint is required for syntactic correctness but was not found on PATH.")
    if not YANG_SCHEMA.exists():
        raise RuntimeError(f"YANG schema not found: {YANG_SCHEMA}")
    if not YANG_MONITORING_SCHEMA.exists():
        raise RuntimeError(f"YANG monitoring schema not found: {YANG_MONITORING_SCHEMA}")


def validate_policy_file(xml_path: Path) -> dict:
    cmd = ["yanglint", "-e", "-p", str(YANG_MODULES_DIR), str(YANG_MONITORING_SCHEMA), str(YANG_SCHEMA), str(xml_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    passed = result.returncode == 0 and "err" not in output.lower() and "YANGLINT[E]" not in output
    return {
        "file": str(xml_path),
        "passed": passed,
        "returncode": result.returncode,
        "output": output,
    }


def validate_policy_dir(policies_dir: Path, output_path: Path) -> dict:
    results = [validate_policy_file(xml_path) for xml_path in sorted(policies_dir.glob("*.xml"))]
    summary = {
        "total": len(results),
        "passed": sum(1 for item in results if item["passed"]),
        "failed": sum(1 for item in results if not item["passed"]),
        "results": results,
    }
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load_intents(dataset_path: Path = DATASET_PATH) -> list[str]:
    with dataset_path.open(newline="", encoding="utf-8-sig") as f:
        return [row["intent"] for row in csv.DictReader(f) if row.get("intent")]


def load_scenario_card(intent_index: int, scenario_card_dir: Path = SCENARIO_CARD_DIR) -> tuple[Path, str]:
    card_path = scenario_card_dir / f"intent{intent_index}.txt"
    if not card_path.exists():
        raise FileNotFoundError(f"Missing hidden scenario card: {card_path}")
    return card_path, card_path.read_text(encoding="utf-8")


def run_single_intent_with_simulator(
    intent: str,
    scenario_card: str,
    n: int,
    k: int,
    run_dir: Path,
    before_dir: Path,
    after_dir: Path,
    logger: logging.Logger,
    pipeline_module=prompt_ensembling_pipeline_empty_datastore,
    ground_truth_slots=None,
) -> dict:
    tee(f"Intent: {intent}", logger)
    tee(f"n = {n}; k = {k}", logger)

    trace_root_dir = run_dir / "policy_generation_traces"
    before_policies, before_generation_traces = generate_n_policies(
        intent,
        n,
        before_dir,
        logger,
        label="before policy",
        trace_root_dir=trace_root_dir,
        trace_label="before_policy",
        pipeline_module=pipeline_module,
    )
    before_disagreement = compute_disagreement_for_dir(before_dir, run_dir / "before_disagreement")
    category_summary = summarize_disagreement_by_category(before_disagreement)
    (run_dir / "before_disagreement_categories.json").write_text(json.dumps(category_summary, indent=2), encoding="utf-8")

    questions = generate_clarification_questions_from_disagreement(intent, category_summary, k, logger)
    (run_dir / "clarification_questions.json").write_text(json.dumps(questions, indent=2), encoding="utf-8")

    qa_pairs = generate_simulated_answers(intent, scenario_card, questions, logger, 1)
    (run_dir / "simulated_qa.json").write_text(json.dumps(qa_pairs, indent=2), encoding="utf-8")

    pipeline_qa_pairs = strip_qa_reason_for_pipeline(qa_pairs)
    clarification_context = json.dumps({"questions_and_answers": pipeline_qa_pairs}, indent=2)
    (run_dir / "clarification_context.txt").write_text(clarification_context, encoding="utf-8")

    _, after_generation_traces = generate_n_policies(
        intent,
        n,
        after_dir,
        logger,
        clarification_context=clarification_context,
        clarification_context_kind="qa",
        label="after policy",
        trace_root_dir=trace_root_dir,
        trace_label="after_policy",
        pipeline_module=pipeline_module,
    )

    after_disagreement = compute_disagreement_for_dir(after_dir, run_dir / "after_disagreement")
    before_syntax = validate_policy_dir(before_dir, run_dir / "before_syntax.json")
    after_syntax = validate_policy_dir(after_dir, run_dir / "after_syntax.json")

    before_score = before_disagreement.get("score")
    after_score = after_disagreement.get("score")
    delta = None if before_score is None or after_score is None else before_score - after_score

    before_alignment = None
    after_alignment = None
    alignment_delta = None
    if ground_truth_slots is not None:
        (run_dir / "ground_truth_slots.json").write_text(json.dumps(ground_truth_slots, indent=2), encoding="utf-8")
        before_alignment = scenario_alignment.score_policy_dir(before_dir, ground_truth_slots, run_dir / "before_alignment")
        after_alignment = scenario_alignment.score_policy_dir(after_dir, ground_truth_slots, run_dir / "after_alignment")
        before_alignment_score = before_alignment.get("average_score")
        after_alignment_score = after_alignment.get("average_score")
        alignment_delta = None if before_alignment_score is None or after_alignment_score is None else after_alignment_score - before_alignment_score

    result = {
        "intent": intent,
        "n": n,
        "k": k,
        "run_dir": str(run_dir),
        "before_policies_dir": str(before_dir),
        "after_policies_dir": str(after_dir),
        "before_generation_traces": before_generation_traces,
        "after_generation_traces": after_generation_traces,
        "questions": questions,
        "simulated_qa": qa_pairs,
        "before_disagreement_score": before_score,
        "after_disagreement_score": after_score,
        "disagreement_delta": delta,
        "before_syntax": before_syntax,
        "after_syntax": after_syntax,
        "before_alignment_score": None if before_alignment is None else before_alignment.get("average_score"),
        "after_alignment_score": None if after_alignment is None else after_alignment.get("average_score"),
        "alignment_delta": alignment_delta,
        "before_extra_behavior_rate": None if before_alignment is None else before_alignment.get("average_extra_behavior_rate"),
        "after_extra_behavior_rate": None if after_alignment is None else after_alignment.get("average_extra_behavior_rate"),
    }
    (run_dir / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def load_or_generate_alignment_slots(intent_index: int, intent: str, scenario_card: str) -> dict:
    SCENARIO_ALIGNMENT_DIR.mkdir(parents=True, exist_ok=True)
    slot_file = SCENARIO_ALIGNMENT_DIR / f"intent_{intent_index:03d}_slots.json"
    if slot_file.exists():
        return scenario_alignment.load_slot_file(slot_file)

    slot_paths = scenario_alignment.load_rule_slot_paths(FIELD_CLASSIFICATION_PATH)
    slots = scenario_alignment.generate_slots_from_card(intent_index, intent, scenario_card, slot_paths)
    slot_file.write_text(json.dumps(slots, indent=2), encoding="utf-8")
    return slots


def _result_to_summary_row(
    *,
    intent_index: int,
    intent: str,
    card_path: Path,
    pipeline_name: str,
    policy_model: str,
    intent_dir: Path,
    result: dict,
) -> dict:
    return {
        "intent_index": intent_index,
        "intent": intent,
        "hidden_scenario_card": str(card_path),
        "pipeline": pipeline_name,
        "policy_model": policy_model,
        "policy_provider": policy_llm.get_policy_generation_config()["provider"],
        "run_dir": str(intent_dir),
        "before_disagreement_score": result["before_disagreement_score"],
        "after_disagreement_score": result["after_disagreement_score"],
        "disagreement_delta": result["disagreement_delta"],
        "before_syntax_passed": result["before_syntax"]["passed"],
        "before_syntax_failed": result["before_syntax"]["failed"],
        "after_syntax_passed": result["after_syntax"]["passed"],
        "after_syntax_failed": result["after_syntax"]["failed"],
        "before_alignment_score": result.get("before_alignment_score"),
        "after_alignment_score": result.get("after_alignment_score"),
        "alignment_delta": result.get("alignment_delta"),
        "before_extra_behavior_rate": result.get("before_extra_behavior_rate"),
        "after_extra_behavior_rate": result.get("after_extra_behavior_rate"),
    }


def _intent_result_is_complete(intent_dir: Path, n: int) -> bool:
    summary_path = intent_dir / "summary.json"
    if not summary_path.exists():
        return False
    if len(list((intent_dir / "before_policies").glob("*.xml"))) != n:
        return False
    if len(list((intent_dir / "after_policies").glob("*.xml"))) != n:
        return False
    try:
        result = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        result.get("before_syntax", {}).get("total") == n
        and result.get("after_syntax", {}).get("total") == n
        and (
            n == 1
            or (result.get("before_disagreement_score") is not None and result.get("after_disagreement_score") is not None)
        )
        and result.get("before_alignment_score") is not None
        and result.get("after_alignment_score") is not None
    )


def _validate_resume_config(existing: dict, requested: dict) -> None:
    checks = {
        "pipeline": (existing.get("pipeline"), requested.get("pipeline")),
        "model": (
            existing.get("policy_generation", {}).get("model"),
            requested.get("policy_generation", {}).get("model"),
        ),
        "n": (existing.get("n"), requested.get("n")),
        "k": (existing.get("k"), requested.get("k")),
        "dataset_sha256": (existing.get("dataset_sha256"), requested.get("dataset_sha256")),
        "scenario_cards_sha256": (
            existing.get("scenario_cards_sha256"),
            requested.get("scenario_cards_sha256"),
        ),
        "alignment_slots_sha256": (
            existing.get("alignment_slots_sha256"),
            requested.get("alignment_slots_sha256"),
        ),
        "datastore_sha256": (
            existing.get("retrieval_and_embedding", {}).get("datastore_sha256"),
            requested.get("retrieval_and_embedding", {}).get("datastore_sha256"),
        ),
    }
    mismatches = [f"{key}: existing={old!r}, requested={new!r}" for key, (old, new) in checks.items() if old != new]
    if mismatches:
        raise ValueError("Resume configuration mismatch:\n" + "\n".join(mismatches))


def run_batch_experiment(
    n: int = 5,
    k: int = 3,
    limit: int | None = None,
    pipeline_name: str = "empty",
    scenario_card_dir: Path = SCENARIO_CARD_DIR,
    policy_model: str = policy_llm.DEFAULT_POLICY_MODEL,
    resume_dir: Path | None = None,
    intent_indices: list[int] | None = None,
) -> dict:
    require_yanglint()
    policy_llm.configure_policy_model(policy_model)
    if pipeline_name not in PIPELINE_MODULES:
        raise ValueError(f"Unknown pipeline: {pipeline_name}")
    pipeline_module = PIPELINE_MODULES[pipeline_name]
    all_intents = load_intents()
    selected_intents = list(enumerate(all_intents, start=1))
    if limit is not None:
        selected_intents = selected_intents[:limit]
    if intent_indices is not None:
        requested_indices = list(dict.fromkeys(intent_indices))
        invalid_indices = [index for index in requested_indices if index < 1 or index > len(all_intents)]
        if invalid_indices:
            raise ValueError(f"Intent indices outside dataset range: {invalid_indices}")
        requested_set = set(requested_indices)
        selected_intents = [(index, intent) for index, intent in selected_intents if index in requested_set]
    experiment_dir, logger = setup_experiment_logging(pipeline_name, policy_model, resume_dir)
    experiment_config = build_experiment_config(
        pipeline_name=pipeline_name,
        policy_model=policy_model,
        n=n,
        k=k,
        scenario_card_dir=scenario_card_dir,
    )
    experiment_config["intent_indices"] = [index for index, _ in selected_intents]
    config_path = experiment_dir / "experiment_config.json"
    if resume_dir is not None and config_path.exists():
        existing_config = json.loads(config_path.read_text(encoding="utf-8"))
        _validate_resume_config(existing_config, experiment_config)
    else:
        config_path.write_text(json.dumps(experiment_config, indent=2), encoding="utf-8")

    tee(f"{pipeline_name} ClarifyGPT experiment", logger)
    tee(f"Experiment dir: {experiment_dir}", logger)
    tee(f"Experiment model: {policy_model} ({policy_llm.get_policy_generation_config()['provider']})", logger)
    tee(f"Dataset: {DATASET_PATH} ({len(selected_intents)} selected intents)", logger)
    tee(f"Scenario card dir: {scenario_card_dir}", logger)
    tee(f"n = {n}; k = {k}; resume = {resume_dir is not None}", logger)

    rows = []
    for selected_position, (intent_index, intent) in enumerate(selected_intents, start=1):
        intent_dir = experiment_dir / f"intent_{intent_index:03d}"
        card_path, scenario_card = load_scenario_card(intent_index, scenario_card_dir)

        if resume_dir is not None and _intent_result_is_complete(intent_dir, n):
            result = json.loads((intent_dir / "summary.json").read_text(encoding="utf-8"))
            rows.append(_result_to_summary_row(
                intent_index=intent_index,
                intent=intent,
                card_path=card_path,
                pipeline_name=pipeline_name,
                policy_model=policy_model,
                intent_dir=intent_dir,
                result=result,
            ))
            tee(f"Skipping completed intent {intent_index} ({selected_position}/{len(selected_intents)})", logger)
            continue

        if resume_dir is not None and intent_dir.exists():
            shutil.rmtree(intent_dir)
        before_dir = intent_dir / "before_policies"
        after_dir = intent_dir / "after_policies"
        before_dir.mkdir(parents=True, exist_ok=True)
        after_dir.mkdir(parents=True, exist_ok=True)
        intent_logger = setup_logger(intent_dir / "run.log", f"main3_intent_{intent_index:03d}")
        (intent_dir / "intent.txt").write_text(intent, encoding="utf-8")
        (intent_dir / "hidden_scenario_card.txt").write_text(scenario_card, encoding="utf-8")

        tee(f"\nRunning intent {intent_index} ({selected_position}/{len(selected_intents)}): {intent}", logger)
        ground_truth_slots = load_or_generate_alignment_slots(intent_index, intent, scenario_card)
        result = run_single_intent_with_simulator(
            intent,
            scenario_card,
            n,
            k,
            intent_dir,
            before_dir,
            after_dir,
            intent_logger,
            pipeline_module=pipeline_module,
            ground_truth_slots=ground_truth_slots,
        )
        if not _intent_result_is_complete(intent_dir, n):
            raise RuntimeError(f"Intent {intent_index} did not produce a complete {n}-before/{n}-after result set.")

        rows.append(_result_to_summary_row(
            intent_index=intent_index,
            intent=intent,
            card_path=card_path,
            pipeline_name=pipeline_name,
            policy_model=policy_model,
            intent_dir=intent_dir,
            result=result,
        ))
        append_summary_csv(experiment_dir / "summary.csv", rows)
        checkpoint = build_aggregate_summary(rows, n, k)
        checkpoint["policy_model"] = policy_model
        checkpoint["policy_provider"] = policy_llm.get_policy_generation_config()["provider"]
        checkpoint["complete"] = len(rows) == len(selected_intents)
        (experiment_dir / "aggregate_summary.json").write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")

    aggregate = build_aggregate_summary(rows, n, k)
    aggregate["policy_model"] = policy_model
    aggregate["policy_provider"] = policy_llm.get_policy_generation_config()["provider"]
    aggregate["complete"] = len(rows) == len(selected_intents)
    (experiment_dir / "aggregate_summary.json").write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    append_summary_csv(experiment_dir / "summary.csv", rows)
    tee(f"Experiment complete. Summary CSV: {experiment_dir / 'summary.csv'}", logger)
    return {"experiment_dir": str(experiment_dir), "rows": rows, "aggregate": aggregate}


def append_summary_csv(csv_path: Path, rows: list[dict]):
    if not rows:
        return
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def build_aggregate_summary(rows: list[dict], n: int, k: int) -> dict:
    before_scores = [float(row["before_disagreement_score"]) for row in rows if row["before_disagreement_score"] is not None]
    after_scores = [float(row["after_disagreement_score"]) for row in rows if row["after_disagreement_score"] is not None]
    deltas = [float(row["disagreement_delta"]) for row in rows if row["disagreement_delta"] is not None]
    before_alignment_scores = [float(row["before_alignment_score"]) for row in rows if row.get("before_alignment_score") is not None]
    after_alignment_scores = [float(row["after_alignment_score"]) for row in rows if row.get("after_alignment_score") is not None]
    alignment_deltas = [float(row["alignment_delta"]) for row in rows if row.get("alignment_delta") is not None]
    before_extra_rates = [float(row["before_extra_behavior_rate"]) for row in rows if row.get("before_extra_behavior_rate") is not None]
    after_extra_rates = [float(row["after_extra_behavior_rate"]) for row in rows if row.get("after_extra_behavior_rate") is not None]

    def avg(values):
        return sum(values) / len(values) if values else None

    return {
        "intent_count": len(rows),
        "n": n,
        "k": k,
        "average_before_disagreement": avg(before_scores),
        "average_after_disagreement": avg(after_scores),
        "average_disagreement_delta": avg(deltas),
        "total_before_syntax_passed": sum(int(row["before_syntax_passed"]) for row in rows),
        "total_before_syntax_failed": sum(int(row["before_syntax_failed"]) for row in rows),
        "total_after_syntax_passed": sum(int(row["after_syntax_passed"]) for row in rows),
        "total_after_syntax_failed": sum(int(row["after_syntax_failed"]) for row in rows),
        "average_before_alignment": avg(before_alignment_scores),
        "average_after_alignment": avg(after_alignment_scores),
        "average_alignment_delta": avg(alignment_deltas),
        "average_before_extra_behavior_rate": avg(before_extra_rates),
        "average_after_extra_behavior_rate": avg(after_extra_rates),
        "improved_alignment_count": sum(1 for delta in alignment_deltas if delta > 0),
        "unchanged_alignment_count": sum(1 for delta in alignment_deltas if delta == 0),
        "worsened_alignment_count": sum(1 for delta in alignment_deltas if delta < 0),
    }


def run_interactive_single(n: int = 5, k: int = 3, policy_model: str = policy_llm.DEFAULT_POLICY_MODEL):
    require_yanglint()
    policy_llm.configure_policy_model(policy_model)
    print("Describe the security policy intent you want to clarify.")
    intent = input("Your intent: ").strip()
    if not intent:
        print("No intent provided. Exiting.")
        return

    card_path = input("Path to hidden scenario card: ").strip()
    if not card_path:
        raise SystemExit("A hidden scenario card is required for simulated answers.")

    scenario_card = Path(card_path).read_text(encoding="utf-8")
    run_dir, before_dir, after_dir, logger = setup_single_run_logging()
    result = run_single_intent_with_simulator(intent, scenario_card, n, k, run_dir, before_dir, after_dir, logger)
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="SPE+HL I2NSF experiment runner")
    parser.add_argument("--experiment", action="store_true", help="Run all intents from dataset/intents.csv")
    parser.add_argument("--n", type=int, default=5, help="Number of policies to compare before/after clarification")
    parser.add_argument("--k", type=int, default=3, help="Number of clarification questions")
    parser.add_argument("--limit", type=int, default=None, help="Run only the first N intents")
    parser.add_argument("--pipeline", choices=sorted(PIPELINE_MODULES.keys()), default="empty", help="Policy generation pipeline to use")
    parser.add_argument("--policy-model", choices=sorted(policy_llm.POLICY_MODELS), default=policy_llm.DEFAULT_POLICY_MODEL, help="LLM used by all model-driven experiment stages")
    parser.add_argument("--scenario-card-dir", type=Path, default=SCENARIO_CARD_DIR, help="Directory containing intentN.txt hidden scenario cards")
    parser.add_argument("--resume-dir", type=Path, default=None, help="Resume an existing checkpointed experiment directory")
    parser.add_argument("--intent-ids", type=int, nargs="+", default=None, help="Run selected 1-based intent IDs")
    args = parser.parse_args()

    if args.experiment:
        result = run_batch_experiment(n=args.n, k=args.k, limit=args.limit, pipeline_name=args.pipeline, scenario_card_dir=args.scenario_card_dir, policy_model=args.policy_model, resume_dir=args.resume_dir, intent_indices=args.intent_ids)
        print(json.dumps(result["aggregate"], indent=2))
    else:
        run_interactive_single(n=args.n, k=args.k, policy_model=args.policy_model)


if __name__ == "__main__":
    main()













