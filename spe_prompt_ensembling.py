"""Shared clarification-aware experts and one-shot yanglint audit for structured pipelines."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from helpers.llm_client import generate_text


DEFAULT_MODEL = None
PROJECT_DIR = Path(__file__).resolve().parent
YANG_MODULES_DIR = PROJECT_DIR / "tests" / "yang-modules"
YANG_SCHEMA = YANG_MODULES_DIR / "ietf-i2nsf-cons-facing-interface@2023-05-15.yang"
YANG_MONITORING_SCHEMA = YANG_MODULES_DIR / "ietf-i2nsf-monitoring-interface@2022-06-01.yang"

def call_policy_llm(system_prompt: str, user_content: str, model: str | None = DEFAULT_MODEL) -> str:
    """Call the configured policy-generation model and return plain text."""
    return generate_text(system_prompt, user_content, model=model)

def format_clarification_context(clarification_context: str | None, context_kind: str = "canonical") -> str:
    """Return a clarification-context block for final policy composition."""
    if not clarification_context or not clarification_context.strip():
        return ""
    if context_kind == "qa":
        return (
            "\n\nClarification Q&A context:\n"
            f"{clarification_context.strip()}\n\n"
            "Treat these clarification answers as authoritative for the policy author's intended behavior. "
            "Use them to resolve ambiguity from the original intent, but do not invent details beyond the "
            "original intent and these answers."
        )
    return (
        "\n\nCanonical resolved intent (authoritative, JSON):\n"
        f"{clarification_context.strip()}\n\n"
        "Use these field values and names exactly; do not invent alternative source, destination, "
        "traffic/application/content, time, location, action, logging, threshold, or threat-source group/feed names. "
        "If this canonical JSON conflicts with an ambiguous interpretation from the original intent, "
        "follow the canonical JSON. Do not invent details beyond the original intent and this JSON."
    )


def format_intent_context(
    original_intent: str,
    restated_intent: str | None = None,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
) -> str:
    """Format original/restated intent plus optional clarification Q&A for expert stages."""
    content = f"Original: {original_intent}"
    if restated_intent:
        content += f"\nRestated: {restated_intent}"
    clarification_block = format_clarification_context(clarification_context, clarification_context_kind)
    if clarification_block:
        content += clarification_block
    return content

def restate_intent(
    policy_intent: str,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    model: str | None = DEFAULT_MODEL,
) -> str:
    """Restate the policy intent in 'IF ... THEN ...' format."""
    system_prompt = (
        "You are a helpful assistant specialized in interpreting security policies. "
        "Restate the user's policy intent as a single conditional statement in the form: "
        "'IF <condition(s)> THEN <action(s)>.' "
        "If clarification Q&A is provided, treat the answers as authoritative when resolving ambiguity."
    )
    user_content = format_intent_context(policy_intent, None, clarification_context, clarification_context_kind)
    return call_policy_llm(system_prompt, user_content, model=model)

def extract_event_action(
    original_intent: str,
    restated_intent: str | None,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    model: str | None = DEFAULT_MODEL,
) -> str:
    """Phase 1: Extract event trigger(s) and action(s) from the policy."""
    system_prompt = (
        "You are an I2NSF policy expert focusing on events and actions. "
        "From the policy description and optional IF-THEN restatement when provided, list the event(s) that trigger the policy and the action(s) taken."

        "Regarding action(s), check if the intent asks for a secondary logging action. Include it if and ONLY if the intent asked for logging."
    )
    user_content = format_intent_context(original_intent, restated_intent, clarification_context, clarification_context_kind)
    return call_policy_llm(system_prompt, user_content, model=model)

def extract_conditions(
    original_intent: str,
    restated_intent: str | None,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    model: str | None = DEFAULT_MODEL,
) -> str:
    """Phase 2: Extract any additional conditions (firewall, context, etc.) from the policy."""
    system_prompt = (
        "You are an I2NSF policy expert focusing on conditions. "
        "Identify all conditions (e.g., source/destination, time, location, protocol) in the policy apart from the main event trigger."
    )
    user_content = format_intent_context(original_intent, restated_intent, clarification_context, clarification_context_kind)
    return call_policy_llm(system_prompt, user_content, model=model)

def extract_endpoint_groups_threat_feeds(
    original_intent: str,
    restated_intent: str | None,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    model: str | None = DEFAULT_MODEL,
) -> str:
    """Phase 3: Identify any endpoint groups, threat feed or list references in the policy."""
    system_prompt = (
        "You are an I2NSF threat intelligence assistant.\n"
        "Determine if the policy references any endpoints groups, threat feeds or known malicious lists\n."
		"- Always try to infer minimal, generic endpoint-group names from the intent (even if not explicit).\n"

    )
    user_content = format_intent_context(original_intent, restated_intent, clarification_context, clarification_context_kind)
    return call_policy_llm(system_prompt, user_content, model=model)

def extract_metadata(
    original_intent: str,
    restated_intent: str | None,
    clarification_context: str | None = None,
    clarification_context_kind: str = "qa",
    model: str | None = DEFAULT_MODEL,
) -> str:
    """Phase 4: Suggest metadata (policy name, rule name) for the policy."""        # language, priority, resolution strategy
    system_prompt = (
        "You are an I2NSF policy metadata assistant. "
        "Provide a policy name and rule name suitable for this policy. "
        "Do not include optional metadata fields: language, priority-usage, resolution-strategy, or rule-level priority. Assume a single-rule English policy setting."
        "Use descriptive names based on the intent and avoid spaces (use '_')."
    )
    user_content = format_intent_context(original_intent, restated_intent, clarification_context, clarification_context_kind)
    return call_policy_llm(system_prompt, user_content, model=model)

def require_yanglint() -> None:
    if shutil.which("yanglint") is None:
        raise RuntimeError("yanglint is required for syntactic validation but was not found on PATH.")
    if not YANG_SCHEMA.exists():
        raise RuntimeError(f"I2NSF YANG schema was not found: {YANG_SCHEMA}")
    if not YANG_MONITORING_SCHEMA.exists():
        raise RuntimeError(f"I2NSF monitoring YANG schema was not found: {YANG_MONITORING_SCHEMA}")


def run_yanglint(policy_xml: str) -> tuple[bool, str]:
    require_yanglint()
    with tempfile.NamedTemporaryFile("w", suffix=".xml", encoding="utf-8", delete=False) as tmp:
        tmp.write(policy_xml)
        tmp_path = Path(tmp.name)
    try:
        cmd = [
            "yanglint",
            "-e",
            "-p",
            str(YANG_MODULES_DIR),
            str(YANG_MONITORING_SCHEMA),
            str(YANG_SCHEMA),
            str(tmp_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
        has_error_text = "err" in output.lower() or "yanglint[e]" in output.lower()
        return result.returncode == 0 and not has_error_text, output
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
