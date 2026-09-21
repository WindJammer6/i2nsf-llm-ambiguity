"""Empty-datastore structured-output prompt ensembling pipeline.

This variant keeps the QA-top expert stages, replaces final XML composition with
provider-native structured outputs into PolicyAst, compiles XML deterministically, and runs
one final yanglint audit.
"""

import json
import os
from pathlib import Path

from spe_prompt_ensembling import (
    restate_intent,
    extract_event_action,
    extract_conditions,
    extract_endpoint_groups_threat_feeds,
    extract_metadata,
    run_yanglint,
)

from helpers.i2nsf_cfi_policy import (
    compose_policy_ast_structured,
    compile_rule_policy_xml,
    derive_datastore_requirements,
    build_placeholder_datastore_sections,
    concatenate_datastore_and_rule_sections,
)


def _trace_dir() -> Path | None:
    value = os.getenv("POLICY_GENERATION_TRACE_DIR")
    if not value:
        return None
    path = Path(value)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_trace(name: str, content: str) -> None:
    path = _trace_dir()
    if path is not None:
        (path / name).write_text(content or "", encoding="utf-8")


def _dump_trace(name: str, obj) -> None:
    _write_trace(name, json.dumps(obj, indent=2))


def main(
    policy_intent,
    clarification_context: str | None = None,
    clarification_context_kind: str = "canonical",
    use_restated_intent: bool = True,
):
    print("Original Policy Intent:", policy_intent, "\n")
    if clarification_context and clarification_context.strip():
        label = "Clarification Q&A context" if clarification_context_kind == "qa" else "Canonical resolved intent (authoritative, JSON)"
        print(f"{label}:\n", clarification_context.strip(), "\n")

    restated = restate_intent(policy_intent, clarification_context, clarification_context_kind) if use_restated_intent else None
    print("Restated Intent:", restated if restated else "(disabled)", "\n")

    event_action = extract_event_action(policy_intent, restated, clarification_context, clarification_context_kind)
    print("Extracted Events & Actions:", event_action, "\n")
    conditions = extract_conditions(policy_intent, restated, clarification_context, clarification_context_kind)
    print("Extracted Conditions:", conditions, "\n")
    feeds = extract_endpoint_groups_threat_feeds(policy_intent, restated, clarification_context, clarification_context_kind)
    print("Extracted Endpoint Groups and Threat Feeds:", feeds, "\n")
    metadata = extract_metadata(policy_intent, restated, clarification_context, clarification_context_kind)
    print("Extracted Metadata:", metadata, "\n")

    policy_ast = compose_policy_ast_structured(
        original_intent=policy_intent,
        restated_intent=restated,
        event_action=event_action,
        conditions=conditions,
        endpoint_groups_and_threat_feeds=feeds,
        metadata=metadata,
        clarification_context=clarification_context,
        clarification_context_kind=clarification_context_kind,
    )
    _dump_trace("policy_ast.json", policy_ast.model_dump(mode="json"))
    print("Structured Policy AST:\n", policy_ast.model_dump_json(indent=2), "\n")

    datastore_requirements = derive_datastore_requirements(policy_ast)
    _dump_trace("datastore_requirements.json", datastore_requirements)
    print("AST-Derived Datastore Requirements:\n", datastore_requirements, "\n")

    datastore_xml = build_placeholder_datastore_sections(
        datastore_requirements,
        fill_missing_location_keys=True,
    )
    _write_trace("datastore_sections.xml", datastore_xml)
    print("Generated Placeholder Datastore XML Sections:\n", datastore_xml, "\n")

    rule_xml = compile_rule_policy_xml(policy_ast)
    _write_trace("compiled_rule_policy.xml", rule_xml)
    final_policy_xml = concatenate_datastore_and_rule_sections(datastore_xml, rule_xml)
    _write_trace("compiled_policy.xml", final_policy_xml)
    print("Compiled I2NSF XML Policy Before Audit:\n", final_policy_xml)

    is_valid, yanglint_output = run_yanglint(final_policy_xml)
    _write_trace("final_yanglint.log", yanglint_output)
    print("yanglint audit passed." if is_valid else "yanglint audit failed.")
    if yanglint_output:
        print(yanglint_output)
    return final_policy_xml
