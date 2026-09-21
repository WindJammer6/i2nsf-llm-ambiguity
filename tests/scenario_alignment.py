"""Scenario alignment scoring

This module keeps the hidden scenario cards human-readable while providing a
machine-readable 43-slot rule-level target for deterministic scoring.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_DIR / "dataset"
DEFAULT_CARDS_DIR = DATASET_DIR / "hidden_scenario_cards"
DEFAULT_INTENTS_PATH = DATASET_DIR / "intents.csv"
DEFAULT_CLASSIFICATION_PATH = DATASET_DIR / "ground_truth" / "field_schema" / "i2nsf_cfi_field_classification.csv"
DEFAULT_ALIGNMENT_SLOTS_DIR = DATASET_DIR / "ground_truth" / "alignment_slots"
MISSING_VALUE = "<NOT_APPLICABLE>"
SLOT_ROOT_PREFIX = "/i2nsf-cfi-policy/rules/"

GROUP_TO_PATH_PREFIXES = {
    "Event": ["/i2nsf-cfi-policy/rules/event"],
    "Firewall Source": ["/i2nsf-cfi-policy/rules/condition/firewall/source"],
    "Firewall Destination": ["/i2nsf-cfi-policy/rules/condition/firewall/destination"],
    "Firewall Transport / Port / ICMP": [
        "/i2nsf-cfi-policy/rules/condition/firewall/transport-layer-protocol",
        "/i2nsf-cfi-policy/rules/condition/firewall/range-port-number",
        "/i2nsf-cfi-policy/rules/condition/firewall/icmp",
    ],
    "DDoS": ["/i2nsf-cfi-policy/rules/condition/ddos"],
    "Payload / Anti-virus": [
        "/i2nsf-cfi-policy/rules/condition/payload",
        "/i2nsf-cfi-policy/rules/condition/anti-virus",
    ],
    "URL Category": ["/i2nsf-cfi-policy/rules/condition/url-category"],
    "Voice": ["/i2nsf-cfi-policy/rules/condition/voice"],
    "Time Context": ["/i2nsf-cfi-policy/rules/condition/context/time"],
    "Application Context": ["/i2nsf-cfi-policy/rules/condition/context/application"],
    "Device-Type Context": ["/i2nsf-cfi-policy/rules/condition/context/device-type"],
    "Users Context": ["/i2nsf-cfi-policy/rules/condition/context/users"],
    "Geographic Location Context": ["/i2nsf-cfi-policy/rules/condition/context/geographic-location"],
    "Threat Feed": ["/i2nsf-cfi-policy/rules/condition/threat-feed"],
    "Primary Action": ["/i2nsf-cfi-policy/rules/action/primary-action"],
    "Secondary Logging Action": ["/i2nsf-cfi-policy/rules/action/secondary-action"],
}

ACTION_VALUES = {
    "pass",
    "drop",
    "reject",
    "mirror",
    "rate-limit",
    "invoke-signaling",
    "tunnel-encapsulation",
    "forwarding",
    "transformation",
}
LOG_ACTION_VALUES = {"rule-log", "session-log"}
SYSTEM_EVENT_VALUES = {"access-violation", "configuration-change"}
SYSTEM_ALARM_VALUES = {"memory-alarm", "cpu-alarm", "disk-alarm", "hardware-alarm", "interface-alarm"}
DEVICE_TYPE_VALUES = {
    "computer",
    "mobile-phone",
    "voip-vocn-phone",
    "tablet",
    "network-infrastructure-device",
    "iot-device",
    "ot",
    "vehicle",
}
APPLICATION_PROTOCOL_VALUES = {
    "http",
    "https",
    "http2",
    "https2",
    "ftp",
    "ssh",
    "telnet",
    "smtp",
    "pop3",
    "pop3s",
    "imap",
    "imaps",
}
TRANSPORT_PROTOCOL_VALUES = {"tcp", "udp", "sctp", "dccp"}
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
WEEKDAY_SET = DAYS[:5]


def load_rule_slot_paths(classification_path: Path) -> list[str]:
    with classification_path.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    paths = [
        row["path"].strip()
        for row in rows
        if row.get("path", "").startswith(SLOT_ROOT_PREFIX)
        and not re.fullmatch(r"/i2nsf-cfi-policy/rules/(name|priority)", row.get("path", ""))
    ]
    return paths


def source_group_for_path(path: str) -> str:
    for group, prefixes in GROUP_TO_PATH_PREFIXES.items():
        if any(path.startswith(prefix) for prefix in prefixes):
            return group
    return "Other"


def empty_slot_template(slot_paths: list[str]) -> dict[str, dict[str, Any]]:
    return {
        path: {
            "applicable": False,
            "expected": None,
            "source_group": source_group_for_path(path),
            "note": "Field is prohibited by the ground-truth scenario.",
        }
        for path in slot_paths
    }


def parse_card_sections(card_text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = None
    buffer: list[str] = []
    for line in card_text.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("-"):
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = stripped[:-1]
            buffer = []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer).strip()
    return sections


def parse_ground_truth(card_text: str) -> dict[str, str]:
    sections = parse_card_sections(card_text)
    ground_truth = sections.get("Ground Truth", "")
    result: dict[str, str] = {}
    for line in ground_truth.splitlines():
        match = re.match(r"^-\s*([^:]+):\s*(.*)$", line.strip())
        if match:
            result[match.group(1).strip()] = match.group(2).strip()
    return result


def is_not_applicable(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower().rstrip(".") in {"not applicable", "n/a", "none", "not specified"}


def split_csv_values(value: str) -> list[str]:
    return [part.strip().rstrip(".") for part in value.split(",") if part.strip()]


def plain_reference_value(value: str) -> str | list[str] | None:
    value = value.strip().rstrip(".")
    if is_not_applicable(value):
        return None
    values = split_csv_values(value)
    if len(values) > 1:
        if all(re.fullmatch(r"[A-Za-z0-9_.|:-]+", item) for item in values):
            return values
        return None
    if re.fullmatch(r"[A-Za-z0-9_.|:-]+", value):
        return value
    return None


def set_slot(slots: dict[str, dict[str, Any]], path: str, expected: Any, note: str = "") -> None:
    if path not in slots:
        return
    slots[path]["applicable"] = True
    slots[path]["expected"] = expected
    slots[path]["note"] = note or "Derived from hidden scenario card ground truth."


def note_slot(slots: dict[str, dict[str, Any]], path: str, note: str) -> None:
    if path in slots and not slots[path]["applicable"]:
        raise ValueError(
            f"Ground truth for {path} could not be converted to an exact required value. "
            f"Resolve it manually instead of treating the field as prohibited. {note}"
        )


def parse_event(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    system_events = re.findall(r"system-event:\s*([A-Za-z0-9_-]+)", value)
    system_alarms = re.findall(r"system-alarm:\s*([A-Za-z0-9_-]+)", value)
    system_events = [item for item in system_events if item in SYSTEM_EVENT_VALUES]
    system_alarms = [item for item in system_alarms if item in SYSTEM_ALARM_VALUES]
    if system_events:
        set_slot(slots, "/i2nsf-cfi-policy/rules/event/system-event", system_events if len(system_events) > 1 else system_events[0])
    if system_alarms:
        set_slot(slots, "/i2nsf-cfi-policy/rules/event/system-alarm", system_alarms if len(system_alarms) > 1 else system_alarms[0])


def parse_simple_reference(value: str, slots: dict[str, dict[str, Any]], path: str, label: str) -> None:
    expected = plain_reference_value(value)
    if expected is not None:
        set_slot(slots, path, expected, f"Derived from {label}.")
    elif not is_not_applicable(value):
        note_slot(slots, path, f"{label} contains prose that was not safely converted: {value}")


def parse_transport_port_icmp(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    lowered = value.lower()
    protocols = [item for item in TRANSPORT_PROTOCOL_VALUES if re.search(rf"\b{re.escape(item)}\b", lowered)]
    if protocols:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/firewall/transport-layer-protocol", protocols if len(protocols) > 1 else protocols[0])

    port_range = re.search(r"(?:ports?|range)\D+(\d{1,5})\D+(?:to|-|through)\D*(\d{1,5})", lowered)
    if port_range:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/firewall/range-port-number/start", port_range.group(1))
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/firewall/range-port-number/end", port_range.group(2))

    if "icmp" in lowered:
        if "ping" in lowered or "echo" in lowered:
            set_slot(slots, "/i2nsf-cfi-policy/rules/condition/firewall/icmp/message", "echo")
        else:
            note_slot(
                slots,
                "/i2nsf-cfi-policy/rules/condition/firewall/icmp/message",
                f"ICMP is mentioned but no exact ICMP message identity is specified: {value}",
            )


def parse_ddos(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    lowered = value.lower()
    packet = re.search(r"(\d+)\s+packets?\s+per\s+second", lowered)
    byte = re.search(r"(\d+)\s+bytes?\s+per\s+second", lowered)
    flow = re.search(r"(\d+)\s+(?:flows?|connection attempts?)\s+per\s+second", lowered)
    if packet:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/packet-rate-threshold", packet.group(1))
    if byte:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/byte-rate-threshold", byte.group(1))
    if flow:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/flow-rate-threshold", flow.group(1))
    if not (packet or byte or flow):
        for path in [
            "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/packet-rate-threshold",
            "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/byte-rate-threshold",
            "/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/flow-rate-threshold",
        ]:
            note_slot(slots, path, f"DDoS is mentioned but no exact threshold was specified: {value}")


def parse_payload_antivirus(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    expected = plain_reference_value(value)
    if expected is not None:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/payload/content", expected, "Derived from Payload / Anti-virus.")
    else:
        note_slot(slots, "/i2nsf-cfi-policy/rules/condition/payload/content", f"Payload/AV prose was not safely converted: {value}")


def parse_voice(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    source = re.search(r"source-id:\s*([A-Za-z0-9_.|:-]+)", value, flags=re.IGNORECASE)
    destination = re.search(r"destination-id:\s*([A-Za-z0-9_.|:-]+)", value, flags=re.IGNORECASE)
    target = re.search(r"targeting\s+(?:the\s+)?([A-Za-z0-9_.|:-]+)", value, flags=re.IGNORECASE)

    if source:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/voice/source-id", source.group(1), "Derived from Voice source-id.")
    if destination:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/voice/destination-id", destination.group(1), "Derived from Voice destination-id.")
    elif target:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/voice/destination-id", target.group(1), "Derived from Voice target.")
    if not (source or destination or target):
        note_slot(slots, "/i2nsf-cfi-policy/rules/condition/voice/source-id", f"Voice prose was not safely converted: {value}")
        note_slot(slots, "/i2nsf-cfi-policy/rules/condition/voice/destination-id", f"Voice prose was not safely converted: {value}")


def parse_time(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    lowered = value.lower()
    datetimes = re.findall(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b", value)
    if len(datetimes) >= 1:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/start-date-time", datetimes[0])
    if len(datetimes) >= 2:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/end-date-time", datetimes[1])

    period_text = value
    if ";" in value:
        period_text = value.split(";", 1)[1]
    time_values = re.findall(r"\b(\d{1,2}:\d{2})(?::\d{2})?\b", period_text)
    if len(time_values) >= 2:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/period/start-time", normalize_time(time_values[0]))
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/period/end-time", normalize_time(time_values[1]))
    if "monday to friday" in lowered or "monday-friday" in lowered or "weekdays" in lowered:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/period/day", WEEKDAY_SET)
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/frequency", "weekly")
    elif any(day in lowered for day in DAYS):
        days = [day for day in DAYS if day in lowered]
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/period/day", days)
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/time/frequency", "weekly")

def normalize_time(value: str) -> str:
    parts = value.split(":")
    hour = int(parts[0])
    minute = int(parts[1])
    return f"{hour:02d}:{minute:02d}:00Z"


def parse_application(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    lowered = value.lower()
    protocols = [item for item in APPLICATION_PROTOCOL_VALUES if re.search(rf"\b{re.escape(item)}\b", lowered)]
    if protocols:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/application/protocol", protocols if len(protocols) > 1 else protocols[0])
    else:
        note_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/application/protocol", f"Application context prose was not safely converted: {value}")


def parse_device_type(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    lowered = value.lower().rstrip(".")
    values = [item for item in DEVICE_TYPE_VALUES if item in lowered]
    if values:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/device-type/device", values if len(values) > 1 else values[0])


def parse_users(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    expected = plain_reference_value(value)
    if expected is not None:
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/users/group/name", expected, "Derived from Users Context.")
    else:
        note_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/users/group/name", f"Users context prose was not safely converted: {value}")


def parse_geographic(value: str, slots: dict[str, dict[str, Any]]) -> None:
    if is_not_applicable(value):
        return
    parts = [part.strip() for part in value.rstrip(".").split("|")]
    if len(parts) == 3 and all(parts):
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/country", parts[0])
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/region", parts[1])
        set_slot(slots, "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/city", parts[2])
    else:
        for path in [
            "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/country",
            "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/region",
            "/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/city",
        ]:
            note_slot(slots, path, f"Geographic context was not safely converted: {value}")


def generate_slots_from_card(intent_index: int, intent: str, card_text: str, slot_paths: list[str]) -> dict[str, Any]:
    slots = empty_slot_template(slot_paths)
    ground_truth = parse_ground_truth(card_text)

    parse_event(ground_truth.get("Event", ""), slots)
    parse_simple_reference(ground_truth.get("Firewall Source", ""), slots, "/i2nsf-cfi-policy/rules/condition/firewall/source", "Firewall Source")
    parse_simple_reference(ground_truth.get("Firewall Destination", ""), slots, "/i2nsf-cfi-policy/rules/condition/firewall/destination", "Firewall Destination")
    parse_transport_port_icmp(ground_truth.get("Firewall Transport / Port / ICMP", ""), slots)
    parse_ddos(ground_truth.get("DDoS", ""), slots)
    parse_payload_antivirus(ground_truth.get("Payload / Anti-virus", ""), slots)
    parse_simple_reference(ground_truth.get("URL Category", ""), slots, "/i2nsf-cfi-policy/rules/condition/url-category/url-name", "URL Category")
    parse_voice(ground_truth.get("Voice", ""), slots)
    parse_time(ground_truth.get("Time Context", ""), slots)
    parse_application(ground_truth.get("Application Context", ""), slots)
    parse_device_type(ground_truth.get("Device-Type Context", ""), slots)
    parse_users(ground_truth.get("Users Context", ""), slots)
    parse_geographic(ground_truth.get("Geographic Location Context", ""), slots)
    parse_simple_reference(ground_truth.get("Threat Feed", ""), slots, "/i2nsf-cfi-policy/rules/condition/threat-feed/name", "Threat Feed")

    primary_action = ground_truth.get("Primary Action", "").strip().rstrip(".")
    if primary_action in ACTION_VALUES:
        set_slot(slots, "/i2nsf-cfi-policy/rules/action/primary-action/action", primary_action, "Derived from Primary Action.")
    primary_action_limit = ground_truth.get("Primary Action Limit", "").strip().rstrip(".")
    limit_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:bytes?\s+per\s+second|bps|b/s)?", primary_action_limit, flags=re.IGNORECASE)
    if primary_action == "rate-limit" and limit_match:
        set_slot(slots, "/i2nsf-cfi-policy/rules/action/primary-action/limit", limit_match.group(1), "Derived from Primary Action Limit.")
    secondary_action = ground_truth.get("Secondary Logging Action", "").strip().rstrip(".")
    if secondary_action in LOG_ACTION_VALUES:
        set_slot(slots, "/i2nsf-cfi-policy/rules/action/secondary-action/log-action", secondary_action, "Derived from Secondary Logging Action.")

    return {
        "intent_index": intent_index,
        "intent": intent,
        "slot_count": len(slots),
        "slots": slots,
    }


def load_intents(dataset_path: Path) -> list[str]:
    with dataset_path.open(newline="", encoding="utf-8-sig") as f:
        return [row["intent"] for row in csv.DictReader(f) if row.get("intent")]


def generate_slot_files(cards_dir: Path, dataset_path: Path, classification_path: Path, output_dir: Path, limit: int | None = None) -> list[Path]:
    slot_paths = load_rule_slot_paths(classification_path)
    intents = load_intents(dataset_path)
    if limit is not None:
        intents = intents[:limit]
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for index, intent in enumerate(intents, start=1):
        card_path = cards_dir / f"intent{index}.txt"
        if not card_path.exists():
            continue
        slots = generate_slots_from_card(index, intent, card_path.read_text(encoding="utf-8"), slot_paths)
        output_path = output_dir / f"intent_{index:03d}_slots.json"
        output_path.write_text(json.dumps(slots, indent=2), encoding="utf-8")
        written.append(output_path)
    return written


def load_slot_file(slot_file: Path) -> dict[str, Any]:
    return json.loads(slot_file.read_text(encoding="utf-8"))


def local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def find_policy_root(xml_root: ET.Element) -> ET.Element | None:
    if local_name(xml_root.tag) == "i2nsf-cfi-policy":
        return xml_root
    for elem in xml_root.iter():
        if local_name(elem.tag) == "i2nsf-cfi-policy":
            return elem
    return None


def parse_xml_root(xml_path: Path) -> ET.Element:
    xml_text = xml_path.read_text(encoding="utf-8-sig")
    xml_text = re.sub(r"<\?xml[^>]*\?>", "", xml_text, count=1, flags=re.IGNORECASE).strip()
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        return ET.fromstring(f"<policy-artifacts>{xml_text}</policy-artifacts>")


def find_child_values(elements: list[ET.Element], parts: list[str]) -> list[str]:
    if not parts:
        values = []
        for elem in elements:
            text = elem.text.strip() if elem.text else ""
            if text:
                values.append(text)
        return values
    next_part = parts[0]
    children = []
    for elem in elements:
        children.extend([child for child in list(elem) if local_name(child.tag) == next_part])
    return find_child_values(children, parts[1:])


def extract_policy_slots(xml_path: Path, slot_paths: list[str]) -> dict[str, Any]:
    root = parse_xml_root(xml_path)
    policy_root = find_policy_root(root)
    if policy_root is None:
        raise ValueError("No <i2nsf-cfi-policy> section found.")

    extracted: dict[str, Any] = {}
    for path in slot_paths:
        parts = [part for part in path.split("/") if part]
        if parts and parts[0] == "i2nsf-cfi-policy":
            parts = parts[1:]
        values = find_child_values([policy_root], parts)
        extracted[path] = normalize_actual_values(values)
    return extracted


def normalize_scalar(value: Any) -> str:
    text = str(value).strip()
    for prefix in ("i2nsfmi:", "i2nsfcfi:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text


def normalize_expected(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return sorted({normalize_scalar(item) for item in value})
    return normalize_scalar(value)


def normalize_actual_values(values: list[str]) -> Any:
    normalized = [normalize_scalar(value) for value in values if normalize_scalar(value)]
    if not normalized:
        return None
    unique = sorted(set(normalized))
    if len(unique) == 1:
        return unique[0]
    return unique


def values_match(expected: Any, actual: Any) -> bool:
    expected_norm = normalize_expected(expected)
    actual_norm = normalize_expected(actual)
    if isinstance(expected_norm, list) or isinstance(actual_norm, list):
        expected_list = expected_norm if isinstance(expected_norm, list) else [expected_norm]
        actual_list = actual_norm if isinstance(actual_norm, list) else [actual_norm]
        return sorted(expected_list) == sorted(actual_list)
    return expected_norm == actual_norm


def has_actual_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return bool(value)
    return str(value).strip() != ""


def score_policy(xml_path: Path, slot_spec: dict[str, Any]) -> dict[str, Any]:
    slots = slot_spec["slots"]
    extracted = extract_policy_slots(xml_path, list(slots.keys()))
    applicable = [path for path, slot in slots.items() if slot.get("applicable")]
    matches = []
    mismatches = []
    missing = []
    extra = []
    ok_absent = []

    for path, slot in slots.items():
        expected = slot.get("expected")
        actual = extracted.get(path)
        if slot.get("applicable"):
            if not has_actual_value(actual):
                missing.append({"path": path, "expected": expected, "actual": None, "source_group": slot.get("source_group")})
            elif values_match(expected, actual):
                matches.append({"path": path, "expected": expected, "actual": actual, "source_group": slot.get("source_group")})
            else:
                mismatches.append({"path": path, "expected": expected, "actual": actual, "source_group": slot.get("source_group")})
        else:
            if has_actual_value(actual):
                extra.append({"path": path, "expected": None, "actual": actual, "source_group": slot.get("source_group")})
            else:
                ok_absent.append(path)

    applicable_count = len(applicable)
    match_count = len(matches)
    non_applicable_count = len(slots) - applicable_count
    prohibited_violation_count = len(extra)
    score_denominator = applicable_count + prohibited_violation_count
    score = match_count / score_denominator if score_denominator else 1.0
    prohibited_rate = prohibited_violation_count / non_applicable_count if non_applicable_count else 0.0
    return {
        "file": str(xml_path),
        "score": score,
        "score_denominator": score_denominator,
        "applicable_slot_count": applicable_count,
        "matched_count": match_count,
        "mismatched_count": len(mismatches),
        "missing_count": len(missing),
        "prohibited_slot_count": non_applicable_count,
        "prohibited_violation_count": prohibited_violation_count,
        "prohibited_behavior_rate": prohibited_rate,
        "extra_behavior_count": prohibited_violation_count,
        "extra_behavior_rate": prohibited_rate,
        "matches": matches,
        "mismatches": mismatches,
        "missing": missing,
        "prohibited_behavior": extra,
        "extra_behavior": extra,
    }


def average(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def score_policy_dir(policies_dir: Path, slot_spec: dict[str, Any], output_prefix: Path | None = None) -> dict[str, Any]:
    results = []
    for xml_path in sorted(policies_dir.glob("*.xml")):
        try:
            results.append(score_policy(xml_path, slot_spec))
        except Exception as exc:
            results.append({"file": str(xml_path), "error": str(exc), "score": None, "extra_behavior_rate": None})

    scores = [item["score"] for item in results if item.get("score") is not None]
    extra_rates = [item["extra_behavior_rate"] for item in results if item.get("extra_behavior_rate") is not None]
    summary = {
        "policy_count": len(results),
        "average_score": average(scores),
        "average_extra_behavior_rate": average(extra_rates),
        "applicable_slot_count": next((item.get("applicable_slot_count") for item in results if item.get("applicable_slot_count") is not None), None),
        "results": results,
    }

    if output_prefix is not None:
        output_prefix.with_suffix(".json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        write_alignment_csv(output_prefix.with_suffix(".csv"), summary)
    return summary


def write_alignment_csv(csv_path: Path, summary: dict[str, Any]) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "path", "status", "expected", "actual", "source_group"])
        writer.writeheader()
        for result in summary.get("results", []):
            file_name = result.get("file", "")
            if result.get("error"):
                writer.writerow({"file": file_name, "path": "", "status": "error", "expected": "", "actual": result["error"], "source_group": ""})
                continue
            for status, key in [("match", "matches"), ("mismatch", "mismatches"), ("missing", "missing"), ("extra", "extra_behavior")]:
                for item in result.get(key, []):
                    writer.writerow({
                        "file": file_name,
                        "path": item.get("path"),
                        "status": status,
                        "expected": json.dumps(item.get("expected"), ensure_ascii=False),
                        "actual": json.dumps(item.get("actual"), ensure_ascii=False),
                        "source_group": item.get("source_group", ""),
                    })


def score_experiment_dir(experiment_dir: Path, slot_dir: Path) -> dict[str, Any]:
    rows = []
    for intent_dir in sorted(experiment_dir.glob("intent_*")):
        match = re.search(r"intent_(\d+)$", intent_dir.name)
        if not match:
            continue
        intent_index = int(match.group(1))
        slot_file = slot_dir / f"intent_{intent_index:03d}_slots.json"
        if not slot_file.exists():
            continue
        slot_spec = load_slot_file(slot_file)
        (intent_dir / "ground_truth_slots.json").write_text(json.dumps(slot_spec, indent=2), encoding="utf-8")
        before = score_policy_dir(intent_dir / "before_policies", slot_spec, intent_dir / "before_alignment")
        after = score_policy_dir(intent_dir / "after_policies", slot_spec, intent_dir / "after_alignment")
        before_score = before.get("average_score")
        after_score = after.get("average_score")
        row = {
            "intent_index": intent_index,
            "before_alignment_score": before_score,
            "after_alignment_score": after_score,
            "alignment_delta": None if before_score is None or after_score is None else after_score - before_score,
            "before_extra_behavior_rate": before.get("average_extra_behavior_rate"),
            "after_extra_behavior_rate": after.get("average_extra_behavior_rate"),
        }
        rows.append(row)
        update_intent_summary(intent_dir, row)

    summary = summarize_alignment_rows(rows)
    update_experiment_summaries(experiment_dir, rows, summary)
    return summary


def alignment_row_fields() -> list[str]:
    return [
        "before_alignment_score",
        "after_alignment_score",
        "alignment_delta",
        "before_extra_behavior_rate",
        "after_extra_behavior_rate",
    ]


def update_intent_summary(intent_dir: Path, row: dict[str, Any]) -> None:
    summary_path = intent_dir / "summary.json"
    if not summary_path.exists():
        return
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    for field in alignment_row_fields():
        summary[field] = row.get(field)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def update_experiment_summaries(experiment_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    aggregate_path = experiment_dir / "aggregate_summary.json"
    if aggregate_path.exists():
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        for key, value in summary.items():
            if key != "rows":
                aggregate[key] = value
        aggregate_path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")

    summary_csv_path = experiment_dir / "summary.csv"
    if not summary_csv_path.exists():
        return
    with summary_csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    row_by_intent = {str(row["intent_index"]): row for row in rows}
    for field in alignment_row_fields():
        if field not in fieldnames:
            fieldnames.append(field)
    for csv_row in csv_rows:
        alignment_row = row_by_intent.get(str(csv_row.get("intent_index", "")))
        if not alignment_row:
            continue
        for field in alignment_row_fields():
            value = alignment_row.get(field)
            csv_row[field] = "" if value is None else value
    with summary_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

def summarize_alignment_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    before_scores = [row["before_alignment_score"] for row in rows if row.get("before_alignment_score") is not None]
    after_scores = [row["after_alignment_score"] for row in rows if row.get("after_alignment_score") is not None]
    deltas = [row["alignment_delta"] for row in rows if row.get("alignment_delta") is not None]
    before_extra = [row["before_extra_behavior_rate"] for row in rows if row.get("before_extra_behavior_rate") is not None]
    after_extra = [row["after_extra_behavior_rate"] for row in rows if row.get("after_extra_behavior_rate") is not None]
    return {
        "intent_count": len(rows),
        "average_before_alignment": average(before_scores),
        "average_after_alignment": average(after_scores),
        "average_alignment_delta": average(deltas),
        "average_before_extra_behavior_rate": average(before_extra),
        "average_after_extra_behavior_rate": average(after_extra),
        "improved_alignment_count": sum(1 for delta in deltas if delta > 0),
        "unchanged_alignment_count": sum(1 for delta in deltas if delta == 0),
        "worsened_alignment_count": sum(1 for delta in deltas if delta < 0),
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate and score 43-slot scenario alignment artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("generate-slots")
    gen.add_argument("--cards-dir", type=Path, default=DEFAULT_CARDS_DIR)
    gen.add_argument("--dataset", type=Path, default=DEFAULT_INTENTS_PATH)
    gen.add_argument("--classification", type=Path, default=DEFAULT_CLASSIFICATION_PATH)
    gen.add_argument("--output-dir", type=Path, default=DEFAULT_ALIGNMENT_SLOTS_DIR)
    gen.add_argument("--limit", type=int, default=None)

    score = subparsers.add_parser("score-experiment")
    score.add_argument("experiment_dir", type=Path)
    score.add_argument("--slot-dir", type=Path, default=DEFAULT_ALIGNMENT_SLOTS_DIR)
    score.add_argument("--output", type=Path, default=None)

    args = parser.parse_args()
    if args.command == "generate-slots":
        written = generate_slot_files(args.cards_dir, args.dataset, args.classification, args.output_dir, args.limit)
        print(json.dumps({"written": len(written), "output_dir": str(args.output_dir)}, indent=2))
    elif args.command == "score-experiment":
        summary = score_experiment_dir(args.experiment_dir, args.slot_dir)
        if args.output:
            args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()



