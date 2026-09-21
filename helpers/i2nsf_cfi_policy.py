"""Structured intermediate policy and deterministic XML conversion for I2NSF CFI policies."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from helpers.llm_client import generate_structured, get_policy_generation_config

NS_URI = "urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface"
MONITORING_NS_URI = "urn:ietf:params:xml:ns:yang:ietf-i2nsf-monitoring-interface"
NS = f"{{{NS_URI}}}"
HELPERS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = HELPERS_DIR.parent
YANG_MODULES_DIR = PROJECT_DIR / "tests" / "yang-modules"
SCHEMA_CATALOG_PATH = HELPERS_DIR / "i2nsf_cfi_schema_catalog.json"
CFI_MODULE = YANG_MODULES_DIR / "ietf-i2nsf-cons-facing-interface@2023-05-15.yang"

ET.register_namespace("", NS_URI)
ET.register_namespace("i2nsfmi", MONITORING_NS_URI)

FALLBACK_IDENTITIES = {
    "primary_action": ["pass", "drop", "reject", "mirror", "rate-limit", "invoke-signaling", "tunnel-encapsulation", "forwarding", "transformation"],
    "log_action": ["rule-log", "session-log"],
    "system_event": ["access-violation", "configuration-change"],
    "system_alarm": ["memory-alarm", "cpu-alarm", "disk-alarm", "hardware-alarm", "interface-alarm"],
    "transport_protocol": ["tcp", "udp", "sctp", "dccp"],
    "application_protocol": ["http", "https", "http2", "https2", "ftp", "ssh", "telnet", "smtp", "pop3", "pop3s", "imap", "imaps"],
    "device_type": ["computer", "mobile-phone", "voip-vocn-phone", "tablet", "network-infrastructure-device", "iot-device", "ot", "vehicle"],
    "icmp_message": ["echo-reply", "destination-unreachable", "redirect", "echo", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem", "experimental-mobility-protocols", "extended-echo-request", "extended-echo-reply", "port-unreachable", "request-no-error", "reply-no-error", "malformed-query", "no-such-interface", "no-such-table-entry", "multiple-interfaces-satisfy-query"],
    "ioc_format": ["stix", "misp", "openioc", "iodef"],
}
FREQUENCIES = ["only-once", "daily", "weekly", "monthly", "yearly"]
WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
GENERIC_ENDPOINTS_TO_OMIT = {"any", "all", "unknown"}
LITERAL_ENDPOINT_PATTERN = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[0-9a-fA-F:]+/\d{1,3})$")


def _strip_prefix(value: str) -> str:
    return value.split(":", 1)[-1] if ":" in value else value


def _identity_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    pattern = re.compile(r"\bidentity\s+([A-Za-z0-9_-]+)\s*\{", re.MULTILINE)
    for match in pattern.finditer(text):
        depth, pos = 1, match.end()
        while pos < len(text) and depth:
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
            pos += 1
        blocks.append((match.group(1), text[match.end():pos - 1]))
    return blocks


def _parse_identity_base_map(yang_dir: Path = YANG_MODULES_DIR) -> dict[str, list[str]]:
    base_map: dict[str, list[str]] = defaultdict(list)
    for path in sorted(yang_dir.glob("*.yang")):
        text = path.read_text(encoding="utf-8")
        for name, body in _identity_blocks(text):
            for base in re.findall(r"\bbase\s+([A-Za-z0-9_:-]+)\s*;", body):
                base_map[_strip_prefix(base)].append(name)
    return {base: sorted(set(children)) for base, children in base_map.items()}


def _descendants(base_map: dict[str, list[str]], base: str) -> list[str]:
    found: list[str] = []
    stack = list(base_map.get(base, []))
    while stack:
        item = stack.pop(0)
        if item in found:
            continue
        found.append(item)
        stack.extend(base_map.get(item, []))
    return found


def _parse_typedef_enums(module_text: str, typedef_name: str) -> list[str]:
    match = re.search(rf"\btypedef\s+{re.escape(typedef_name)}\s*\{{", module_text)
    if not match:
        return []
    depth, pos = 1, match.end()
    while pos < len(module_text) and depth:
        if module_text[pos] == "{":
            depth += 1
        elif module_text[pos] == "}":
            depth -= 1
        pos += 1
    return re.findall(r"\benum\s+([A-Za-z0-9_-]+)\s*\{", module_text[match.end():pos - 1])


def load_schema_catalog(force_refresh: bool = False) -> dict[str, Any]:
    if SCHEMA_CATALOG_PATH.exists() and not force_refresh:
        try:
            return json.loads(SCHEMA_CATALOG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    base_map = _parse_identity_base_map(YANG_MODULES_DIR)
    cfi_text = CFI_MODULE.read_text(encoding="utf-8") if CFI_MODULE.exists() else ""
    identities = {
        "primary_action": _descendants(base_map, "primary-action") or FALLBACK_IDENTITIES["primary_action"],
        "log_action": _descendants(base_map, "log-action") or FALLBACK_IDENTITIES["log_action"],
        "system_event": _descendants(base_map, "system-event") or FALLBACK_IDENTITIES["system_event"],
        "system_alarm": _descendants(base_map, "system-alarm") or FALLBACK_IDENTITIES["system_alarm"],
        "transport_protocol": _descendants(base_map, "transport-protocol") or FALLBACK_IDENTITIES["transport_protocol"],
        "application_protocol": _descendants(base_map, "application-protocol") or FALLBACK_IDENTITIES["application_protocol"],
        "device_type": _descendants(base_map, "device-type") or FALLBACK_IDENTITIES["device_type"],
        "icmp_message": _descendants(base_map, "icmp-message") or FALLBACK_IDENTITIES["icmp_message"],
        "ioc_format": _descendants(base_map, "ioc-format") or FALLBACK_IDENTITIES["ioc_format"],
    }
    for key, fallback in FALLBACK_IDENTITIES.items():
        identities[key] = [v for v in identities.get(key, []) if v not in {key, "event", "action"}] or fallback
    catalog = {
        "identities": identities,
        "typedef_enums": {"day": _parse_typedef_enums(cfi_text, "day") or WEEKDAYS, "frequency": FREQUENCIES},
        "placement": {"firewall": ["source", "destination", "transport-layer-protocol", "range-port-number", "icmp"], "condition": ["firewall", "ddos", "anti-virus", "payload", "url-category", "voice", "context", "threat-feed"], "context": ["time", "application", "device-type", "users", "geographic-location"]},
        "constraints": {"primary_action_limit_requires": "rate-limit", "period_requires_frequency_not": "only-once", "day_requires_frequency": "weekly", "date_requires_frequency": "monthly", "month_requires_frequency": "yearly", "location_group_key_order": ["country", "region", "city"]},
    }
    SCHEMA_CATALOG_PATH.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return catalog


def sanitize_schema_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    identities = catalog.get("identities", {})
    identities["primary_action"] = [
        value for value in identities.get("primary_action", [])
        if value not in {"primary-action", "ingress-action", "egress-action"}
    ] or FALLBACK_IDENTITIES["primary_action"]
    catalog["identities"] = identities
    return catalog


SCHEMA_CATALOG = sanitize_schema_catalog(load_schema_catalog())


def _enum(name: str, values: list[str]) -> type[Enum]:
    members: dict[str, str] = {}
    for value in values:
        key = re.sub(r"\W+", "_", value).strip("_").upper() or "VALUE"
        if key[0].isdigit():
            key = f"V_{key}"
        while key in members:
            key += "_"
        members[key] = value
    return Enum(name, members, type=str)


PrimaryAction = _enum("PrimaryAction", SCHEMA_CATALOG["identities"]["primary_action"])
LogAction = _enum("LogAction", SCHEMA_CATALOG["identities"]["log_action"])
SystemEvent = _enum("SystemEvent", SCHEMA_CATALOG["identities"]["system_event"])
SystemAlarm = _enum("SystemAlarm", SCHEMA_CATALOG["identities"]["system_alarm"])
TransportProtocol = _enum("TransportProtocol", SCHEMA_CATALOG["identities"]["transport_protocol"])
ApplicationProtocol = _enum("ApplicationProtocol", SCHEMA_CATALOG["identities"]["application_protocol"])
DeviceType = _enum("DeviceType", SCHEMA_CATALOG["identities"]["device_type"])
IcmpMessage = _enum("IcmpMessage", SCHEMA_CATALOG["identities"]["icmp_message"])
Frequency = _enum("Frequency", SCHEMA_CATALOG["typedef_enums"]["frequency"])
Day = _enum("Day", SCHEMA_CATALOG["typedef_enums"]["day"])

# ISO 3166-1 alpha-2 country codes. Used as a closed enum for location-group/country
# so structured outputs can only emit a schema-valid 2-letter code (length "2",
# pattern "[a-zA-Z]{2}"), never a human-readable name like "South Korea".
ISO_3166_1_ALPHA2 = (
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM "
    "BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX "
    "CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG "
    "GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR "
    "IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV "
    "LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE "
    "NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO "
    "RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF "
    "TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF "
    "WS YE YT ZA ZM ZW"
).split()
CountryCode = _enum("CountryCode", ISO_3166_1_ALPHA2)

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class EventAst(StrictModel):
    system_events: list[SystemEvent]
    system_alarms: list[SystemAlarm]


class PortRangeAst(StrictModel):
    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)


class FirewallAst(StrictModel):
    sources: list[str]
    destinations: list[str]
    transport_layer_protocols: list[TransportProtocol]
    port_ranges: list[PortRangeAst]
    icmp_messages: list[IcmpMessage]


class DdosAst(StrictModel):
    packet_rate_threshold: int | None = Field(ge=0)
    byte_rate_threshold: int | None = Field(ge=0)
    flow_rate_threshold: int | None = Field(ge=0)


class AntiVirusAst(StrictModel):
    profiles: list[str]
    exception_files: list[str]


class PayloadAst(StrictModel):
    content_refs: list[str]


class UrlCategoryAst(StrictModel):
    url_name: str | None


class VoiceAst(StrictModel):
    source_ids: list[str]
    destination_ids: list[str]
    user_agents: list[str]


class MonthRangeAst(StrictModel):
    start: str = Field(pattern=r"^\d{2}-\d{2}$")
    end: str = Field(pattern=r"^\d{2}-\d{2}$")


class PeriodAst(StrictModel):
    start_time: str | None = Field(..., description="Recurring time-of-day in hh:mm:ss form, e.g. '09:00:00'. Use this (not start_date_time) for repeating windows like business hours.")
    end_time: str | None = Field(..., description="Recurring time-of-day in hh:mm:ss form, e.g. '17:00:00'. Use this (not end_date_time) for repeating windows like business hours.")
    days: list[Day]
    dates: list[int]
    months: list[MonthRangeAst]


class TimeAst(StrictModel):
    start_date_time: str | None = Field(..., description="One-off absolute instant as a full RFC-3339 datetime, e.g. '2026-06-24T09:00:00Z'. Leave null for recurring schedules; use period.start_time instead.")
    end_date_time: str | None = Field(..., description="One-off absolute instant as a full RFC-3339 datetime, e.g. '2026-06-24T17:00:00Z'. Leave null for recurring schedules; use period.end_time instead.")
    frequency: Frequency | None
    period: PeriodAst


class UsersAst(StrictModel):
    user_ids: list[int]
    user_names: list[str]
    group_ids: list[int]
    group_names: list[str]


class LocationSideAst(StrictModel):
    country: CountryCode | None = Field(
        ...,
        description="ISO 3166-1 alpha-2 country code (exactly 2 letters), e.g. 'US' for United States, 'KR' for South Korea, 'SG' for Singapore. Never the full country name.",
    )
    region: str | None = Field(
        ...,
        description="ISO 3166-2 subdivision code of the form XX-YYY (5-6 chars), e.g. 'US-CA' for California, 'KR-11' for Seoul. Never the full region/state name.",
    )
    city: str | None = Field(..., description="City name in English (free text), e.g. 'San Francisco', 'Seoul'.")


class GeographicLocationAst(StrictModel):
    source: LocationSideAst
    destination: LocationSideAst


class ContextAst(StrictModel):
    time: TimeAst | None
    application_protocols: list[ApplicationProtocol]
    device_types: list[DeviceType]
    users: UsersAst
    geographic_location: GeographicLocationAst


class ConditionAst(StrictModel):
    firewall: FirewallAst
    ddos: DdosAst
    anti_virus: AntiVirusAst
    payload: PayloadAst
    url_category: UrlCategoryAst
    voice: VoiceAst
    context: ContextAst
    threat_feed_names: list[str]


class ActionAst(StrictModel):
    primary_action: PrimaryAction
    rate_limit: float | None
    secondary_log_action: LogAction | None


class PolicyAst(StrictModel):
    policy_name: str
    rule_name: str
    event: EventAst
    condition: ConditionAst
    action: ActionAst


def empty_policy_ast_template() -> dict[str, Any]:
    return {
        "policy_name": "descriptive_policy_name",
        "rule_name": "descriptive_rule_name",
        "event": {"system_events": [], "system_alarms": []},
        "condition": {
            "firewall": {"sources": [], "destinations": [], "transport_layer_protocols": [], "port_ranges": [], "icmp_messages": []},
            "ddos": {"packet_rate_threshold": None, "byte_rate_threshold": None, "flow_rate_threshold": None},
            "anti_virus": {"profiles": [], "exception_files": []},
            "payload": {"content_refs": []},
            "url_category": {"url_name": None},
            "voice": {"source_ids": [], "destination_ids": [], "user_agents": []},
            "context": {
                "time": None,
                "application_protocols": [],
                "device_types": [],
                "users": {"user_ids": [], "user_names": [], "group_ids": [], "group_names": []},
                "geographic_location": {"source": {"country": None, "region": None, "city": None}, "destination": {"country": None, "region": None, "city": None}},
            },
            "threat_feed_names": [],
        },
        "action": {"primary_action": "drop", "rate_limit": None, "secondary_log_action": None},
    }


def _safe_name(text: str, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_-]+", "_", (text or "").strip()).strip("_")
    return text[:80] or fallback


def _dedupe(values: list[Any]) -> list[Any]:
    seen, result = set(), []
    for value in values:
        key = str(value).strip()
        if key and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _text(parent: ET.Element, tag: str, value: Any) -> ET.Element:
    child = ET.SubElement(parent, f"{NS}{tag}")
    child.text = str(value)
    return child


def _enum_value(value: Any) -> str:
    return str(value.value) if isinstance(value, Enum) else str(value)


def _with_monitoring_prefix(value: str) -> str:
    value = str(value).strip()
    return value if not value or ":" in value else f"i2nsfmi:{value}"


def _is_generic_endpoint(value: str) -> bool:
    return value.strip().lower() in GENERIC_ENDPOINTS_TO_OMIT


def _is_literal_endpoint(value: str) -> bool:
    return bool(LITERAL_ENDPOINT_PATTERN.match(value.strip()))


def _has_monitoring_identityrefs(ast: PolicyAst) -> bool:
    c = ast.condition
    return bool(ast.event.system_events or ast.event.system_alarms or c.firewall.transport_layer_protocols or c.context.application_protocols)


def _element_to_string(elem: ET.Element) -> str:
    ET.indent(elem, space="  ")
    return ET.tostring(elem, encoding="unicode")

def _add_firewall(condition: ET.Element, firewall: FirewallAst) -> None:
    sources = [s for s in _dedupe(firewall.sources) if not _is_generic_endpoint(str(s))]
    destinations = [d for d in _dedupe(firewall.destinations) if not _is_generic_endpoint(str(d))]
    protocols = _dedupe([_enum_value(v) for v in firewall.transport_layer_protocols])
    icmp_messages = _dedupe([_enum_value(v) for v in firewall.icmp_messages])
    if not (sources or destinations or protocols or firewall.port_ranges or icmp_messages):
        return
    elem = ET.SubElement(condition, f"{NS}firewall")
    for source in sources:
        _text(elem, "source", source)
    for destination in destinations:
        _text(elem, "destination", destination)
    for protocol in protocols[:1]:
        _text(elem, "transport-layer-protocol", _with_monitoring_prefix(protocol))
    for port_range in firewall.port_ranges:
        start = max(0, min(65535, int(port_range.start)))
        end = max(start, min(65535, int(port_range.end)))
        r = ET.SubElement(elem, f"{NS}range-port-number")
        _text(r, "start", start)
        _text(r, "end", end)
    if icmp_messages:
        icmp = ET.SubElement(elem, f"{NS}icmp")
        for message in icmp_messages:
            _text(icmp, "message", message)


# Time-of-day for the cons-facing `time` typedef: hh:mm:ss[.f] with optional tz.
_TIME_OF_DAY_RE = re.compile(
    r"^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d)(\.\d+)?)?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?$"
)
# Full RFC-3339 date-and-time for start-date-time / end-date-time.
_DATE_TIME_RE = re.compile(
    r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?"
    r"(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?$"
)


def _normalize_time_of_day(value: str | None) -> str | None:
    """Coerce a clock time into a schema-valid `time` value (hh:mm:ss[.f][tz]), or None."""
    if not value:
        return None
    v = value.strip()
    # If a full datetime was placed in a time-of-day slot, keep only the time part.
    dt = re.match(r"^\d{4}-\d{2}-\d{2}T(.+)$", v)
    if dt:
        v = dt.group(1)
    m = _TIME_OF_DAY_RE.match(v)
    if not m:
        return None
    hh, mm, ss, frac, tz = m.groups()
    return f"{hh}:{mm}:{ss or '00'}{frac or ''}{tz or ''}"


def _normalize_date_time(value: str | None) -> str | None:
    """Return a schema-valid RFC-3339 date-and-time, padding missing seconds, or None."""
    if not value:
        return None
    v = value.strip()
    if _DATE_TIME_RE.match(v):
        return v
    # Pad missing seconds: YYYY-MM-DDThh:mm[tz] -> YYYY-MM-DDThh:mm:00[tz].
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T([01]\d|2[0-3]):[0-5]\d)(Z|[+-]\d{2}:\d{2})?$", v)
    if m:
        candidate = f"{m.group(1)}:00{m.group(3) or ''}"
        if _DATE_TIME_RE.match(candidate):
            return candidate
    return None


def _add_time(context: ET.Element, time_ast: TimeAst) -> None:
    period = time_ast.period
    # Normalize the period time-of-day leaves up front (e.g. "09:00" -> "09:00:00").
    period_start = _normalize_time_of_day(period.start_time)
    period_end = _normalize_time_of_day(period.end_time)
    # The absolute leaves require a full RFC-3339 datetime. If the model instead put a
    # recurring clock time there (the "business hours" case), reroute it into the period.
    start_dt = _normalize_date_time(time_ast.start_date_time)
    end_dt = _normalize_date_time(time_ast.end_date_time)
    rerouted = False
    if start_dt is None and time_ast.start_date_time:
        tod = _normalize_time_of_day(time_ast.start_date_time)
        if tod:
            period_start = period_start or tod
            rerouted = True
    if end_dt is None and time_ast.end_date_time:
        tod = _normalize_time_of_day(time_ast.end_date_time)
        if tod:
            period_end = period_end or tod
            rerouted = True

    days = [_enum_value(d) for d in period.days]
    dates = [int(d) for d in period.dates if 1 <= int(d) <= 31]
    months = period.months
    has_period_content = bool(period_start or period_end or days or dates or months)
    frequency = _enum_value(time_ast.frequency) if time_ast.frequency is not None else None
    if days:
        frequency = "weekly"
    elif dates:
        frequency = "monthly"
    elif months:
        frequency = "yearly"
    elif has_period_content and (not frequency or frequency == "only-once"):
        frequency = "daily"
    if rerouted and (not frequency or frequency == "only-once"):
        frequency = "daily"
    if frequency == "only-once":
        has_period_content = False
    if not (start_dt or end_dt or has_period_content or frequency):
        return
    elem = ET.SubElement(context, f"{NS}time")
    if start_dt:
        _text(elem, "start-date-time", start_dt)
    if end_dt:
        _text(elem, "end-date-time", end_dt)
    if has_period_content:
        p = ET.SubElement(elem, f"{NS}period")
        if period_start:
            _text(p, "start-time", period_start)
        if period_end:
            _text(p, "end-time", period_end)
        if frequency == "weekly":
            for day in days or WEEKDAYS:
                _text(p, "day", day)
        elif frequency == "monthly":
            for date in dates:
                _text(p, "date", date)
        elif frequency == "yearly":
            for month in months:
                m = ET.SubElement(p, f"{NS}month")
                _text(m, "start", month.start)
                _text(m, "end", month.end)
    if frequency and frequency != "only-once":
        _text(elem, "frequency", frequency)


def _add_context(condition: ET.Element, context_ast: ContextAst) -> None:
    context = ET.Element(f"{NS}context")
    if context_ast.time is not None:
        _add_time(context, context_ast.time)
    application_protocols = _dedupe([_enum_value(v) for v in context_ast.application_protocols])
    if application_protocols:
        app = ET.SubElement(context, f"{NS}application")
        for protocol in application_protocols:
            _text(app, "protocol", _with_monitoring_prefix(protocol))
    device_types = _dedupe([_enum_value(v) for v in context_ast.device_types])
    if device_types:
        dev = ET.SubElement(context, f"{NS}device-type")
        for device_type in device_types:
            _text(dev, "device", device_type)
    users_ast = context_ast.users
    if users_ast.user_ids or users_ast.user_names or users_ast.group_ids or users_ast.group_names:
        users = ET.SubElement(context, f"{NS}users")
        for idx, user_id in enumerate(users_ast.user_ids):
            user = ET.SubElement(users, f"{NS}user")
            _text(user, "id", int(user_id))
            if idx < len(users_ast.user_names):
                _text(user, "name", users_ast.user_names[idx])
        for idx, group_id in enumerate(users_ast.group_ids):
            group = ET.SubElement(users, f"{NS}group")
            _text(group, "id", int(group_id))
            if idx < len(users_ast.group_names):
                _text(group, "name", users_ast.group_names[idx])
    geo = context_ast.geographic_location
    if any([geo.source.country, geo.source.region, geo.source.city, geo.destination.country, geo.destination.region, geo.destination.city]):
        ge = ET.SubElement(context, f"{NS}geographic-location")
        for side_name, side in (("source", geo.source), ("destination", geo.destination)):
            if not any([side.country, side.region, side.city]):
                continue
            side_elem = ET.SubElement(ge, f"{NS}{side_name}")
            if side.country:
                _text(side_elem, "country", side.country)
            if side.region:
                _text(side_elem, "region", side.region)
            if side.city:
                _text(side_elem, "city", side.city)
    if len(context):
        condition.append(context)


def compile_rule_policy_xml(ast: PolicyAst) -> str:
    root = ET.Element(f"{NS}i2nsf-cfi-policy")
    if _has_monitoring_identityrefs(ast):
        root.set("xmlns:i2nsfmi", MONITORING_NS_URI)
    _text(root, "name", _safe_name(ast.policy_name, "generated_policy"))
    rule = ET.SubElement(root, f"{NS}rules")
    _text(rule, "name", _safe_name(ast.rule_name, "generated_rule"))

    if ast.event.system_events or ast.event.system_alarms:
        event = ET.SubElement(rule, f"{NS}event")
        for value in _dedupe([_enum_value(v) for v in ast.event.system_events]):
            _text(event, "system-event", _with_monitoring_prefix(value))
        for value in _dedupe([_enum_value(v) for v in ast.event.system_alarms]):
            _text(event, "system-alarm", _with_monitoring_prefix(value))

    condition = ET.SubElement(rule, f"{NS}condition")
    c = ast.condition
    _add_firewall(condition, c.firewall)
    if any(v is not None for v in [c.ddos.packet_rate_threshold, c.ddos.byte_rate_threshold, c.ddos.flow_rate_threshold]):
        ddos = ET.SubElement(condition, f"{NS}ddos")
        rate = ET.SubElement(ddos, f"{NS}rate-limit")
        if c.ddos.packet_rate_threshold is not None:
            _text(rate, "packet-rate-threshold", int(c.ddos.packet_rate_threshold))
        if c.ddos.byte_rate_threshold is not None:
            _text(rate, "byte-rate-threshold", int(c.ddos.byte_rate_threshold))
        if c.ddos.flow_rate_threshold is not None:
            _text(rate, "flow-rate-threshold", int(c.ddos.flow_rate_threshold))
    if c.anti_virus.profiles or c.anti_virus.exception_files:
        av = ET.SubElement(condition, f"{NS}anti-virus")
        for profile in _dedupe(c.anti_virus.profiles):
            _text(av, "profile", profile)
        for exception in _dedupe(c.anti_virus.exception_files):
            _text(av, "exception-files", exception)
    if c.payload.content_refs:
        payload = ET.SubElement(condition, f"{NS}payload")
        for ref in _dedupe(c.payload.content_refs):
            _text(payload, "content", ref)
    if c.url_category.url_name:
        url = ET.SubElement(condition, f"{NS}url-category")
        _text(url, "url-name", c.url_category.url_name)
    if c.voice.source_ids or c.voice.destination_ids or c.voice.user_agents:
        voice = ET.SubElement(condition, f"{NS}voice")
        for ref in _dedupe(c.voice.source_ids):
            _text(voice, "source-id", ref)
        for ref in _dedupe(c.voice.destination_ids):
            _text(voice, "destination-id", ref)
        for ua in _dedupe(c.voice.user_agents):
            _text(voice, "user-agent", ua)
    _add_context(condition, c.context)
    if c.threat_feed_names:
        threat = ET.SubElement(condition, f"{NS}threat-feed")
        for name in _dedupe(c.threat_feed_names):
            _text(threat, "name", name)

    action = ET.SubElement(rule, f"{NS}action")
    primary = ET.SubElement(action, f"{NS}primary-action")
    primary_action = _enum_value(ast.action.primary_action)
    _text(primary, "action", primary_action)
    if primary_action == "rate-limit" and ast.action.rate_limit is not None:
        _text(primary, "limit", ast.action.rate_limit)
    if ast.action.secondary_log_action is not None:
        secondary = ET.SubElement(action, f"{NS}secondary-action")
        _text(secondary, "log-action", _enum_value(ast.action.secondary_log_action))
    return _element_to_string(root)

_ISO_3166_2_RE = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{2,3}$")


def _normalize_region(region: str | None, country: str | None) -> str | None:
    """Coerce a region into a valid ISO 3166-2 code, or None if unmappable.

    - Already valid (e.g. 'US-CA') -> kept (upper-cased).
    - A subdivision name resolvable for the country (e.g. 'California') -> its code via pycountry.
    - Anything else (e.g. an IP prefix) -> None, so the region leaf is dropped.
    """
    if not region:
        return None
    value = region.strip()
    if _ISO_3166_2_RE.match(value):
        return value.upper()
    try:
        import pycountry
    except ImportError:
        return None
    cc = (country or "").upper()
    try:
        subdivisions = list(pycountry.subdivisions.get(country_code=cc) or []) if cc else list(pycountry.subdivisions)
    except Exception:
        subdivisions = []
    name = value.lower()
    for sub in subdivisions:
        if sub.name.lower() == name:
            return sub.code.upper()
    for sub in subdivisions:
        if name in sub.name.lower() or sub.name.lower() in name:
            return sub.code.upper()
    return None


def _normalize_geographic_location(ast: PolicyAst) -> PolicyAst:
    """Normalize the region code on both geographic-location sides (drop if unmappable),
    so the endpoint-groups location-group and the context leafref stay consistent."""
    geo = ast.condition.context.geographic_location
    for side in (geo.source, geo.destination):
        side.region = _normalize_region(side.region, side.country)
    return ast


def _location_name(side: LocationSideAst) -> str:
    return "|".join(v for v in [side.country, side.region, side.city] if v) or "location-group"


def derive_datastore_requirements(ast: PolicyAst) -> list[dict[str, str]]:
    reqs: list[dict[str, str]] = []

    def add(section: str, kind: str, name: str | None, source_field: str, role: str, **extra: str) -> None:
        if not name:
            return
        value = str(name).strip()
        if not value or _is_generic_endpoint(value) or _is_literal_endpoint(value):
            return
        req = {"section": section, "kind": kind, "name": value, "source_field": source_field, "role": role}
        req.update({k: v for k, v in extra.items() if v})
        if req not in reqs:
            reqs.append(req)

    fw = ast.condition.firewall
    for value in fw.sources:
        add("endpoint-groups", "endpoint-group", value, "firewall/source", "source")
    for value in fw.destinations:
        add("endpoint-groups", "endpoint-group", value, "firewall/destination", "destination")
    if ast.condition.url_category.url_name:
        add("endpoint-groups", "url-group", ast.condition.url_category.url_name, "url-category/url-name", "url-category")
    for value in ast.condition.voice.source_ids:
        add("endpoint-groups", "voice-group", value, "voice/source-id", "voice-source")
    for value in ast.condition.voice.destination_ids:
        add("endpoint-groups", "voice-group", value, "voice/destination-id", "voice-destination")
    for value in ast.condition.payload.content_refs:
        add("threat-prevention", "payload-content", value, "payload/content", "payload")
    for value in ast.condition.threat_feed_names:
        add("threat-prevention", "threat-feed-list", value, "threat-feed/name", "threat-feed")

    geo = ast.condition.context.geographic_location
    for role, side in (("source", geo.source), ("destination", geo.destination)):
        if any([side.country, side.region, side.city]):
            add("endpoint-groups", "location-group", _location_name(side), f"context/geographic-location/{role}", "geographic-location", country=side.country or "", region=side.region or "", city=side.city or "")
    return reqs


def apply_resolved_requirements_to_ast(ast: PolicyAst, resolved: list[dict[str, Any]]) -> PolicyAst:
    data = ast.model_dump(mode="json")
    for ref in resolved:
        match = ref.get("match")
        old = ref.get("name")
        if not match or not old:
            continue
        source_field = ref.get("source_field", "")
        if ref.get("kind") == "location-group":
            values = match.get("location_values") or {}
            for side_name in ("source", "destination"):
                if source_field.endswith(side_name):
                    side = data["condition"]["context"]["geographic_location"][side_name]
                    for key in ("country", "region", "city"):
                        if side.get(key) and values.get(key):
                            side[key] = values[key]
            continue
        new = match.get("name")
        if not new or new == old:
            continue
        if source_field == "firewall/source":
            data["condition"]["firewall"]["sources"] = [new if v == old else v for v in data["condition"]["firewall"]["sources"]]
        elif source_field == "firewall/destination":
            data["condition"]["firewall"]["destinations"] = [new if v == old else v for v in data["condition"]["firewall"]["destinations"]]
        elif source_field == "url-category/url-name":
            data["condition"]["url_category"]["url_name"] = new
        elif source_field == "voice/source-id":
            data["condition"]["voice"]["source_ids"] = [new if v == old else v for v in data["condition"]["voice"]["source_ids"]]
        elif source_field == "voice/destination-id":
            data["condition"]["voice"]["destination_ids"] = [new if v == old else v for v in data["condition"]["voice"]["destination_ids"]]
        elif source_field == "payload/content":
            data["condition"]["payload"]["content_refs"] = [new if v == old else v for v in data["condition"]["payload"]["content_refs"]]
        elif source_field == "threat-feed/name":
            data["condition"]["threat_feed_names"] = [new if v == old else v for v in data["condition"]["threat_feed_names"]]
    return PolicyAst.model_validate(data)


def build_placeholder_datastore_sections(
    requirements: list[dict[str, str]],
    *,
    fill_missing_location_keys: bool = False,
) -> str:
    endpoint = ET.Element(f"{NS}endpoint-groups")
    threat = ET.Element(f"{NS}threat-prevention")
    seen = set()
    for req in requirements:
        kind = req.get("kind", "")
        name = (req.get("name") or "").strip()
        if not name or (kind, name) in seen:
            continue
        seen.add((kind, name))
        if kind in {"endpoint-group", "user-group", "device-group"}:
            xml_kind = "device-group" if kind == "endpoint-group" else kind
            elem = ET.SubElement(endpoint, f"{NS}{xml_kind}")
            _text(elem, "name", name)
            _text(elem, "ipv4-prefix", "192.0.2.0/24")
        elif kind == "location-group":
            elem = ET.SubElement(endpoint, f"{NS}location-group")
            country = req.get("country") or ""
            region = req.get("region") or ""
            city = req.get("city") or ""
            if fill_missing_location_keys:
                if not country and re.match(r"^[A-Z]{2}-[A-Z0-9]{2,3}$", region, flags=re.IGNORECASE):
                    country = region[:2].upper()
                country = country or "ZZ"
                region = region or f"{country}-00"
                city = city or "Unspecified"
            else:
                country = country or (name.split("|")[0] if name else "ZZ")
                region = region or (f"{country}-01" if re.match(r"^[A-Z]{2}$", country) else "ZZ-01")
                city = city or (name.split("|")[-1] if "|" in name else "Placeholder City")
            _text(elem, "country", country)
            _text(elem, "region", region)
            _text(elem, "city", city)
            _text(elem, "ipv4-prefix", "192.0.2.0/24")
        elif kind == "url-group":
            elem = ET.SubElement(endpoint, f"{NS}url-group")
            _text(elem, "name", name)
            _text(elem, "url", "https://example.com")
        elif kind == "voice-group":
            elem = ET.SubElement(endpoint, f"{NS}voice-group")
            _text(elem, "name", name)
            _text(elem, "sip-id", "sip:placeholder@example.com")
        elif kind == "threat-feed-list":
            elem = ET.SubElement(threat, f"{NS}threat-feed-list")
            _text(elem, "name", name)
            _text(elem, "ioc", "placeholder-ioc")
            _text(elem, "format", "stix")
        elif kind == "payload-content":
            elem = ET.SubElement(threat, f"{NS}payload-content")
            _text(elem, "name", name)
            _text(elem, "description", "Placeholder payload content generated for empty datastore validation")
            contents = ET.SubElement(elem, f"{NS}contents")
            _text(contents, "content", "AAAA")
    sections: list[str] = []
    if len(endpoint):
        sections.append(_element_to_string(endpoint))
    if len(threat):
        sections.append(_element_to_string(threat))
    return "\n\n".join(sections)


def concatenate_datastore_and_rule_sections(datastore_xml: str, rule_policy_xml: str) -> str:
    pieces = [p.strip() for p in [datastore_xml, rule_policy_xml] if p and p.strip()]
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\n" + "\n\n".join(pieces)


def compose_policy_ast_structured(original_intent: str, restated_intent: str | None, event_action: str, conditions: str, endpoint_groups_and_threat_feeds: str, metadata: str, clarification_context: str | None = None, clarification_context_kind: str = "qa") -> PolicyAst:
    catalog_excerpt = {"identity_values": SCHEMA_CATALOG["identities"], "frequency_values": FREQUENCIES, "day_values": WEEKDAYS, "placement": SCHEMA_CATALOG["placement"], "constraints": SCHEMA_CATALOG["constraints"]}
    system_prompt = (
        "You convert I2NSF natural-language policy analysis into a single behavior-oriented PolicyAst. "
        "Return only fields supported by the PolicyAst schema. Use empty lists or null for non-applicable fields. "
        "Do not invent unsupported XML/YANG leaves such as memory-usage or cpu-usage; map such ideas to valid system alarms when appropriate. "
        "Place application, device-type, users, time, and geographic-location only under context fields. "
        "For geographic-location, country MUST be the ISO 3166-1 alpha-2 code (2 letters: United States -> US, South Korea -> KR, Singapore -> SG) and region MUST be the ISO 3166-2 code (California -> US-CA, Seoul -> KR-11); city stays free text. Never emit full country or region names. "
        "For time, each rule supports at most one time context. Recurring clock windows (e.g. business hours, 'every day 9-5') go in period.start_time/end_time as hh:mm:ss with a frequency; only one-off absolute moments go in start_date_time/end_date_time as full RFC-3339 datetimes. Never put a bare clock time like '09:00' in start_date_time. "
        "For secondary logging, choose at most one log action: rule-log, session-log, or null when logging is not required. "
        "Use source/destination only for endpoint-like firewall references. Use exact I2NSF enum values from the schema catalog."
    )
    context_label = "Clarification Q&A" if clarification_context_kind == "qa" else "Canonical resolved intent"
    provider = get_policy_generation_config()["provider"]
    if provider == "google":
        from helpers.gemini_structured_output_adapter import GeminiPolicyAst, empty_gemini_policy_ast_template, to_policy_ast

        output_schema = GeminiPolicyAst
        output_template = empty_gemini_policy_ast_template()
    else:
        output_schema = PolicyAst
        output_template = empty_policy_ast_template()
    user_content = (
        f"Original intent:\n{original_intent}\n\n"
        f"Restated intent:\n{restated_intent or '(not provided)'}\n\n"
        f"{context_label}:\n{clarification_context or '(not provided)'}\n\n"
        f"Expert event/action extraction:\n{event_action}\n\n"
        f"Expert condition extraction:\n{conditions}\n\n"
        f"Expert endpoint/threat extraction:\n{endpoint_groups_and_threat_feeds}\n\n"
        f"Expert metadata extraction:\n{metadata}\n\n"
        f"YANG-derived schema catalog:\n{json.dumps(catalog_excerpt, indent=2)}\n\n"
        f"Empty AST template showing required fields:\n{json.dumps(output_template, indent=2)}"
    )
    generated_ast = generate_structured(output_schema, system_prompt, user_content)
    policy_ast = to_policy_ast(generated_ast) if provider == "google" else generated_ast
    return _normalize_geographic_location(policy_ast)




