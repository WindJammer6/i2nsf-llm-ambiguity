"""Shared helpers for retrieving existing endpoint-group / threat-prevention
objects from dataset/pre_registered_datastore/pre_registered_datastore.xml via embedding similarity."""

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from openai import OpenAI
from helpers.llm_client import get_openai_api_key

client = OpenAI(api_key=get_openai_api_key())

NS_URI = "urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface"
NS = "{" + NS_URI + "}"
# Monitoring-interface module: defines the identities (e.g. http/https) used as
# identityref values such as <application-protocol>i2nsfmi:http</application-protocol>.
MONITORING_NS_URI = "urn:ietf:params:xml:ns:yang:ietf-i2nsf-monitoring-interface"
MONITORING_NS_PREFIX = "i2nsfmi"
ET.register_namespace("", NS_URI)

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATASTORE_PATH = PROJECT_DIR / "dataset" / "pre_registered_datastore" / "pre_registered_datastore.xml"
EMBEDDING_PROVIDER = "openai"
EMBEDDING_MODEL = "text-embedding-3-small"
RETRIEVAL_METHOD = "top1_cosine_best_similarity"

ENDPOINT_REFERENCE_CATEGORIES = ["user-group", "device-group"]
ENDPOINT_GROUPS_CATEGORIES = ENDPOINT_REFERENCE_CATEGORIES + ["location-group", "url-group", "voice-group"]
THREAT_PREVENTION_CATEGORIES = ["threat-feed-list", "payload-content"]
ALL_CATEGORIES = ENDPOINT_GROUPS_CATEGORIES + THREAT_PREVENTION_CATEGORIES


def retrieval_experiment_config() -> dict:
    """Return auditable deterministic retrieval settings."""
    datastore_path = DATASTORE_PATH
    datastore_hash = hashlib.sha256(datastore_path.read_bytes()).hexdigest() if datastore_path.exists() else None
    return {
        "embedding_provider": EMBEDDING_PROVIDER,
        "embedding_model": EMBEDDING_MODEL,
        "retrieval_method": RETRIEVAL_METHOD,
        "llm_reranker": False,
        "embedding_held_constant_across_models": True,
        "datastore_path": str(DATASTORE_PATH),
        "datastore_sha256": datastore_hash,
        "indexed_object_representation": "name-only; location country/region/city indexed separately",
    }
def local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag




def _load_datastore_root():
    xml_text = open(DATASTORE_PATH, encoding="utf-8").read()
    body = re.sub(r"<\?xml[^>]*\?>", "", xml_text)
    wrapped = f"<root xmlns='{NS_URI}'>{body}</root>"
    return ET.fromstring(wrapped)


def _text(elem, tag: str) -> str:
    return elem.findtext(f"{NS}{tag}", default="").strip()


def load_datastore_entries() -> list[dict]:
    """Return searchable datastore entries, with each entry pointing to its live XML element.

    Named objects are embedded by name only. Location groups have no name, so each
    country, region, and city value becomes a separate searchable entry that points
    back to the same location-group XML element.
    """
    root = _load_datastore_root()
    entries = []
    for top in root:
        for elem in top:
            category = local(elem.tag)
            if category == "location-group":
                location_values = {
                    "country": _text(elem, "country"),
                    "region": _text(elem, "region"),
                    "city": _text(elem, "city"),
                }
                location_name = "|".join(
                    value for value in (
                        location_values["country"],
                        location_values["region"],
                        location_values["city"],
                    )
                    if value
                )
                for field, value in location_values.items():
                    if not value:
                        continue
                    entries.append({
                        "category": category,
                        "name": location_name,
                        "text": value,
                        "elem": elem,
                        "location_field": field,
                        "location_values": location_values.copy(),
                    })
                continue

            name = _text(elem, "name")
            if not name:
                continue
            entries.append({
                "category": category,
                "name": name,
                "text": name,
                "elem": elem,
            })
    return entries

def embed_texts(texts: list[str]) -> list[list[float]]:
    resp = client.embeddings.create(model=EMBEDDING_MODEL, input=texts)
    return [d.embedding for d in resp.data]


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb)


def build_datastore_index() -> tuple[list[dict], list[list[float]]]:
    entries = load_datastore_entries()
    embs = embed_texts([e["text"] for e in entries])
    return entries, embs


def entry_to_xml_string(elem) -> str:
    return ET.tostring(elem, encoding="unicode")


def build_resolved_sections_xml(resolved_refs: list[dict]) -> str:
    """Deterministically build <endpoint-groups> and <threat-prevention> sections
    from the matched datastore entries (deduplicated by category+name)."""
    seen = set()
    endpoint_elems = []
    threat_elems = []
    for ref in resolved_refs:
        match = ref.get("match")
        if not match:
            continue
        key = (match["category"], match["name"])
        if key in seen:
            continue
        seen.add(key)
        xml_str = entry_to_xml_string(match["elem"])
        if match["category"] in ENDPOINT_GROUPS_CATEGORIES:
            endpoint_elems.append(xml_str)
        else:
            threat_elems.append(xml_str)

    # Declare the monitoring-interface prefix on the wrappers so that any injected
    # identityref values (e.g. <application-protocol>i2nsfmi:http</application-protocol>)
    # resolve. An unused declaration is harmless valid XML.
    mi_decl = f'xmlns:{MONITORING_NS_PREFIX}="{MONITORING_NS_URI}"'
    sections = []
    if endpoint_elems:
        sections.append(
            f'<endpoint-groups xmlns="{NS_URI}" {mi_decl}>\n' + "\n".join(endpoint_elems) + "\n</endpoint-groups>"
        )
    if threat_elems:
        sections.append(
            f'<threat-prevention xmlns="{NS_URI}" {mi_decl}>\n' + "\n".join(threat_elems) + "\n</threat-prevention>"
        )
    return "\n\n".join(sections)


def format_resolved_refs(resolved_refs: list[dict]) -> str:
    if not resolved_refs:
        return "(No endpoint groups, URL groups, voice groups, or threat feeds referenced.)"
    lines = []
    for ref in resolved_refs:
        match = ref.get("match")
        if match:
            lines.append(
                f"- role: {ref['role']}, phrase: \"{ref['phrase']}\" -> "
                f"existing datastore object: [{match['category']}] {match['name']}"
            )
        else:
            lines.append(f"- role: {ref['role']}, phrase: \"{ref['phrase']}\" -> NO MATCH FOUND in datastore")
    return "\n".join(lines)


def _candidate_categories(kind: str) -> set[str]:
    if kind == "endpoint-group":
        return set(ENDPOINT_REFERENCE_CATEGORIES)
    return {kind}


def match_top1_best_similarity(
    phrase: str, category: str, original_intent: str,
    entries: list[dict], entry_embs: list[list[float]],
) -> dict | None:
    candidate_categories = _candidate_categories(category)
    candidates = [(e, emb) for e, emb in zip(entries, entry_embs) if e["category"] in candidate_categories]
    if not candidates:
        return None
    phrase_emb = embed_texts([phrase])[0]
    sims = sorted(((cosine(phrase_emb, emb), e) for e, emb in candidates), key=lambda x: x[0], reverse=True)
    best_score, best_entry = sims[0]
    top_candidates = [(e["name"], e.get("text", ""), round(s, 4)) for s, e in sims[:3]]
    print(
        f"[top1_best_similarity] phrase={phrase!r} category={category!r} "
        f"top_candidates={top_candidates}"
    )
    print(
        f"[top1_best_similarity] -> MATCH {best_entry['name']!r} "
        f"via {best_entry.get('text', '')!r} (score={best_score:.4f})"
    )
    return best_entry


def _xml_values(policy_xml: str, tag: str) -> list[str]:
    return [
        match.group(1).strip()
        for match in re.finditer(
            rf"<{tag}\b[^>]*>\s*([^<]+?)\s*</{tag}>",
            policy_xml,
            flags=re.IGNORECASE,
        )
    ]


def _looks_like_literal_endpoint(value: str) -> bool:
    value = value.strip()
    if not value or value.lower() in {"any", "all", "unknown"}:
        return True
    if re.search(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$", value):
        return True
    return bool(":" in value and re.search(r"^[0-9a-fA-F:]+(?:/\d{1,3})?$", value))


def identify_missing_datastore_requirements(rule_xml: str) -> list[dict[str, str]]:
    """Deterministically map XML rule references to datastore requirements."""
    requirements: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()

    def add(section: str, kind: str, name: str, source_field: str) -> None:
        clean_name = name.strip()
        key = (section, kind, clean_name)
        if not clean_name or key in seen:
            return
        seen.add(key)
        requirements.append({
            "section": section,
            "kind": kind,
            "name": clean_name,
            "source_field": source_field,
        })

    def add_location(country: str, region: str, city: str, source_field: str) -> None:
        country, region, city = country.strip(), region.strip(), city.strip()
        key = ("endpoint-groups", "location-group", country, region, city)
        if not any((country, region, city)) or key in seen:
            return
        seen.add(key)
        item = {
            "section": "endpoint-groups",
            "kind": "location-group",
            "source_field": source_field,
        }
        item.update({k: v for k, v in {"country": country, "region": region, "city": city}.items() if v})
        requirements.append(item)

    for value in _xml_values(rule_xml, "url-name"):
        add("endpoint-groups", "url-group", value, "url-category/url-name")
    for value in _xml_values(rule_xml, "source-id"):
        add("endpoint-groups", "voice-group", value, "voice/source-id")
    for value in _xml_values(rule_xml, "destination-id"):
        add("endpoint-groups", "voice-group", value, "voice/destination-id")
    for value in _xml_values(rule_xml, "content"):
        add("threat-prevention", "payload-content", value, "payload/content")
    for block in re.findall(r"<threat-feed\b[\s\S]*?</threat-feed>", rule_xml, flags=re.IGNORECASE):
        for value in _xml_values(block, "name"):
            add("threat-prevention", "threat-feed-list", value, "threat-feed/name")
    for geo in re.findall(r"<geographic-location\b[\s\S]*?</geographic-location>", rule_xml, flags=re.IGNORECASE):
        for direction in ("source", "destination"):
            for location in re.findall(rf"<{direction}\b[\s\S]*?</{direction}>", geo, flags=re.IGNORECASE):
                add_location(
                    next(iter(_xml_values(location, "country")), ""),
                    next(iter(_xml_values(location, "region")), ""),
                    next(iter(_xml_values(location, "city")), ""),
                    f"context/geographic-location/{direction}",
                )
    for firewall in re.findall(r"<firewall\b[\s\S]*?</firewall>", rule_xml, flags=re.IGNORECASE):
        for field in ("source", "destination"):
            for value in _xml_values(firewall, field):
                if not _looks_like_literal_endpoint(value):
                    add("endpoint-groups", "device-group", value, f"firewall/{field}")
    return requirements

RELEVANT_REQUIREMENT_KINDS = {"endpoint-group", "user-group", "device-group", "location-group", "url-group", "voice-group", "threat-feed-list", "payload-content"}

_RENAME_TAG_FOR_FIELD = {
    "url-category/url-name": "url-name",
    "voice/source-id": "source-id",
    "voice/destination-id": "destination-id",
    "payload/content": "content",
    "firewall/source": "source",
    "firewall/destination": "destination",
}


def _location_requirement_phrase(req: dict) -> str:
    for field in ("city", "region", "country"):
        value = (req.get(field) or "").strip()
        if value:
            return value
    return ""


def resolve_requirements(requirements: list[dict], original_intent: str, match_fn) -> list[dict]:
    """For each deterministic datastore requirement, try to match it to an existing
    datastore object of the same or compatible kind via the given match_fn."""
    if not requirements:
        return []
    entries, entry_embs = build_datastore_index()
    resolved = []
    for req in requirements:
        kind = req.get("kind")
        if kind not in RELEVANT_REQUIREMENT_KINDS:
            resolved.append({**req, "match": None})
            continue
        phrase = _location_requirement_phrase(req) if kind == "location-group" else (req.get("name") or "").strip()
        if not phrase:
            resolved.append({**req, "match": None})
            continue
        match = match_fn(phrase, kind, original_intent, entries, entry_embs)
        resolved.append({**req, "match": match, "retrieval_phrase": phrase})
    return resolved


def apply_resolved_renames(rule_xml: str, resolved: list[dict]) -> str:
    """Rewrite rule_xml leaf values to use the exact names/keys of matched datastore objects."""
    fixed = rule_xml
    for ref in resolved:
        match = ref.get("match")
        if not match:
            continue
        source_field = ref.get("source_field", "")
        if ref.get("kind") == "location-group":
            continue
        if match["name"] == ref.get("name"):
            continue
        old, new = ref["name"], match["name"]
        if source_field == "threat-feed/name":
            def repl(m, old=old, new=new):
                block = m.group(0)
                return re.sub(rf"(<name>\s*){re.escape(old)}(\s*</name>)", rf"\1{new}\2", block, count=1)
            fixed = re.sub(r"<threat-feed\b[\s\S]*?</threat-feed>", repl, fixed, flags=re.IGNORECASE)
            continue
        tag = _RENAME_TAG_FOR_FIELD.get(source_field)
        if not tag:
            continue
        fixed = re.sub(
            rf"(<{tag}\b[^>]*>\s*){re.escape(old)}(\s*</{tag}>)",
            rf"\1{new}\2",
            fixed,
            count=1,
            flags=re.IGNORECASE,
        )
    return fixed


