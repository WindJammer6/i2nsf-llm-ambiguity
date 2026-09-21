"""Gemini-compatible flat structured schema for the shared I2NSF PolicyAst."""
from __future__ import annotations

from typing import Any

from pydantic import Field

from helpers.i2nsf_cfi_policy import (
    ApplicationProtocol,
    Day,
    DeviceType,
    Frequency,
    IcmpMessage,
    LogAction,
    MonthRangeAst,
    PolicyAst,
    PrimaryAction,
    StrictModel,
    SystemAlarm,
    SystemEvent,
    TransportProtocol,
    empty_policy_ast_template,
)


class GeminiPortRangeAst(StrictModel):
    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)


class GeminiTimeAst(StrictModel):
    start_date_time: str | None
    end_date_time: str | None
    frequency: Frequency | None
    start_time: str | None
    end_time: str | None
    days: list[Day]
    dates: list[int]
    months: list[MonthRangeAst]


class GeminiPolicyAst(StrictModel):
    policy_name: str
    rule_name: str
    system_events: list[SystemEvent]
    system_alarms: list[SystemAlarm]
    firewall_sources: list[str]
    firewall_destinations: list[str]
    transport_layer_protocols: list[TransportProtocol]
    port_ranges: list[GeminiPortRangeAst]
    icmp_messages: list[IcmpMessage]
    packet_rate_threshold: int | None
    byte_rate_threshold: int | None
    flow_rate_threshold: int | None
    anti_virus_profiles: list[str]
    anti_virus_exception_files: list[str]
    payload_content_refs: list[str]
    url_name: str | None
    voice_source_ids: list[str]
    voice_destination_ids: list[str]
    voice_user_agents: list[str]
    time: GeminiTimeAst | None
    application_protocols: list[ApplicationProtocol]
    device_types: list[DeviceType]
    user_ids: list[int]
    user_names: list[str]
    group_ids: list[int]
    group_names: list[str]
    geo_source_country: str | None = Field(pattern=r"^[A-Z]{2}$")
    geo_source_region: str | None = Field(pattern=r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
    geo_source_city: str | None
    geo_destination_country: str | None = Field(pattern=r"^[A-Z]{2}$")
    geo_destination_region: str | None = Field(pattern=r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
    geo_destination_city: str | None
    threat_feed_names: list[str]
    primary_action: PrimaryAction
    rate_limit: float | None
    secondary_log_action: LogAction | None


def empty_gemini_policy_ast_template() -> dict[str, Any]:
    nested = empty_policy_ast_template()
    condition = nested["condition"]
    context = condition["context"]
    users = context["users"]
    location = context["geographic_location"]
    action = nested["action"]
    return {
        "policy_name": nested["policy_name"],
        "rule_name": nested["rule_name"],
        "system_events": [],
        "system_alarms": [],
        "firewall_sources": [],
        "firewall_destinations": [],
        "transport_layer_protocols": [],
        "port_ranges": [],
        "icmp_messages": [],
        "packet_rate_threshold": None,
        "byte_rate_threshold": None,
        "flow_rate_threshold": None,
        "anti_virus_profiles": [],
        "anti_virus_exception_files": [],
        "payload_content_refs": [],
        "url_name": None,
        "voice_source_ids": [],
        "voice_destination_ids": [],
        "voice_user_agents": [],
        "time": None,
        "application_protocols": [],
        "device_types": [],
        "user_ids": users["user_ids"],
        "user_names": users["user_names"],
        "group_ids": users["group_ids"],
        "group_names": users["group_names"],
        "geo_source_country": location["source"]["country"],
        "geo_source_region": location["source"]["region"],
        "geo_source_city": location["source"]["city"],
        "geo_destination_country": location["destination"]["country"],
        "geo_destination_region": location["destination"]["region"],
        "geo_destination_city": location["destination"]["city"],
        "threat_feed_names": condition["threat_feed_names"],
        "primary_action": action["primary_action"],
        "rate_limit": action["rate_limit"],
        "secondary_log_action": action["secondary_log_action"],
    }


def to_policy_ast(flat: GeminiPolicyAst) -> PolicyAst:
    data = flat.model_dump(mode="json")
    time = None
    if data["time"] is not None:
        item = data["time"]
        time = {
            "start_date_time": item["start_date_time"],
            "end_date_time": item["end_date_time"],
            "frequency": item["frequency"],
            "period": {
                "start_time": item["start_time"],
                "end_time": item["end_time"],
                "days": item["days"],
                "dates": item["dates"],
                "months": item["months"],
            },
        }
    return PolicyAst.model_validate(
        {
            "policy_name": data["policy_name"],
            "rule_name": data["rule_name"],
            "event": {"system_events": data["system_events"], "system_alarms": data["system_alarms"]},
            "condition": {
                "firewall": {
                    "sources": data["firewall_sources"],
                    "destinations": data["firewall_destinations"],
                    "transport_layer_protocols": data["transport_layer_protocols"],
                    "port_ranges": data["port_ranges"],
                    "icmp_messages": data["icmp_messages"],
                },
                "ddos": {
                    "packet_rate_threshold": data["packet_rate_threshold"],
                    "byte_rate_threshold": data["byte_rate_threshold"],
                    "flow_rate_threshold": data["flow_rate_threshold"],
                },
                "anti_virus": {
                    "profiles": data["anti_virus_profiles"],
                    "exception_files": data["anti_virus_exception_files"],
                },
                "payload": {"content_refs": data["payload_content_refs"]},
                "url_category": {"url_name": data["url_name"]},
                "voice": {
                    "source_ids": data["voice_source_ids"],
                    "destination_ids": data["voice_destination_ids"],
                    "user_agents": data["voice_user_agents"],
                },
                "context": {
                    "time": time,
                    "application_protocols": data["application_protocols"],
                    "device_types": data["device_types"],
                    "users": {
                        "user_ids": data["user_ids"],
                        "user_names": data["user_names"],
                        "group_ids": data["group_ids"],
                        "group_names": data["group_names"],
                    },
                    "geographic_location": {
                        "source": {
                            "country": data["geo_source_country"],
                            "region": data["geo_source_region"],
                            "city": data["geo_source_city"],
                        },
                        "destination": {
                            "country": data["geo_destination_country"],
                            "region": data["geo_destination_region"],
                            "city": data["geo_destination_city"],
                        },
                    },
                },
                "threat_feed_names": data["threat_feed_names"],
            },
            "action": {
                "primary_action": data["primary_action"],
                "rate_limit": data["rate_limit"],
                "secondary_log_action": data["secondary_log_action"],
            },
        }
    )
