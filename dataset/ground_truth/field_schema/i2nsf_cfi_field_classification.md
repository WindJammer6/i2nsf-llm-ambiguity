# I2NSF CFI field classification
Classification used here:
- **Common entity**: one value users commonly express directly in intent, such as protocol, port, action, user, location, time, or threshold.
- **Composite entity**: value is a group/reference/range/choice/list that must be resolved together with other fields or another object, such as endpoint groups, URL groups, port ranges, and recurring schedules.
- **Immutable/System default**: metadata, keys, or policy mechanics that should usually be generated/defaulted by the system rather than clarified from the user.

Note: line references are from the uploaded local files in `/mnt/data`.

| Field path | Class | Allowed values / type | Default | Notes/source |
|---|---|---|---|---|
| `/i2nsf-cfi-policy/name` | Immutable/System-generated | string | — | Policy key/name; can be generated from intent unless user explicitly names it. Lines 823-827 |
| `/i2nsf-cfi-policy/language` | Immutable/System default | RFC5646 language tag string | en-US | Usually auto-fill; do not clarify unless natural-language description fields matter. Lines 828-856 |
| `/i2nsf-cfi-policy/priority-usage` | Immutable/System default | priority-by-order \| priority-by-number | priority-by-order | Clarify only if user explicitly needs numeric priority semantics. Lines 867-871 |
| `/i2nsf-cfi-policy/resolution-strategy` | Immutable/System default | fmr \| lmr \| pmre \| pmrn | fmr | Conflict strategy; normally auto-fill. Lines 876-880 |
| `/i2nsf-cfi-policy/rules/name` | Immutable/System-generated | string | — | Rule key/name; uniqueness enforced by list key. Lines 896-901 |
| `/i2nsf-cfi-policy/rules/priority` | Common entity (conditional) | uint8: 0..255 | — | Only valid when priority-usage = priority-by-number. Lines 904-920 |
| `/i2nsf-cfi-policy/rules/event/system-event` | Common entity (event-triggered) | access-violation \| configuration-change | — | Only ask when intent is event-triggered. Lines 926-933; values from monitoring model lines 311-324 |
| `/i2nsf-cfi-policy/rules/event/system-alarm` | Common entity (event-triggered) | memory-alarm \| cpu-alarm \| disk-alarm \| hardware-alarm \| interface-alarm | — | Only ask when intent refers to system alarms. Lines 935-942; values from monitoring model lines 271-309 |
| `/i2nsf-cfi-policy/rules/condition/firewall/source` | Composite entity | leafref to /endpoint-groups/user-group/name or /endpoint-groups/device-group/name | — | Usually points to a group such as employees, guests, internal-devices. Lines 953-964 |
| `/i2nsf-cfi-policy/rules/condition/firewall/destination` | Composite entity | leafref to /endpoint-groups/user-group/name or /endpoint-groups/device-group/name | — | Usually points to a group such as web-servers or external-sites. Lines 966-977 |
| `/i2nsf-cfi-policy/rules/condition/firewall/transport-layer-protocol` | Common entity | tcp \| udp \| sctp \| dccp | — | Use CFI/imported identity names; not arbitrary strings. Lines 979-985; values from monitoring model lines 704-738 |
| `/i2nsf-cfi-policy/rules/condition/firewall/range-port-number/start` | Composite entity | inet:port-number, 0..65535 | — | Part of inclusive port range. Lines 987-993; inet port-number range lines 143-146 |
| `/i2nsf-cfi-policy/rules/condition/firewall/range-port-number/end` | Composite entity | inet:port-number, 0..65535; must be >= start | — | Part of inclusive port range. Lines 994-1009 |
| `/i2nsf-cfi-policy/rules/condition/firewall/icmp/message` | Common entity | echo-reply \| destination-unreachable \| redirect \| echo \| router-advertisement \| router-solicitation \| time-exceeded \| parameter-problem \| experimental-mobility-protocols \| extended-echo-request \| extended-echo-reply \| port-unreachable \| request-no-error \| reply-no-error \| malformed-query \| no-such-interface \| no-such-table-entry \| multiple-interfaces-satisfy-query | — | Only relevant when ICMP condition is used. Lines 1022-1038; values from CFI identities lines 329-457 |
| `/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/packet-rate-threshold` | Common entity | uint64 packets/sec | — | DDoS trigger threshold. Lines 1048-1055 |
| `/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/byte-rate-threshold` | Common entity | uint64 bytes/sec | — | DDoS trigger threshold. Lines 1056-1063 |
| `/i2nsf-cfi-policy/rules/condition/ddos/rate-limit/flow-rate-threshold` | Common entity | uint64 flows/sec | — | DDoS trigger threshold. Lines 1064-1071 |
| `/i2nsf-cfi-policy/rules/condition/anti-virus/profile` | Common entity | string/glob profile path or name | — | AV scan profile. Lines 1079-1089 |
| `/i2nsf-cfi-policy/rules/condition/anti-virus/exception-files` | Common entity | string/glob file patterns | — | AV exceptions. Lines 1091-1101 |
| `/i2nsf-cfi-policy/rules/condition/payload/content` | Composite entity | leafref to /threat-prevention/payload-content/name | — | References a payload-content object. Lines 1107-1113 |
| `/i2nsf-cfi-policy/rules/condition/url-category/url-name` | Composite entity | leafref to /endpoint-groups/url-group/name | — | References URL group. Lines 1119-1127 |
| `/i2nsf-cfi-policy/rules/condition/voice/source-id` | Composite entity | leafref to /endpoint-groups/voice-group/name | — | References SIP/voice group for From header. Lines 1148-1158 |
| `/i2nsf-cfi-policy/rules/condition/voice/destination-id` | Composite entity | leafref to /endpoint-groups/voice-group/name | — | References SIP/voice group for To header. Lines 1160-1170 |
| `/i2nsf-cfi-policy/rules/condition/voice/user-agent` | Common entity | string | — | SIP User-Agent match. Lines 1172-1180 |
| `/i2nsf-cfi-policy/rules/condition/context/time/start-date-time` | Common entity | yang:date-and-time / RFC3339-like timestamp | — | Policy start datetime. Lines 1191-1196 |
| `/i2nsf-cfi-policy/rules/condition/context/time/end-date-time` | Common entity | yang:date-and-time / RFC3339-like timestamp | — | Policy end datetime. Lines 1197-1203 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/start-time` | Composite entity | HH:MM:SS with optional timezone | — | Only if repeated schedule. Lines 1204-1213; local time typedef lines 579-587 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/end-time` | Composite entity | HH:MM:SS with optional timezone | — | Only if repeated schedule. Lines 1214-1218 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/day` | Composite entity | monday \| tuesday \| wednesday \| thursday \| friday \| saturday \| sunday | — | Only when frequency = weekly. Lines 1219-1228; day typedef lines 589-622 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/date` | Composite entity | int8 range 1..31 | — | Only when frequency = monthly. Lines 1229-1239 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/month/start` | Composite entity | MM-DD pattern | — | Only when frequency = yearly. Lines 1240-1254 |
| `/i2nsf-cfi-policy/rules/condition/context/time/period/month/end` | Composite entity | MM-DD pattern; should be >= start | — | Only when frequency = yearly. Lines 1255-1274 |
| `/i2nsf-cfi-policy/rules/condition/context/time/frequency` | Immutable/System default or common if schedule explicit | only-once \| daily \| weekly \| monthly \| yearly | only-once | Default is one continuous interval unless user asks for recurring schedule. Lines 1277-1312 |
| `/i2nsf-cfi-policy/rules/condition/context/application/protocol` | Common entity | http \| https \| http2 \| https2 \| ftp \| ssh \| telnet \| smtp \| pop3 \| pop3s \| imap \| imaps | — | Application-layer protocol identities. Lines 1322-1329; values from monitoring model lines 740-838 |
| `/i2nsf-cfi-policy/rules/condition/context/device-type/device` | Common entity | computer \| mobile-phone \| voip-vocn-phone \| tablet \| network-infrastructure-device \| iot-device \| ot \| vehicle | — | Destination device type. Lines 1335-1344; values from CFI identities lines 512-573 |
| `/i2nsf-cfi-policy/rules/condition/context/users/user/id` | Common entity | uint32 | — | User identifier from user management system. Lines 1350-1362 |
| `/i2nsf-cfi-policy/rules/condition/context/users/user/name` | Common entity | string | — | Username. Lines 1363-1367 |
| `/i2nsf-cfi-policy/rules/condition/context/users/group/id` | Common entity | uint32 | — | Group identifier. Lines 1369-1380 |
| `/i2nsf-cfi-policy/rules/condition/context/users/group/name` | Common entity | string | — | Group name. Lines 1382-1386 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/country` | Composite entity | leafref to /endpoint-groups/location-group/country; ISO3166-1 alpha-2 | — | Location source. Lines 1393-1403 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/region` | Composite entity | leafref to /endpoint-groups/location-group/region; ISO3166-2 | — | Location source region. Lines 1404-1412 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/source/city` | Composite entity | leafref to /endpoint-groups/location-group/city | — | Location source city. Lines 1413-1424 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/destination/country` | Composite entity | leafref to /endpoint-groups/location-group/country; ISO3166-1 alpha-2 | — | Location destination. Lines 1426-1436 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/destination/region` | Composite entity | leafref to /endpoint-groups/location-group/region; ISO3166-2 | — | Location destination region. Lines 1437-1445 |
| `/i2nsf-cfi-policy/rules/condition/context/geographic-location/destination/city` | Composite entity | leafref to /endpoint-groups/location-group/city | — | Location destination city. Lines 1446-1457 |
| `/i2nsf-cfi-policy/rules/condition/threat-feed/name` | Composite entity | leafref to /threat-prevention/threat-feed-list/name | — | References threat-feed object. Lines 1464-1470 |
| `/i2nsf-cfi-policy/rules/action/primary-action/action` | Common entity | pass \| drop \| reject \| mirror \| rate-limit \| invoke-signaling \| tunnel-encapsulation \| forwarding \| transformation | mandatory; no explicit CFI default | Critical action field. Lines 1483-1494 |
| `/i2nsf-cfi-policy/rules/action/primary-action/limit` | Common entity (conditional) | decimal64, fraction-digits 2, bytes/sec | — | Only when action = rate-limit. Lines 1495-1507 |
| `/i2nsf-cfi-policy/rules/action/secondary-action/log-action` | Common entity (optional) | rule-log \| session-log | — | Optional logging. Lines 1514-1520 |
| `/endpoint-groups/user-group/name` | Composite entity | string | — | Key/name for user group. Lines 1530-1534 plus grouping lines 716-723 |
| `/endpoint-groups/user-group/mac-address` | Common entity | yang:mac-address | — | One or more MAC addresses. Lines 724-729 |
| `/endpoint-groups/user-group/ipv4-prefix` | Common entity | inet:ipv4-prefix OR IPv4 range start/end | — | From ip-address-info grouping. Prefix/range choices lines 641-668 |
| `/endpoint-groups/user-group/ipv6-prefix` | Common entity | inet:ipv6-prefix OR IPv6 range start/end | — | From ip-address-info grouping. Prefix/range choices lines 678-705 |
| `/endpoint-groups/device-group/name` | Composite entity | string | — | Key/name for device group. Lines 1536-1540 plus grouping lines 744-748 |
| `/endpoint-groups/device-group/ipv4-prefix` | Common entity | inet:ipv4-prefix OR IPv4 range start/end | — | From ip-address-info grouping. Lines 641-668 |
| `/endpoint-groups/device-group/ipv6-prefix` | Common entity | inet:ipv6-prefix OR IPv6 range start/end | — | From ip-address-info grouping. Lines 678-705 |
| `/endpoint-groups/device-group/application-protocol` | Common entity | http \| https \| http2 \| https2 \| ftp \| ssh \| telnet \| smtp \| pop3 \| pop3s \| imap \| imaps | — | Application protocol identities. Lines 756-764 |
| `/endpoint-groups/location-group/country` | Composite entity | 2-letter ISO3166-1 alpha-2 code | — | Key component and location mapping. Lines 1542-1546 plus grouping lines 771-782 |
| `/endpoint-groups/location-group/region` | Composite entity | ISO3166-2 pattern: [A-Z]{2}-[A-Z0-9]{2,3} | — | Key component and location mapping. Lines 783-794 |
| `/endpoint-groups/location-group/city` | Composite entity | string | — | Key component and location mapping. Lines 795-800 |
| `/endpoint-groups/location-group/ipv4-prefix` | Common entity | inet:ipv4-prefix OR IPv4 range start/end | — | From ip-address-info grouping. Lines 801-807 |
| `/endpoint-groups/location-group/ipv6-prefix` | Common entity | inet:ipv6-prefix OR IPv6 range start/end | — | From ip-address-info grouping. Lines 801-807 |
| `/endpoint-groups/url-group/name` | Composite entity | string | — | URL group key/name. Lines 1548-1557 |
| `/endpoint-groups/url-group/url` | Common entity | inet:uri | — | URI(s) in group. Lines 1558-1565 |
| `/endpoint-groups/voice-group/name` | Composite entity | string | — | Voice group key/name. Lines 1567-1575 |
| `/endpoint-groups/voice-group/sip-id` | Common entity | inet:uri; SIP/SIPS URI | — | SIP logical identity. Lines 1576-1584 |
| `/threat-prevention/threat-feed-list/name` | Composite entity | string | — | Threat feed key/name. Lines 1591-1600 |
| `/threat-prevention/threat-feed-list/ioc` | Common entity | string IOC/signature(s) | — | Indicators of compromise. Lines 1601-1610 |
| `/threat-prevention/threat-feed-list/format` | Common entity | stix \| misp \| openioc \| iodef | mandatory; no default | Must be known to parse IOC. Lines 1611-1627 |
| `/threat-prevention/payload-content/name` | Composite entity | string | — | Payload-content key/name. Lines 1630-1640 |
| `/threat-prevention/payload-content/description` | Common entity | string | — | Payload description. Lines 1641-1647 |
| `/threat-prevention/payload-content/contents/content` | Common entity | binary | — | Payload pattern. Lines 1651-1666 |
| `/threat-prevention/payload-content/contents/depth` | Common entity | uint16 range 1..max, bytes | undefined = search whole payload | Search depth. Lines 1667-1680 |
| `/threat-prevention/payload-content/contents/offset` | Composite entity | int32 bytes | undefined = start from beginning | Starting point choice: offset OR distance. Lines 1682-1701 |
| `/threat-prevention/payload-content/contents/distance` | Composite entity | int32 bytes | undefined = start from beginning | Starting point choice: offset OR distance; not for first content. Lines 1703 onward |