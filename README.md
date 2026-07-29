# KQL Detection Query Library

A curated set of KQL detection queries for Microsoft Sentinel and Microsoft
Defender XDR, organized by MITRE ATT&CK tactic. Each query is documented
with what it detects, why it matters operationally, and known false
positive sources — the same rigor I'd expect to see reviewed before
promoting a query from "hunting" to "production alert."

## Why this exists

Detection logic is only as useful as its documentation. A query without
context on false positives and severity just shifts triage burden onto
whoever inherits it. Every query here follows the same format so it's easy
to slot into a SOC's existing rule catalog or use as a study reference for
Sentinel/Defender content.

## Structure

Queries are grouped by MITRE ATT&CK tactic, one `.kql` file per detection.
Each file's header comment includes:

- **MITRE ATT&CK mapping** (tactic + technique ID)
- **Log source** (Sentinel table or Defender XDR table)
- **What it detects**
- **Why it matters**
- **False positive considerations**

| Tactic | Query | Technique | Log Source |
|---|---|---|---|
| Initial Access | [Mailbox forwarding rule](initial-access/mailbox-forwarding-rule.kql) | T1114.003 | OfficeActivity |
| Credential Access | [Brute force / password spray](credential-access/brute-force-password-spray.kql) | T1110 | SigninLogs |
| Credential Access | [LSASS credential dumping](credential-access/lsass-credential-dumping.kql) | T1003.001 | DeviceProcessEvents |
| Persistence | [New privileged role assignment](persistence/new-privileged-role-assignment.kql) | T1098.003 | AuditLogs |
| Persistence | [Registry Run key persistence](persistence/registry-run-key-persistence.kql) | T1547.001 | DeviceRegistryEvents |
| Privilege Escalation | [Impossible travel sign-in](privilege-escalation/impossible-travel-signin.kql) | T1078.004 | SigninLogs |
| Defense Evasion | [Event log cleared](defense-evasion/event-log-cleared.kql) | T1070.001 | SecurityEvent |
| Defense Evasion | [Encoded PowerShell command](defense-evasion/encoded-powershell-command.kql) | T1027 / T1059.001 | DeviceProcessEvents |
| Lateral Movement | [RDP logon anomaly](lateral-movement/rdp-logon-anomaly.kql) | T1021.001 | DeviceLogonEvents |
| Command and Control | [Network beaconing](command-and-control/network-beaconing.kql) | T1071 / T1571 | DeviceNetworkEvents |
| Exfiltration | [Unsanctioned cloud upload](exfiltration/unsanctioned-cloud-upload.kql) | T1567.002 | DeviceNetworkEvents |

## Usage

These queries are written for direct use in:

- **Microsoft Sentinel** — Logs blade, Analytics Rules, or Hunting queries
- **Microsoft Defender XDR** — Advanced Hunting

Thresholds (time windows, byte counts, connection counts) are starting
points, not universal constants — every environment's baseline traffic and
auth volume is different. Tune before promoting any of these to a
production alert with paging/escalation attached.

## Roadmap

- [ ] Add Sigma-format equivalents for cross-platform portability
- [ ] Add a scored evaluation harness (true positive / false positive test
      cases per query)
- [ ] Expand Collection and Reconnaissance tactic coverage

## About

Built by [Abdiaziz Maalim](https://github.com/Amaalim1) — Cybersecurity
student focused on detection engineering, threat intelligence, and blue
team tooling.
