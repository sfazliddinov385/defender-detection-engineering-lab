# Defender Detection Engineering Lab

Built a Defender detection engineering lab with two Windows 11 hosts and one Kali attacker machine. Ran a six-stage attack chain against Microsoft Defender for Endpoint Plan 2, checked what Defender caught by default, then built custom KQL detections to catch the activity and turn the telemetry into incidents.

---

## Main finding

> **Microsoft Defender for Endpoint recorded every stage of the attack, but it did not create a single built-in incident.**

The full attack chain was visible in Defender telemetry, but the default alerts did not correlate the activity into an incident. I used Advanced Hunting to prove each stage was logged, then built four custom KQL detection rules to close the gap.

After the rules were enabled, Defender created three incidents, including one multi-stage incident that correlated execution and persistence on the same endpoint.

The main lesson: **visibility is not the same as detection**. Defender had the data, but custom detection logic was needed to turn that data into actionable alerts.

---

## Before and after

| Scenario | Incidents created |
|---|---|
| **Default Defender detections only** | **0** — full attack chain was missed as an incident |
| **After custom detection rules** | **3** — including 1 multi-stage incident |

![Default Defender generated 0 incidents from the full 6-stage attack chain](screenshots/18-incidents-empty-before.png)

*Default Defender created 0 incidents from the full six-stage attack. Attack disruptions: None. Multi-alert incidents: 0%.*

![Incidents page after custom detection engineering](screenshots/16-incidents-populated-after.png)

*After the custom rules were enabled, the same activity created three incidents, including one multi-stage incident. Multi-alert incidents: 25%.*

---

## What this project shows

- Built a live Microsoft Defender for Endpoint lab with two Windows 11 victims and one Kali attacker machine.
- Ran a six-stage intrusion chain covering brute force, encoded PowerShell, persistence, discovery, lateral movement, and C2.
- Used Advanced Hunting and KQL to find activity that default Defender detections did not raise as incidents.
- Created four custom detection rules with entity mapping so Defender could group alerts into incidents.
- Tuned a detection rule to remove a false positive from a harmless Microsoft Edge Run key.
- Confirmed RDP lateral movement from `victim-a` to `victim-b`.
- Completed a full NIST SP 800-61 incident response using Defender isolation and Live Response.

---

## Lab environment

| Role | Host | IP | Software |
|------|------|-----|----------|
| Victim A / initial foothold | `victim-a` | `192.168.74.130` | MDE sensor, Sysmon, Atomic Red Team |
| Victim B / lateral movement target | `victim-b` | `192.168.74.137` | MDE sensor, Sysmon, Atomic Red Team |
| Attacker / C2 | `Kali` | `192.168.74.136` | Hydra, Python `http.server` |

All machines ran in VMware Workstation on a NAT network. The Windows hosts had internet access so they could communicate with the Defender cloud.

Full setup:

- [Lab architecture](lab-setup/architecture.md)
- [MDE onboarding](lab-setup/mde-onboarding.md)

---

## Attack chain

Six-stage attack chain mapped to MITRE ATT&CK.

| # | Stage | ATT&CK | Path | Writeup |
|---|-------|--------|------|---------|
| 1 | Initial access through brute force | T1110 | Kali → victim-a | [1-initial-access-T1110.md](attack-chain/1-initial-access-T1110.md) |
| 2 | Encoded PowerShell execution | T1059.001 | victim-a | [2-execution-T1059.001.md](attack-chain/2-execution-T1059.001.md) |
| 3 | Run key persistence | T1547.001 | victim-a | [3-persistence-T1547.001.md](attack-chain/3-persistence-T1547.001.md) |
| 4 | Discovery | T1087 / T1018 | victim-a | [4-discovery-T1087.md](attack-chain/4-discovery-T1087.md) |
| 5 | RDP lateral movement | T1021.001 | victim-a → victim-b | [5-lateral-movement-T1021.001.md](attack-chain/5-lateral-movement-T1021.001.md) |
| 6 | Command and control | T1071 | victim-a → Kali | [6-command-control-T1071.md](attack-chain/6-command-control-T1071.md) |

---

## Custom detection rules

Built four continuous custom detection rules in Advanced Hunting. Each rule included entity mapping so alerts could be tied back to the correct host and user.

Full KQL and rule notes:

- [Custom detection rules](detections/custom-detection-rules.md)

| Rule | ATT&CK | Category | Table |
|------|--------|----------|-------|
| Encoded PowerShell Execution | T1059.001 | Execution | DeviceProcessEvents |
| PowerShell Outbound Network Connection | T1071 | Command and Control | DeviceNetworkEvents |
| Suspicious Run Key Persistence | T1547.001 | Persistence | DeviceRegistryEvents |
| RDP Lateral Movement Detected | T1021.001 | Lateral Movement | DeviceLogonEvents |

The persistence rule also includes a real tuning example. The first version flagged both the malicious Run key and a harmless Microsoft Edge Run key. After tuning, it only flagged the malicious persistence activity.

---

## Multi-stage incident

The strongest result was a correlated multi-stage incident.

After the custom rules were enabled, Defender connected the encoded PowerShell alert and the Run key persistence alert. Both alerts happened on `victim-a` and were tied to the same user, so Defender grouped them into one incident.

Defender named the incident:

> **Multi-stage incident involving Execution & Persistence on one endpoint**

![Multi-stage incident attack story graph](screenshots/19-multistage-attack-story.png)

*The incident graph shows both alerts tied to `victim-a`. The host also shows as isolated, which confirms the containment step.*

---

## Incident response

Completed a full NIST SP 800-61 incident response from detection through recovery.

Full runbook:

- [Incident response runbook](response/incident-response-runbook.md)

```text
DETECT
Four custom rules fired, and Defender created a multi-stage incident.

TRIAGE
Reviewed the incident, decoded the PowerShell cradle, and classified the activity as a True Positive.

CONTAIN
Isolated victim-a from the Microsoft Defender portal.

INVESTIGATE
Used Live Response on victim-a and confirmed the payload was never written to disk.

ERADICATE
Removed the malicious Run key, disabled two accounts, blocked the attacker IP, and re-ran cleanup through Live Response.

VERIFY
Confirmed the Run key was removed locally and through Live Response.

RECOVER
Released victim-a from isolation.
```

![Action Center incident response history](screenshots/20-action-center-ir-history.png)

*The Action Center shows the response history, including isolation, Live Response sessions, cleanup attempts, folder checks, and the script that removed persistence.*

---

## Reusable KQL

All hunting and detection queries used in this lab are documented here:

- [Advanced Hunting KQL](hunting/advanced-hunting-kql.md)

---

## Repository structure

```text
defender-detection-engineering-lab/
├── README.md                          This file
├── lab-setup/
│   ├── architecture.md                Hosts, network, accounts
│   └── mde-onboarding.md              Tenant, trial, onboarding
├── attack-chain/
│   ├── 1-initial-access-T1110.md
│   ├── 2-execution-T1059.001.md
│   ├── 3-persistence-T1547.001.md
│   ├── 4-discovery-T1087.md
│   ├── 5-lateral-movement-T1021.001.md
│   └── 6-command-control-T1071.md
├── detections/
│   └── custom-detection-rules.md      4 rules, entity mapping, and tuning
├── response/
│   └── incident-response-runbook.md   Full NIST 800-61 response cycle
├── hunting/
│   └── advanced-hunting-kql.md        Reusable hunting and detection KQL
└── screenshots/                       Evidence
```

---

## Safety and scope

This was a closed lab built for learning and portfolio demonstration. Every host, account, and password used in this project was a lab asset.

I only ran attacker tools against machines I owned and controlled inside an isolated virtual network. I decoded attacker commands for analysis, but I did not run decoded payloads outside the lab.
