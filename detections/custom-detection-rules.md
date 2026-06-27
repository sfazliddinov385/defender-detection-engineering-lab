# Custom Detection Rules

Built four custom detection rules in Microsoft Defender Advanced Hunting after confirming that default Defender detections created zero incidents for the attack chain.

All four rules were created through:

```text
Advanced Hunting -> Create detection rule
```

Each rule was set to **Continuous (NRT)** and included entity mappings so Defender could group related alerts into incidents.

## Why entity mapping matters

A query that only returns rows is a hunting query. To turn it into a detection rule that creates alerts and incidents, the rule needs mapped entities.

At minimum, I mapped:

- **Device:** `DeviceId`
- **User:** a SID column, such as `AccountSid` or `InitiatingProcessAccountSid`

Defender uses shared entities like host, user, IP, and timing to group alerts into incidents. That is what allowed the execution and persistence alerts to become one multi-stage incident.

Two setup notes:

- A half-filled **Related Evidence** entity can block the rule from saving. Either finish the dropdown mappings or remove the entity with the blue X.
- If the top-right button says **View rule**, you are editing an existing rule. To create a new rule, open a fresh query tab with the **+** button.

---

## Rule 1: Encoded PowerShell Execution

**ATT&CK:** T1059.001  
**Category:** Execution  
**Severity:** Medium  
**Table:** `DeviceProcessEvents`

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-e ")
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
```

**Entity mapping**

| Entity | Column |
|--------|--------|
| Device | `DeviceId` |
| User SID | `AccountSid` |

**Why this rule exists**

This rule detects PowerShell execution using encoded command flags. That matched Stage 2 of the attack chain.

Filtering out the `system` account helped reduce noise from legitimate system-run PowerShell activity.

**Result**

This rule fired and created a custom detection alert. It later became part of the multi-stage incident with the Run key persistence alert.

![Encoded PowerShell detection rule](../screenshots/11-rule1-encoded-ps.png)

*The Encoded PowerShell Execution rule matching the Stage 2 activity.*

---

## Rule 2: PowerShell Outbound Network Connection

**ATT&CK:** T1071  
**Category:** Command and Control  
**Severity:** Medium  
**Table:** `DeviceNetworkEvents`

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemotePort in (80, 443, 8080, 4444)
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, DeviceId, DeviceName,
          InitiatingProcessAccountName, InitiatingProcessAccountSid,
          RemoteIP, RemotePort, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ReportId
```

**Entity mapping**

| Entity | Column |
|--------|--------|
| Device | `DeviceId` |
| User SID | `InitiatingProcessAccountSid` |

**Schema note**

`DeviceNetworkEvents` does not have `AccountName` or `AccountSid`.

For this table, the correct columns are:

- `InitiatingProcessAccountName`
- `InitiatingProcessAccountSid`

Using `AccountName` in this table causes this error:

```text
Failed to resolve scalar expression named 'AccountName'
```

**Why this rule exists**

This rule detects PowerShell making outbound network connections to common web and C2 ports. That matched the network side of Stage 6 command and control activity.

Filtering by PowerShell, common ports, and non-system users kept the rule focused.

![PowerShell outbound network detection rule](../screenshots/10-rule2-ps-network.png)

*The PowerShell Outbound Network Connection rule with Device and SID entities mapped.*

---

## Rule 3: Suspicious Run Key Persistence

**ATT&CK:** T1547.001  
**Category:** Persistence  
**Severity:** Medium  
**Table:** `DeviceRegistryEvents`

```kusto
DeviceRegistryEvents
| where RegistryKey has @"CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessAccountName !~ "system"
// Skip normal apps that commonly use Run keys
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe", "OneDrive.exe", "Teams.exe")
// Focus on scripts and suspicious user-writable paths
| where RegistryValueData has_any (".ps1", ".vbs", ".bat", ".js", "\\Public\\", "\\Temp\\", "\\AppData\\")
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid,
          RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ReportId
```

**Entity mapping**

| Entity | Column |
|--------|--------|
| Device | `DeviceId` |
| User SID | `InitiatingProcessAccountSid` |

## Tuning story

This rule is the clearest detection engineering example in the project because the first version was noisy.

### Before tuning

A basic query that matched any Run key write returned two rows:

| Result | Description |
|--------|-------------|
| True positive | `Updater` pointing to `C:\Users\Public\beacon.ps1` on `victim-a` |
| False positive | `MicrosoftEdgeAutoLaunch_...` written by `msedge.exe` on `victim-b` |

![Run key detection before tuning: 2 rows including benign Edge key](../screenshots/13-rule3-fp-before.png)

*Before tuning, the rule returned both the malicious Updater key and a harmless Microsoft Edge startup key.*

### After tuning

I added two refinements:

- Skipped known-good apps that commonly use Run keys: `msedge.exe`, `chrome.exe`, `OneDrive.exe`, and `Teams.exe`
- Required the value data to include a script extension or suspicious user-writable path, such as `.ps1`, `.vbs`, `.bat`, `.js`, `\Public\`, `\Temp\`, or `\AppData\`

After tuning, the query returned one row: only the malicious Run key.

![Run key detection after tuning: 1 malicious row only](../screenshots/15-rule3-fp-after.png)

*After tuning, only the malicious Updater key remained. The benign Edge key was removed.*

This is the part that shows real detection engineering. A rule is not useful just because it catches a true positive. It also needs to ignore normal activity. This tuning step removed the false positive while keeping the true detection.

---

## Rule 4: RDP Lateral Movement Detected

**ATT&CK:** T1021.001  
**Category:** Lateral Movement  
**Severity:** Medium  
**Table:** `DeviceLogonEvents`

```kusto
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid, RemoteIP, RemoteDeviceName, ReportId
```

**Entity mapping**

| Entity | Column |
|--------|--------|
| Device | `DeviceId` |
| Source device | `RemoteDeviceName` |
| User SID | `AccountSid` |
| Related IP evidence | `RemoteIP` |

**Why this rule exists**

This rule detects successful RemoteInteractive logons with a remote source IP. That matched Stage 5, where the attacker pivoted from `victim-a` to `victim-b` over RDP.

`DeviceLogonEvents` has `AccountSid` directly, so it does not need the `InitiatingProcess` prefix used in `DeviceNetworkEvents`.

**Entity mapping detail**

Mapping `RemoteDeviceName` as a second device gave the alert better cross-host context. It showed both the target host, `victim-b`, and the source host, `victim-a`, involved in the RDP pivot.

**Result**

This rule fired and created its own incident:

```text
RDP Lateral Movement Detected on victim-b
```

![RDP lateral movement detection rule](../screenshots/14-rule4-rdp-lateral.png)

*The RDP Lateral Movement rule matching the Stage 5 pivot, with source and target machine entities.*

---

## The payoff: multi-stage incident

With the custom rules enabled, the Incidents page changed from empty to populated.

The main incident was:

```text
Multi-stage incident involving Execution & Persistence on one endpoint
```

**Incident details**

| Field | Value |
|-------|-------|
| Severity | Medium |
| Categories | Execution, Persistence |
| Alerts | 2/2 |
| Detection source | Custom detection |
| Asset | `victim-a` |

Defender took the **Encoded PowerShell Execution** alert and the **Suspicious Run Key Persistence** alert and merged them into one incident.

Both alerts shared:

- Same host: `victim-a`
- Same user: `sfazl`
- Related timing
- Custom detection source

Defender named and correlated the incident automatically.

![Multi-stage incident attack story graph](../screenshots/19-multistage-attack-story.png)

*The incident graph shows both alerts tied to victim-a. The host also shows as isolated after containment.*

## Honest note on grouping

Defender grouped the two same-host, same-user alerts from `victim-a` into one incident:

- Execution
- Persistence

The RDP lateral movement alert on `victim-b` stayed as a separate incident because it involved a different machine and a different account, `labtest`.

That is expected behavior. Defender groups alerts based on shared entities and timing. Since the lateral movement alert did not share the same host or user, it did not merge with the `victim-a` incident.

In a real environment, alerts are more likely to merge when the same account, device, IP, or session appears across multiple stages.

The result was still successful: the **Multi-alert incidents** tile changed from `0%` to `25%`, confirming that the custom rules created grouped incidents.
