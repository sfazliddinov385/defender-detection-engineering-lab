# Advanced Hunting KQL Reference

Every reusable KQL query from the project, in one place. They're grouped by the table they run against. Time and host filters are there for convenience — widen or drop them when you hunt.

## Table notes

A few table-specific things I learned that shape how these queries are written:

- **`DeviceNetworkEvents` has no `AccountName` / `AccountSid`.** Use `InitiatingProcessAccountName` / `InitiatingProcessAccountSid`. Using `AccountName` here throws "Failed to resolve scalar expression named 'AccountName'".
- **`DeviceLogonEvents` and `DeviceProcessEvents` have `AccountName` / `AccountSid` directly** (no `Initiating` prefix needed for the acting account).
- **Detection rules need entity columns.** Put `DeviceId` and a SID column in the projection so the rule can map entities for grouping. `ReportId` is also required for detection rules.

---

## DeviceLogonEvents

### Brute force: failed-then-success (Stage 1)

```kusto
DeviceLogonEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(30m)
| where AccountName == "labvictim"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, Protocol
| order by Timestamp asc
```

### RDP lateral movement: inbound RemoteInteractive logons (Stage 5)

```kusto
DeviceLogonEvents
| where DeviceName startswith "victim-b"
| where Timestamp > ago(30m)
| where AccountName == "labtest"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| order by Timestamp desc
```

### RDP lateral movement: detection form (Rule 4)

```kusto
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid, RemoteIP, RemoteDeviceName, ReportId
```

---

## DeviceProcessEvents

### Encoded PowerShell (Stage 2 / Rule 1)

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-e ")
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
```

### Discovery commands (Stage 4)

```kusto
DeviceProcessEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(2h)
| where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "arp.exe")
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## DeviceRegistryEvents

### Run key persistence: hunting form (Stage 3)

```kusto
DeviceRegistryEvents
| where Timestamp > ago(1h)
| where RegistryKey has @"CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

### Run key persistence: tuned detection form (Rule 3)

```kusto
DeviceRegistryEvents
| where RegistryKey has @"CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessAccountName !~ "system"
// skip normal apps that use Run keys
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe", "OneDrive.exe", "Teams.exe")
// only flag scripts or sneaky folders
| where RegistryValueData has_any (".ps1", ".vbs", ".bat", ".js", "\\Public\\", "\\Temp\\", "\\AppData\\")
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid,
          RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ReportId
```

---

## DeviceNetworkEvents

### C2 / beacon to a specific host (Stage 6)

```kusto
DeviceNetworkEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(30m)
| where RemoteIP == "192.168.74.136"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PowerShell out to common C2 ports: detection form (Rule 2)

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
