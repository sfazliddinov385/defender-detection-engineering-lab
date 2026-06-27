# Advanced Hunting KQL Reference

Reusable KQL queries from the project, grouped by Microsoft Defender table. These queries were used for hunting, validation, and custom detection rule logic.

Time and host filters are included for convenience. Widen or remove them when doing broader hunting.

## Table notes

A few table-specific lessons shaped how these queries were written:

- **`DeviceNetworkEvents` does not have `AccountName` or `AccountSid`.** Use `InitiatingProcessAccountName` and `InitiatingProcessAccountSid` instead. Using `AccountName` in this table causes the error: `Failed to resolve scalar expression named 'AccountName'`.
- **`DeviceLogonEvents` and `DeviceProcessEvents` include `AccountName` and `AccountSid` directly.** No `Initiating` prefix is needed for the acting account in these tables.
- **Custom detection rules need entity columns.** Include `DeviceId` and a SID column in the projection so Defender can map alerts to devices and users. `ReportId` is also required for custom detection rules.

---

## DeviceLogonEvents

### Brute force: failed-then-success pattern

Used to review Stage 1 initial access activity against `victim-a`.

```kusto
DeviceLogonEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(30m)
| where AccountName == "labvictim"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, Protocol
| order by Timestamp asc
```

### RDP lateral movement: inbound RemoteInteractive logons

Used to review Stage 5 lateral movement into `victim-b`.

```kusto
DeviceLogonEvents
| where DeviceName startswith "victim-b"
| where Timestamp > ago(30m)
| where AccountName == "labtest"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| order by Timestamp desc
```

### RDP lateral movement detection rule

Detection form for Rule 4. Flags successful inbound RDP logons with a remote IP.

```kusto
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid, RemoteIP, RemoteDeviceName, ReportId
```

---

## DeviceProcessEvents

### Encoded PowerShell execution

Used for Stage 2 execution and Rule 1. Flags PowerShell commands using encoded command options.

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-e ")
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
```

### Discovery commands

Used to review Stage 4 discovery activity on `victim-a`.

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

### Run key persistence hunting query

Used to review Stage 3 persistence activity. Searches for Run key changes.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(1h)
| where RegistryKey has @"CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

### Tuned Run key persistence detection rule

Detection form for Rule 3. Filters out common benign apps and focuses on script-based or suspicious Run key values.

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

---

## DeviceNetworkEvents

### C2 beacon to attacker host

Used to review Stage 6 command and control traffic from `victim-a` to the Kali attacker machine.

```kusto
DeviceNetworkEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(30m)
| where RemoteIP == "192.168.74.136"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PowerShell outbound network connection detection rule

Detection form for Rule 2. Flags PowerShell making outbound connections to common web and C2 ports.

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
