# Stage 4 — Discovery

**MITRE ATT&CK:** [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) and [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
**Path:** victim-a
**Table:** `DeviceProcessEvents`

---

## What I ran

On victim-a, as `sfazl`, I ran the usual built-in commands to look around — find the local account, check group membership, see what else is reachable. This is the recon an attacker does after getting in and before moving to another machine:

- `whoami /groups` — my groups
- `net user` — local accounts
- `net user labvictim` — detail on the cracked account
- `net localgroup administrators` — who's a local admin
- `net localgroup "Remote Desktop Users"` — who can RDP in
- `net view` — what's reachable on the network

![Discovery commands in DeviceProcessEvents](../screenshots/05-stage4-discovery.png)
*Discovery commands (whoami, net user, net localgroup, net view) in DeviceProcessEvents, all run as sfazl.*

## What Defender recorded

```kusto
DeviceProcessEvents
| where DeviceName startswith "victim-a"
| where Timestamp > ago(2h)
| where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "arp.exe")
| where InitiatingProcessAccountName !~ "system"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

Heads up: `net.exe` often spawns `net1.exe` as a child. So both show up. That's normal Windows behavior, worth knowing when you read the data.

## What Defender did

Default Defender raised **no incident** for the recon. Every one of these is a normal admin tool used all day, everywhere. On its own, none crosses a threshold. That's exactly why discovery is so easy to hide in normal activity.

Discovery is on purpose **not** one of my four rules. To catch it well you need behavioral logic — like many different recon commands from one process in a short window. That's a harder build. I'm documenting this stage so the attack story is complete and to show the data is there to hunt.

## Tier 1 triage

- **Commands:** harmless one at a time, a recon pattern together. One `whoami` is nothing. But `whoami /groups`, then `net user`, `net localgroup administrators`, `net localgroup "Remote Desktop Users"`, and `net view` back to back from one session is a clear recon run.
- **Context:** this matters most *after* an initial-access alert. Alone it's weak. Chained to the Stage 1 brute force and Stage 2 execution on the same host, it adds weight that the box is compromised.
- **Verdict:** suspicious together, low confidence alone.

## Detection takeaway

Discovery is the hardest stage to catch cleanly because it's all native tools. The real approach is behavioral — count different recon commands per host or user over a window — not alert on any single command. This stage is a good reminder that not every ATT&CK technique needs its own rule.
