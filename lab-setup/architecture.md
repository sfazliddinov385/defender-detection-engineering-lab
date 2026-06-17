# Lab Architecture

## The setup

Three machines. Two are victims protected by the EDR. One is the attacker. The two victims let me show a jump from one machine to another.

```
                    ┌─────────────────────────────┐
                    │   Microsoft Defender cloud   │
                    │  (*.security.microsoft.com)  │
                    └──────────────┬──────────────┘
                                   │ sensor data (outbound)
            ┌──────────────────────┼──────────────────────┐
            │                      │                      
   ┌────────┴────────┐    ┌────────┴────────┐    ┌─────────────────┐
   │    victim-a     │    │    victim-b     │    │      Kali       │
   │ 192.168.74.130  │◄───┤ 192.168.74.137  │    │ 192.168.74.136  │
   │  Windows 11     │RDP │  Windows 11     │    │   attacker /    │
   │  MDE sensor     │    │  MDE sensor     │    │       C2        │
   └────────┬────────┘    └─────────────────┘    └────────┬────────┘
            │                                              │
            └──────────────── brute force + C2 ────────────┘
```

## The machines

| Role | Host (Defender name) | IP | Software |
|------|----------------------|-----|----------|
| Victim A — first target, main foothold | victim-a | 192.168.74.130 | MDE sensor, Sysmon, Atomic Red Team |
| Victim B — lateral movement target | victim-b | 192.168.74.137 | MDE sensor, Sysmon, Atomic Red Team |
| Attacker / C2 | Kali | 192.168.74.136 | Hydra, Python http.server |

## Hypervisor and network

- **Hypervisor:** VMware Workstation.
- **Network:** NAT, **with internet access**. This part matters. The MDE sensors have to reach the Defender cloud (`*.endpoint.security.microsoft.com`) to onboard and send data. All three machines can talk to each other and to the internet.
- **Why not host-only:** I tried a closed host-only network first. It broke onboarding — the sensor couldn't reach the Defender cloud. NAT with internet fixed it. More on that in [mde-onboarding.md](mde-onboarding.md).

## The accounts

| Account | Host | What it's for |
|---------|------|---------------|
| `sfazl` | victim-a | Main user (SID ends in `-1001`). The Run key persistence was written under this user. |
| `labvictim` | victim-a | Local account I brute-forced. Cracked password: `P@ssw0rd123!`. Disabled during cleanup. |
| `labtest` | victim-b | Account used for the RDP jump into victim-b. Disabled during cleanup. |

## Fixing the cloned machines (HEADACHE)

Both Windows 11 VMs started with the same hostname, `Advanced.lab.local`, because victim-b was a clone of victim-a. Both were also stuck on a `lab.local` domain whose controller was gone.

Trying to leave the domain the clean way failed — "the domain could not be contacted." Here's what worked:

1. Forced workgroup membership through `sysdm.cpl` (System Properties → Computer Name → Change → Workgroup = `WORKGROUP`).
2. Rebooted and logged in with **local** accounts. You need the local password first, or you lock yourself out.
3. Renamed the machines to `victim-a` and `victim-b`.
4. Checked with `hostname` and `systeminfo | findstr Domain` that each said `WORKGROUP`.

The old `Advanced.lab.local` records in Defender were left to drop off on their own. I didn't exclude them — that only affects vulnerability views, and Defender warned the devices were still active.
