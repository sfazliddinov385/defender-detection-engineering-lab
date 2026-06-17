# Onboarding Microsoft Defender for Endpoint

## Tenant and trial

- **Tenant:** `Beckslab.onmicrosoft.com`
- **License:** Microsoft Defender for Endpoint Plan 2 (P2) web trial — 25 user licenses, about 50 devices, US region.
- **Region:** United States.

### Why I used the P2 web trial

I looked at a few ways to get a Defender environment first:

- The Microsoft 365 Developer Program E5 sandbox needed a Visual Studio subscription.
- Azure for Students doesn't include Defender for Endpoint.

The standalone P2 web trial had no sales call and no approval gate. It was the fastest way to a working tenant.

### It takes a day to turn on

A fresh trial tenant takes about 24 hours to fully provision. During that time the onboarding pages threw "Something went wrong." A license being assigned is not the same as the service being ready. The service has to come online first.

## Onboarding the sensors

I onboarded both Windows 11 VMs with the **Defender deployment tool**. That's the newer replacement for the old local onboarding script in this tenant.

After onboarding, both machines showed **Onboarded + Active** under Assets → Devices.

### Things that tripped me up

- **Network:** the sensors need internet to reach the Defender cloud. A closed host-only network made the deployment tool fail (exit code 400). Switching to NAT with internet fixed it. This was the biggest blocker in setup.
- **Right tenant:** I made sure the portal said **Becks lab** before doing anything. I have another tenant too, and running this in the wrong one would just give me empty results.
- **Machine identity:** the two VMs shared a hostname and were stuck on a dead domain. How I fixed that is in [architecture.md](architecture.md#fixing-the-cloned-machines-a-real-headache).

## Checking that data flows

Once both sensors were active, I ran a few harmless commands on each machine and queried the matching tables (`DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`). Seeing the events show up told me the sensors were reporting before I started the attack.
