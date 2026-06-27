# Onboarding Microsoft Defender for Endpoint

Set up a Microsoft Defender for Endpoint Plan 2 lab tenant and onboarded two Windows 11 VMs as sensors. Used the Defender deployment tool, confirmed both machines reported as active, then verified telemetry across process, logon, registry, and network event tables before starting the attack chain.

## Tenant and trial

- **Tenant:** `Beckslab.onmicrosoft.com`
- **License:** Microsoft Defender for Endpoint Plan 2 web trial
- **Capacity:** 25 user licenses, about 50 devices
- **Region:** United States

## Why I used the P2 web trial

I checked a few options before choosing the standalone Defender for Endpoint Plan 2 trial:

- The Microsoft 365 Developer Program E5 sandbox required a Visual Studio subscription.
- Azure for Students did not include Defender for Endpoint.
- The standalone P2 web trial did not require a sales call or approval process.

The P2 web trial was the fastest way to get a working Defender tenant for the lab.

## Provisioning delay

A fresh trial tenant did not work immediately. It took about 24 hours before Defender for Endpoint was fully provisioned.

During that time, the onboarding pages showed:

```text
Something went wrong
```

The main lesson: assigning a license does not mean the service is ready. The Defender service has to finish provisioning before onboarding works.

## Onboarding the sensors

I onboarded both Windows 11 VMs with the **Defender deployment tool**. In this tenant, that was the newer replacement for the older local onboarding script.

After onboarding, both machines showed:

```text
Onboarded + Active
```

Path checked:

```text
Assets -> Devices
```

## Setup issues I fixed

### Network access

The sensors needed internet access to reach the Defender cloud.

My first setup used a closed host-only network, and the deployment tool failed with exit code `400`. Switching the VMs to NAT with internet access fixed the issue.

This was the biggest setup blocker.

### Correct tenant

Before onboarding anything, I confirmed the Defender portal showed the correct tenant:

```text
Becks lab
```

I had access to another tenant too, so using the wrong one would have caused empty results and missing device data.

### Machine identity

The two Windows VMs were cloned, so they shared a hostname and were still tied to a dead domain. That caused device identity issues.

I documented the fix here:

- [Fixing the cloned machines](architecture.md#fixing-the-cloned-machines-a-real-headache)

## Verifying data flow

Once both sensors were onboarded and active, I ran a few harmless commands on each machine and checked the matching Defender tables:

- `DeviceProcessEvents`
- `DeviceLogonEvents`
- `DeviceRegistryEvents`
- `DeviceNetworkEvents`

Seeing events in those tables confirmed that telemetry was flowing correctly before I started the attack chain.
