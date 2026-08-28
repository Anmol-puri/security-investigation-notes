# Attributing an Internal IP Address to the Correct Device

## Overview

An alert identified an internal source IP, but Microsoft Defender associated the address with multiple devices and logged-on users. The investigation required time-bounded attribution rather than assuming that every historical association represented the device involved in the alert.

> All indicators and environment details in this article are sanitized.

## Why This Is Difficult

Internal addresses can be reassigned through DHCP or represented by VPN concentrators, NAT devices, proxies, RDP gateways, jump servers, or shared infrastructure. Defender's long-term “observed in organization” information is useful context, but it is not definitive identity evidence for one moment in time.

## Investigation Approach

1. Define a narrow time window around the alert.
2. Search device network events for the IP during that window.
3. Correlate device logons and remote-interactive sessions.
4. Determine whether the address was local, remote, intermediary, or translated.
5. Review DHCP, VPN, firewall, proxy, and RDP records where available.
6. Compare timestamps in a consistent timezone and account for ingestion delay.

## Sample Hunting Queries

```kusto
let TargetIP = "10.x.x.x";
let AlertTime = datetime(2026-02-10 18:30:00);
DeviceNetworkInfo
| where Timestamp between (AlertTime - 2h .. AlertTime + 2h)
| mv-expand IPAddress = IPAddresses
| extend Address = tostring(IPAddress.IPAddress)
| where Address == TargetIP
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, Address
| order by LastSeen desc
```

```kusto
let TargetIP = "10.x.x.x";
let AlertTime = datetime(2026-02-10 18:30:00);
DeviceLogonEvents
| where Timestamp between (AlertTime - 2h .. AlertTime + 2h)
| where RemoteIP == TargetIP
| project Timestamp, DeviceName, AccountDomain, AccountName,
          LogonType, ActionType, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc
```

## Findings and Assessment

The address had multiple historical associations, so it could not independently identify the originating endpoint. Attribution required corroboration from telemetry recorded closest to the alert time and, where possible, the authoritative DHCP or VPN lease record.

## Lessons Learned

Treat an IP address as a pivot, not a person or permanent device identity. State confidence explicitly: confirmed, probable, possible, or unresolved. If network telemetry is insufficient, preserve the ambiguity instead of forcing a conclusion.

