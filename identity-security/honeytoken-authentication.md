# Investigating Honeytoken Authentication

## Overview

A decoy account generated authentication activity from a workstation toward a domain controller. Because the account had no legitimate operational use, even a failed attempt required investigation.

## Why Honeytoken Alerts Matter

Honeytokens are intentionally unused identities. Activity may indicate password spraying, credential discovery, stale stored credentials, a misconfigured script, or an attacker testing access. Successful authentication significantly increases the urgency.

## Investigation Questions

- Was authentication successful or unsuccessful?
- Which system and process initiated it?
- What user sessions were active on the source device?
- Which protocol and logon type were used?
- Was the account stored in a service, scheduled task, script, or credential manager?
- Were other accounts tested from the same source?
- Did the attempt lead to privilege use or lateral movement?

## Sample Hunting Queries

```kusto
let Honeytoken = "decoy.admin";
let AlertTime = datetime(2026-05-01 12:00:00);
DeviceLogonEvents
| where Timestamp between (AlertTime - 2h .. AlertTime + 2h)
| where AccountName =~ Honeytoken
| project Timestamp, DeviceName, ActionType, LogonType,
          RemoteIP, InitiatingProcessFileName, FailureReason
| order by Timestamp asc
```

```kusto
let SourceDevice = "LAB-WKS-07";
let AlertTime = datetime(2026-05-01 12:00:00);
DeviceProcessEvents
| where DeviceName == SourceDevice
| where Timestamp between (AlertTime - 30m .. AlertTime + 30m)
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

## Assessment Framework

An unsuccessful attempt may result from stale credentials or reconnaissance, but the originating process must still be established. Successful authentication should trigger immediate containment, credential rotation, source-device investigation, and review of subsequent account activity.

Apparent timing differences should be checked for UTC conversion, ingestion delay, and the distinction between authentication telemetry and endpoint event timestamps.

## Lessons Learned

A honeytoken's value depends on having no legitimate use and a documented response plan. Analysts should know the account owner, permitted exceptions, severity model, and containment authority before the first alert occurs.

