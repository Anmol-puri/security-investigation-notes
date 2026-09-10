# Investigating Suspected DCSync Activity

## Overview

Microsoft Defender for Identity generated a suspected DCSync alert involving a service account. DCSync abuse allows an attacker with replication privileges to request credential data from a domain controller, so the alert required urgent validation.

## Initial Risk

The account had been observed across multiple systems, and the activity resembled directory replication. Possible explanations included compromised replication credentials, unauthorized privilege assignment, or legitimate identity-synchronization activity.

## Evidence Reviewed

- Source device identity and business purpose
- Account type, ownership, privileges, and normal usage
- Directory-replication permissions
- Authentication and logon history
- Processes operating under the account
- Domain-controller communication
- Related identity or endpoint alerts
- Recent changes to the account or synchronization configuration

## Investigation Approach

The source was validated as an approved Microsoft Entra Connect server. Its synchronization service and associated Windows processes communicated with domain controllers as part of the expected directory-synchronization workflow.

I confirmed that the account was associated with the synchronization platform, the activity came from the expected server, and no interactive use, alternate source, lateral movement, or supporting credential-theft behavior was present.

## Sample Advanced Hunting Query

```kusto
let SuspectAccount = "sync_service";
let AlertTime = datetime(2026-04-01 16:00:00);
IdentityLogonEvents
| where Timestamp between (AlertTime - 6h .. AlertTime + 2h)
| where AccountName =~ SuspectAccount
| project Timestamp, AccountName, ActionType, LogonType,
          DeviceName, DestinationDeviceName, IPAddress, Protocol
| order by Timestamp asc
```

## Findings and Assessment

- The source was an authorized synchronization server.
- The account and processes aligned with the server's documented purpose.
- No unexpected source device or interactive sign-in was found.
- No additional evidence supported credential theft or lateral movement.

The alert was assessed as expected directory-synchronization activity after validating the server, account, privileges, and surrounding behavior.

## When to Escalate

Escalate if replication originates from a workstation, an unapproved server, a newly privileged identity, or a source showing LSASS access, credential dumping, remote-service creation, or unusual administrative logons.

## Lessons Learned

Do not automatically suppress DCSync alerts for service accounts. Build an allowlist only after verifying the exact account-source relationship, and alert whenever that relationship changes.

