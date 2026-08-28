# Analyzing a PowerShell DPAPI Decryption Command

## Overview

A PowerShell command read a binary file from a temporary directory, invoked Windows DPAPI using the current-user scope, and converted the result to Base64. Because attackers may abuse DPAPI to recover browser or application secrets, the command required careful analysis.

## Technical Behavior

Conceptually, the command performed three actions:

1. Read bytes from a local file.
2. Ask Windows to decrypt data protected for the current user.
3. Represent the result as Base64 text.

None of these steps independently proves credential theft. The investigation must determine the file's origin, the initiating application, and how the decrypted output was used.

## Investigation Approach

- Identify the parent and grandparent processes.
- Determine which process created the protected file.
- Review the file path, creation time, hash, and access history.
- Search for browser, credential-manager, token-cache, or application-secret access.
- Look for output redirection, clipboard access, child processes, and external connections.
- Check whether the same behavior is reproducible during an approved application workflow.

## Sample Hunting Query

```kusto
let Device = "LAB-WIN11-01";
let StartTime = datetime(2026-03-12 13:00:00);
DeviceProcessEvents
| where DeviceName == Device
| where Timestamp between (StartTime - 30m .. StartTime + 90m)
| where ProcessCommandLine has_any ("ProtectedData", "Unprotect", "CurrentUser", "ToBase64String")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp asc
```

## Assessment

DPAPI is a security boundary and a normal Windows application service. The command remained suspicious until its data flow was understood, but there was no evidence in this scenario that the result was persisted, passed to an unknown program, or transmitted externally.

## Escalation Indicators

- Access to browser login databases or token caches
- Execution by an unexpected user or unsigned program
- Output written to staging archives
- Connections to unknown external destinations
- Credential dumping, persistence, or lateral movement nearby

## Lessons Learned

Technique-based detections are starting points. The decisive question is not merely whether protected data was decrypted, but whether the caller was authorized and what happened to the plaintext.

