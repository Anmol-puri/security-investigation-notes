# Investigating Suspicious PowerShell Activity in Microsoft Defender XDR

## Overview

Microsoft Defender XDR generated a behavioral alert after PowerShell was launched through an AI-assisted development application. The commands read temporary files, processed HTML, invoked Windows Data Protection API (DPAPI), and converted data to Base64. These are dual-use behaviors: legitimate applications use them, but attackers also use them for collection and credential access.

> This case study uses fictional identities and sanitized technical details. 

## Investigation Scenario

The general process lineage was:

```text
explorer.exe
└── development-application.exe
    └── development-agent.exe
        └── pwsh.exe
```

Later, the development application deleted JSON files from a directory associated with a previous plugin installation.

## Questions to Answer

- Did the user intentionally launch the parent application?
- What did each PowerShell command actually do?
- Was protected or decoded data transmitted elsewhere?
- Did the activity create persistence or execute another payload?
- Was file deletion restricted to the application's directory?
- Were there related credential-theft or lateral-movement alerts?

## Evidence Reviewed

- Full parent-child process lineage and command lines
- File creation, read, modification, and deletion events
- Network connections from PowerShell and its parent processes
- Code signatures and file hashes
- User and device context
- Related alerts before and after the detection
- Public reporting about comparable supply-chain behavior

## Investigation Approach

### 1. Establish execution context

The process tree showed that PowerShell originated from a user-launched application. This supported a possible legitimate explanation, but a trusted-looking parent alone was not sufficient to close the alert.

### 2. Interpret the commands

One command read a local HTML file, decoded HTML entities, removed script and style elements, stripped markup, normalized whitespace, and extracted a limited portion of the resulting text. It processed local content rather than executing code from the page.

A second command used DPAPI under the current-user context and encoded the result as Base64. Because this could expose protected application data, I treated it as sensitive and investigated what happened to the output.

### 3. Search for follow-on behavior

I looked for the output being written to an unusual location, passed to an unknown executable, transmitted externally, or followed by persistence, credential access, or lateral movement. No such supporting activity was identified.

### 4. Review file deletion scope

The JSON deletions were confined to a previous plugin-resource directory. There was no broad document deletion, shadow-copy manipulation, or other destructive pattern. The scope was consistent with plugin replacement or application cleanup.

## Sample Hunting Queries

```kusto
let StartTime = datetime(2026-01-15 14:00:00);
let EndTime = StartTime + 2h;
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

```kusto
let StartTime = datetime(2026-01-15 14:00:00);
let EndTime = StartTime + 2h;
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "development-agent.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp asc
```

## Findings and Assessment

- The user intentionally launched the development application.
- HTML content was parsed locally rather than executed.
- DPAPI was used, but no evidence showed that the output was exfiltrated.
- No malicious payload, persistence, or suspicious follow-on connection was found.
- File deletions were limited to an application-owned plugin directory.

The evidence was most consistent with legitimate development and plugin-management activity. The conclusion relied on the complete behavior - not on trusting the parent application or dismissing PowerShell as harmless.

## Lessons Learned

PowerShell, DPAPI, Base64, and file deletion are not verdicts by themselves. A reliable assessment must establish who initiated the action, what data was accessed, what happened to the output, and whether malicious follow-on behavior occurred.

