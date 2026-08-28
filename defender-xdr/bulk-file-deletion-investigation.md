# Investigating Unexpected Bulk File Deletion

## Overview

Endpoint telemetry showed an application deleting numerous JSON files. Bulk deletion can indicate ransomware, destructive malware, or anti-forensics, but it is also common during upgrades, cache cleanup, and plugin replacement.

## Investigation Scenario

The deleted files were located beneath a resource directory associated with a previous version of a locally installed integration. The investigation focused on whether the behavior was restricted application maintenance or part of a broader destructive pattern.

## Evidence Reviewed

- Initiating process, signer, hash, and installation path
- Deleted paths, extensions, volume, and timing
- Files modified outside the application directory
- Preceding installer, update, or plugin activity
- Shadow-copy deletion and recovery-inhibition behavior
- Ransom-note creation, encryption patterns, and security-control tampering
- Network connections and related alerts

## Sample Hunting Query

```kusto
let StartTime = datetime(2026-03-05 09:00:00);
let EndTime = StartTime + 2h;
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where ActionType == "FileDeleted"
| summarize DeletedFiles=count(),
            ExamplePaths=make_set(FolderPath, 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by DeletedFiles desc
```

## Findings and Assessment

- Deletions were limited to the application's previous plugin-resource directory.
- The filenames and timing aligned with a replacement or cleanup operation.
- No user documents, backups, or security tools were affected.
- No encryption, recovery inhibition, persistence, or suspicious network activity followed.

The behavior was assessed as consistent with legitimate application maintenance. A narrow directory scope was important evidence, but the verdict also depended on the absence of destructive activity elsewhere.

## Lessons Learned

File volume alone does not determine severity. Analysts should evaluate scope, file value, application context, preceding activity, and follow-on behavior before classifying bulk deletion as malicious.

