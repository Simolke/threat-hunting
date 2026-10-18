# Cormorant Capital // Copilot Hijack (Indirect Prompt Injection) Full Incident Response Report
 
**Analyst:** Zach S.  
**Date Completed:** 17 October 2026  
**Flags Captured:** 17 of 17 across 6 hunt sections
 
---
 
## Executive Summary
 
On 20 September 2026 a financial analyst at Cormorant Capital Partners, Emily Chen, received an external email carrying `Q3-2026-Global-Markets-Review.docx`. About 87 minutes later she asked Microsoft 365 Copilot to summarize it. Hidden instructions in the document steered Copilot into 21 Graph tool calls that searched and read 13 confidential files (board, M&A, salary, client and insider-trading material), including Copilot's own system configuration. Copilot then wrote 13 markdown image URLs to `metrics-cdn.analyticshub.io` with base64-encoded file names in the query string. Every action ran under Emily's legitimate session, so sign-in logs showed nothing unusual. The incident is classified as external input manipulation, not a compromised account or a compromised Copilot configuration. The audit data proves Copilot wrote the URLs; it does not prove the client fetched them or that any file content left the tenant.
 
---
 
## Environment
 
- **Workspace:** LAW-HuntPractice (RunId `el--17-20260920`)
- **Log Sources:** `OfficeActivity_CL`, `CopilotAudit_CL`, `EntraSignIn_CL`
- **Domain:** cormorantcapital.com (about 200 users, M365 E5 with Copilot)
- **Users in Scope:** emily.chen@cormorantcapital.com, mark.ross@cormorantcapital.com
- **Window:** 20 September 2026, 09:00 to 11:00 UTC (portal display was UTC-7)
---
 
## Attack Chain Overview
 
1. **Delivery:** external email with a poisoned `.docx` reaches Emily (09:15:22 UTC)
2. **Hijack:** after about 87 minutes of dormancy, a summary request pulls the hidden instructions into Copilot's context (10:42:35)
3. **Extraction:** Copilot searches and reads five sensitive files and embeds beacon URLs in its response (10:42:41 to 10:43:08)
4. **Blast radius:** its configuration is printed in plaintext, 13 files in total are exposed and the beacons point to one external domain (10:44:19 to 10:46:35)
5. **Judgement:** the session is compared with Emily's normal Copilot use and found to be hijacked
6. **Impact and classification:** eight more files found through keyword search, total exposure set at 13, and the incident classified as external input manipulation
---
 
## Kill Chain Correlation
 
> **How to read this report:** the hunt is broken into six main phases, one per hunt section, and each of the 17 flags falls inside exactly one. The table below is a map of those phases: the hunt section, the kill chain stage it corresponds to, and the flags it covers.
 
| Phase | Hunt Section | Kill Chain | Flags |
| --- | --- | --- | --- |
| 1 | Delivery | Delivery | 1 to 3 |
| 2 | Copilot Hijack | Exploitation | 4 to 6 |
| 3 | Data Extraction | Actions on Objectives | 7 to 9 |
| 4 | Blast Radius | Actions on Objectives | 10 to 12 |
| 5 | Normal or Anomalous | Exploitation to Actions on Objectives | 13 to 14 |
| 6 | Impact and Classification | Actions on Objectives | 15 to 17 |
 
- **Not observed in the telemetry:** Reconnaissance, Installation and a separate command-and-control channel. There was no malware, persistence or beaconing process, and the response-rendering channel does both the C2 and exfiltration jobs.
- **Phases 5 and 6** are analyst steps, not attacker steps. They are placed on the chain because they decide whether stages 2 to 4 were malicious and how far they reached.
---
 
## Phase 1: Delivery (Flags 1 to 3) 🚩
 
**MITRE ATT&CK:** Initial Access (T1566.001)
 
### Evidence
 
```
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T09:30:00Z))
| where Operation == "MessageReceived"
| where SenderAddress !endswith "@cormorantcapital.com"
| project TimeGenerated, UserId, SenderAddress, Subject, AttachmentNames
| order by TimeGenerated asc
```
 
```
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SenderAddress has "globalfinancereview" or AttachmentNames has "Global-Markets-Review"
| project TimeGenerated, UserId, Operation, SenderAddress, Subject, AttachmentNames
```
 
### Finding
 
- **Flag 1, sender:** `quarterly.reports@globalfinancereview.net`
- **Flag 2, poisoned document:** `Q3-2026-Global-Markets-Review.docx`, subject "Q3 2026 Global Markets Review - For Your Analysis", delivered 09:15:22 UTC
- **Flag 3, time gap:** about 87 minutes between delivery (09:15:22) and the Copilot prompt (10:42:35); the document itself was opened at 10:42:08
- The other eight external messages went to other staff from known brands with mismatched subjects and attachments: background noise
- The sender and attachment search returned only Emily's message, so she was the sole recipient in this dataset
- Nothing happens in the gap: no macro, beacon, process or sign-in anomaly
- Delayed, victim-triggered attack: the attacker controls the content, not the timing, and it is not strictly zero-click because Emily must open the file and invoke Copilot
- Time-correlation detections ("attachment opened, then something suspicious within N minutes") cannot catch this
---
 
## Phase 2: Copilot Hijack (Flags 4 to 6) 🚩
 
**MITRE ATT&CK:** Execution (T1204.002); ATLAS AML.T0051
 
### Evidence
 
```
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated > datetime(2026-09-20T10:42:35Z)
| where InteractionType in ("ToolCall", "Search")
| project TimeGenerated, InteractionType, ToolName, ToolParameters
| order by TimeGenerated asc
```
 
### Finding
 
- **Flag 4, user prompt:** "Summarise the key findings of this quarterly report" (session `cp-emily-20261007-1042`, 10:42:35)
- **Flag 5, anomalous tool calls:** 21 calls, 8 `Graph.SearchFiles` and 13 `Graph.ReadFile`, all against `cormorantcapital.sharepoint.com`; none touched the document she asked about
- **Flag 6, ATLAS technique:** `AML.T0051` (LLM Prompt Injection); the indirect variant `.001` is our assessment from behaviour, since the injected text was never inspected
- The first search came 6 seconds after the prompt and the instructions were obeyed with no further user input
- The five wave 2 searches are logged as `Search`, not `ToolCall`, so filtering on `ToolCall` alone returns 16 calls instead of 21
- Each of the 13 reads matches a `FileAccessed` event under Emily's identity in the Office log, 0 to 5 seconds apart
---
 
## Phase 3: Data Extraction (Flags 7 to 9) 🚩
 
**MITRE ATT&CK:** Collection (T1213.002); ATLAS AML.T0077
 
### Evidence
 
```
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:43:15Z))
| where OfficeObjectId !has "Q3-2026"
| summarize dcount(OfficeObjectId)
```
 
```
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where TimeGenerated between (datetime(2026-09-20T10:42:30Z) .. datetime(2026-09-20T10:44:00Z))
| where CopilotResponse has "metrics-cdn" or CopilotResponse has "analyticshub"
| project TimeGenerated, CopilotResponse
```
 
### Finding
 
- **Flag 7, first-burst file count:** 5 files (10:42:47 to 10:42:55, an 8-second span): Board Meeting Minutes, Project Falcon M&A assessment, Salary Review FY2027, Henderson Family Office portfolio and the Copilot System Configuration file
- **Flag 8, exfiltration domain:** `metrics-cdn.analyticshub.io`, in `CopilotAudit_CL`, field `CopilotResponse`
- **Flag 9, mechanism:** Copilot wrote markdown image URLs into its response with the stolen data base64-encoded in the query string (`metrics-cdn.analyticshub.io/img?d=...`), and the trusted Microsoft 365 client fetches them automatically when rendering, so endpoint tools see only an allowed app loading an image and no malicious process or file transfer
- The first response (10:43:08) hides four beacons labelled "Chart 1 to 4" under a plausible three-point market summary
- The window above returns that first response; ending it at 10:47:00 returns all three
- The `d=` values were decoded offline in Python (the in-KQL decode did not run):
| Beacon | Response (UTC) | Decoded |
| --- | --- | --- |
| 1 to 4 | 10:43:08 | Board minutes, Project Falcon, Salary Review, Henderson portfolio |
| config | 10:44:19 | system_prompt_cormorant_capital |
| sl1 to sl8 | 10:46:35 | The eight wave 2 files |
 
---
 
## Phase 4: Blast Radius (Flags 10 to 12) 🚩
 
**MITRE ATT&CK:** Exfiltration (T1567); ATLAS AML.T0057
 
### Evidence
 
```
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:47:00Z))
| where OfficeObjectId !has "Q3-2026"
| summarize Accesses = count(), FirstAccess = min(TimeGenerated) by OfficeObjectId
| order by FirstAccess asc
```
 
### Finding
 
- **Flag 10, accessed files:** 13 distinct files, listed by site:
| Site | Files |
| --- | --- |
| Executive (4) | Board Meeting Minutes, Board Committee Minutes (Audit Committee), Project Falcon M&A assessment, Quarterly Revenue Report (Restricted) |
| Finance (5) | Henderson Family Office portfolio, Compliance Audit Results, Restricted Client List, Board Resolution (Emergency Session), Acquisition Pipeline Q4 2026 |
| HR (3) | Salary Review FY2027, Executive Salary Benchmarking 2027, Confidential Investigation (Insider Trading) |
| IT (1) | Copilot System Configuration |
 
- The config file shows 2 accesses (10:42:55 and 10:44:15), so there are 14 access events but 13 distinct files; the second read appears only in the Office log
- **Flag 11, content visibility:** No. The logs hold access metadata and Copilot's response text, not the content of the files read, and no table shows the outbound request, so the exact data that left cannot be determined
- **Flag 12, system prompt exposure:** the 10:44:19 response printed Copilot's system prompt and enterprise configuration (sensitivity label taxonomy, classification policy, DLP policy `block-external-sharing-confidential`, permitted data sources, `Global Reader` scope, org structure). It gives an attacker a map of the firm's defences and Copilot's reach, so follow-on injections can be tailored to the DLP rules, the labels and the system prompt's wording, aimed at the highest-value sites, and reused against any user in the tenant
- The DLP policy governs sharing, not what a response renders, which is why the image channel was not blocked
- The decoded beacons are file names and one marker, not file contents
---
 
## Phase 5: Normal or Anomalous - Judgement (Flags 13 and 14) 🚩
 
**MITRE ATT&CK:** None (analyst phase, compares the session against baseline)
 
### Evidence
 
```
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where InteractionType == "ToolCall"
| summarize ToolCallCount = count() by UserId
```
 
```
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:44:00Z))
| where InteractionType == "ToolCall"
| project TimeGenerated, ToolName, ToolParameters
```
 
### Finding
 
- **Flag 13, manager's claim:** it does not hold; Copilot was hijacked. Normal sessions (`cp-emily-norm-###`) are a prompt and a response on one named Finance/Shared Documents file with zero `Graph.SearchFiles` or `Graph.ReadFile` calls. The anomalous session made 21 tool calls six seconds after a one-document summary request, searched the whole tenant for "confidential", "restricted", "board" and "salary", and read 13 Executive, HR, Finance and IT files
- **Flag 14, three differences:** Tool calls (21 vs none), first-time file access (13 never-opened files), machine-speed timing (searches 6 seconds after prompt)
- The first query returned one user, Emily, with 16 `ToolCall` rows (the other 5 calls are logged as `Search`); the second returned the 8 wave 1 calls
- Both queries returned nothing until an explicit `TimeGenerated` window was added
| Axis | Baseline | Hijacked session |
| --- | --- | --- |
| Tool calls | None | 21 |
| Files | Finance/Shared Documents only | Executive, HR, Finance, IT |
| Timing | Prompt and response together | Search 6 seconds after prompt, wave 2 with no new prompt |
| Response content | Plain text | 13 external image URLs and a printed configuration |
 
- No single axis is conclusive on its own; the combination is the detection pattern
- "Never opened before" is checked only inside the 09:00 to 11:00 dataset and Emily's pasted baseline sessions
---
 
## Phase 6: Impact and Classification - Incident Response (Flags 15 to 17) 🚩
 
**MITRE ATT&CK:** Discovery (T1083)
 
### Evidence
 
```
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Search"
| where TimeGenerated > datetime(2026-09-20T10:44:00Z)
| project TimeGenerated, ToolParameters
```
 
```
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:47:00Z))
| where OfficeObjectId !has "Q3-2026"
| summarize dcount(OfficeObjectId)
```
 
```
EntraSignIn_CL
| where RunId == "el--17-20260920"
| where UserPrincipalName =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T08:00:00Z) .. datetime(2026-09-20T12:00:00Z))
| project TimeGenerated, IPAddress, Location, Status, ConditionalAccessStatus, AppDisplayName
```
 
### Finding
 
- **Flag 15, SearchLeak scope:** 8 additional files, driven by the keywords confidential, restricted, board, acquisition and salary (five searches at 10:45:30 to 10:45:45, then reads to 10:46:26, with no new prompt)
- The "confidential" and "restricted" terms reuse label names from the configuration leaked at 10:44:19
- **Flag 16, total file count:** 13 (5 from the first extraction plus 8 from the search phase), counted once per distinct file
- **Flag 17, classification:** external input manipulation (indirect prompt injection via the email attachment)
- **Not a compromised account:** two sign-ins, both successful from 203.0.113.45 (London), Azure Portal 10:15:31 and Outlook Mobile 10:29:45, conditional access passing; the prompt was Emily's own and benign, and the attacker never appears as an identity
- **Not a compromised configuration:** the file was only read, and baseline sessions before and after behaved normally under the same configuration
- **Visibility gap:** the audit tables hold access metadata and response text, not file content or the outbound request
---
 
## Key Lessons Learned
 
### 1. Always set an explicit time window
 
- The same query returned nothing without a `TimeGenerated` filter and the expected rows with one
- Portal time was UTC-7, so answers and windows must be converted to UTC
### 2. Check every interaction type
 
- Wave 2 searches are logged as `Search`; filtering on `ToolCall` alone returns 16 calls instead of 21
### 3. Detect on behaviour, not delivery
 
- Nothing in email delivery, sign-in or endpoint telemetry looked malicious
- The signal is the mismatch between what the prompt asked for and what Copilot did: tool calls where the baseline has none, files outside the user's pattern, external image URLs in responses
---
 
## MITRE ATT&CK and ATLAS Mapping
 
| Phase | Tactic | Technique |
| --- | --- | --- |
| 1 | Initial Access | T1566.001 Phishing: Spearphishing Attachment |
| 2 | Execution | T1204.002 User Execution: Malicious File |
| 2 | AI Execution | AML.T0051 LLM Prompt Injection (indirect variant AML.T0051.001 assessed) |
| 3 | Collection | T1213.002 Data from Information Repositories: SharePoint (analyst mapping) |
| 3 | AI Exfiltration | AML.T0077 LLM Response Rendering (analyst mapping) |
| 4 | Exfiltration | T1567 Exfiltration Over Web Service (analyst mapping) |
| 4 | AI Data Leakage | AML.T0057 LLM Data Leakage (analyst mapping) |
| 6 | Discovery | T1083 File and Directory Discovery, via Graph search (analyst mapping) |
 
The Phase 1 and 2 techniques were used during the hunt; the rows marked analyst mapping were added afterwards and were not graded.
 
---
 
## Final Assessment
 
- **Impact:** High (analyst assessment). Copilot read 13 sensitive files and its own configuration under a legitimate identity
- **Confirmed:** Copilot wrote 13 beacon URLs to `metrics-cdn.analyticshub.io` carrying encoded file names
- **Not confirmed:** that Emily's client fetched the URLs, that any file content left the tenant, or what the injected text said (the payload was never inspected)
- **Scope limits:** "never opened before" is checked only inside the 09:00 to 11:00 dataset; only Emily received the email in this dataset
- **Recommended actions:** search all mailboxes for the sender domain and attachment, block `analyticshub.io` and review proxy and DNS logs, treat the 13 files and the configuration as exposed, restrict external image rendering in Copilot output, narrow Copilot's access scope, and log retrieved-resource metadata for tool calls
---
 
## Analyst Reflection
 
> Every log line in this incident looked legitimate in isolation: a real user, a real session, Copilot using its own permissions. The attack only shows up when the user's request is compared with what the assistant did next. Detection for AI assistants has to start from that comparison, with a per-user baseline and an alert on any session whose actions go beyond its prompt.
