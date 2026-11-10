---
layout: default
title: Evidence register
permalink: /evidence-register.html
---

# Evidence register

This register maps the original screenshots to their publication filenames and the narrow conclusion each supports. The 17 selected original screenshots are copied without destructive cropping; click an image in the case study to open the full-resolution file. Figure 1 is a newly rendered logical topology, not a screenshot.

| Original source filename | Published filename | Case-study placement | Evidence interpretation |
|---|---|---|---|
| `word-launching-powershell.png` | [`01-document-to-powershell-ancestry.png`](assets/evidence/01-document-to-powershell-ancestry.png) | §1 / Figure 2 | Security 4688 process rows show LibreOffice parentage and PowerShell/`whoami` child execution. |
| `LO-UPLOAD-20261108-210304 — Process Execution (4688).png` | [`05-macro-upload-process-4688.png`](assets/evidence/05-macro-upload-process-4688.png) | §1, §5 / Figure 3 | Expanded Security 4688 command and parent for the macro upload run; not receiver completion evidence. |
| `ENUMERATION.png` | [`02-domain-discovery-process-tree.png`](assets/evidence/02-domain-discovery-process-tree.png) | §2 / Figure 4 | `CORP\belisarius` discovery utilities; `net1.exe` is part of the `net.exe` utility chain. |
| `upload-log-1.png` | [`03-powershell-outbound-connections.png`](assets/evidence/03-powershell-outbound-connections.png) | §3 / Figure 5 | Several WFP 5156 connections to Kali TCP 8080 across distinct PowerShell executions. WFP contains no URI or request ID. |
| `Suricata — Kali Traffic Overview.png` | [`03-suricata-checkin-overview.png`](assets/evidence/03-suricata-checkin-overview.png) | §3 / Figure 6 | Broad HTTP/flow overview, not isolated proof of the Nov. 9 persistence callback. |
| `Alert, HTTP and Flow Correlation.png` | [`05-manual-upload-flow-correlation.png`](assets/evidence/05-manual-upload-flow-correlation.png) | §5 / Figure 7 | Alert, HTTP, and flow records describe one manual upload connection, not three uploads. |
| `Evidence — Manual Upload — HTTP Transaction — 20261108-200228.png` | [`05-manual-upload-http-200.png`](assets/evidence/05-manual-upload-http-200.png) | §5 / Figure 8 | Suricata shows manual `POST /upload`, HTTP 200 at Nov. 8 20:02:29 local (UTC+03:00); receiver receipt is separate byte/hash evidence. |
| `LO-UPLOAD-20261108-210304 — Permitted Connection (5156).png` | [`05-macro-upload-wfp-5156.png`](assets/evidence/05-macro-upload-wfp-5156.png) | §5 / Figure 9 | WFP 5156 PowerShell connection `172.30.0.2:60560` → `10.200.78.20:8080`; connection tuple only. |
| `LO-UPLOAD-20261108-210304 — Suricata PowerShell Alert and Upload Evidence.png` | [`05-macro-upload-suricata-http.png`](assets/evidence/05-macro-upload-suricata-http.png) | §5 / Figure 10 | Suricata PowerShell user-agent alert, `POST /upload`, and HTTP 200; the signature is a pivot, not an exfiltration verdict. |
| `Sysmon — Run-Key Value Write — Admin Proof — 20261109-145423.png` | [`06-earlier-user-runkey-write-162443.png`](assets/evidence/06-earlier-user-runkey-write-162443.png) | §6 / Figure 11 | Visible row is an earlier domain-user Run-key write at 16:24:43 local; saved-view title is stale. |
| `Persistence — HKCU Run Installation — LabPersistenceCheckIn.png` | [`06-user-runkey-write-164141.png`](assets/evidence/06-user-runkey-write-164141.png) | §6 / Figure 12 | Sysmon Event 13 shows `CORP\belisarius` setting `LabPersistenceCheckIn` under the user's Run key at 16:41:41 local. |
| `Persistence — PowerShell Logon Callback — WFP 5156 — 20261109-165432.png` | [`06-logon-callback-wfp-5156.png`](assets/evidence/06-logon-callback-wfp-5156.png) | §6 / Figure 13 | WFP 5156 records PowerShell `172.30.0.2:62172` → `10.200.78.20:8080` at 16:54:32 local. Marker/request ID is not in WFP. |
| `Persistence — Logon Callback — Suricata — 20261109-165432.png` | [`06-suricata-callback-overview.png`](assets/evidence/06-suricata-callback-overview.png) | §6 / Figure 14 | Broad Suricata callback view; visible Nov. 8 rows do not independently establish the Nov. 9 callback. |
| `Defense Evasion — Disable Windows Firewall (T1686).png` | [`08-firewall-disable-restore-processes.png`](assets/evidence/08-firewall-disable-restore-processes.png) | §8 / Figure 15 | Netsh off/on process starts 12.171 seconds apart; not a measurement of disabled-state duration, and process creation alone does not prove command success. |
| `Credential Access — NPPSpy Artifact Verification (Sysmon EID 1).png` | [`09-nppspy-artifact-inspection.png`](assets/evidence/09-nppspy-artifact-inspection.png) | §9 / Figure 16 | PowerShell `Test-Path` and Notepad reference NPPSpy artifacts. This proves inspection, not credential extraction/capture; saved-view title is stale. |
| `Registry-modification-0.png` | [`10-sysmon-registry-ingestion-proof.png`](assets/evidence/10-sysmon-registry-ingestion-proof.png) | Telemetry engineering / Figure 17 | Local `windows` administrator's `LabRegistryProof` Event 13 arrived in Kibana; instrumentation proof, not domain-user persistence. |
| `ELK-raw-screenshot.png` | [`10-winlogbeat-ingestion-overview.png`](assets/evidence/10-winlogbeat-ingestion-overview.png) | Telemetry engineering / Figure 18 | 327,408 Winlogbeat documents in a selected historical range; not an attack or alert count. |

## Explicit exclusions

| Original source filename | Decision | Reason |
|---|---|---|
| `attack-chain.png` | Excluded; retained only in source archive | Outdated diagram mislabels LibreOffice as Word and nests Samba inside the workstation. Replaced by corrected logical topology. |
| `topology-mermaid-diagram.png` | Excluded; retained only in source archive | Superseded by the checked-in Mermaid source and rendered SVG. |
| `kali-setup-fresh.png` | Excluded from main narrative | Generic Kali root-directory listing does not establish a lab behavior or detection result. |
| `creds` | Excluded and not inspected or copied | Not an image and may contain sensitive material. |

## Caption and time conventions

The Kibana screenshots use local time consistent with UTC+03:00. Receiver JSON uses UTC. Captions label local timestamps where relevant. Saved Discover titles/time windows can be stale; interpretation follows the query, visible event fields, identity, and event time—not the saved title.

Screenshots supplement raw event records. They should not be treated as a complete export of the underlying event or as proof beyond the visible fields. [Return to the case study](index.html).
