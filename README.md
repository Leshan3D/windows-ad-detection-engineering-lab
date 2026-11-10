# Windows & Active Directory Detection Engineering Lab

An evidence-led portfolio case study documenting hands-on detection engineering across a Windows 11 domain workstation, Samba Active Directory, Suricata, Winlogbeat/Sysmon, and a controlled HTTP receiver.

## Read the project

- **[Published technical case study](https://leshan3d.github.io/windows-ad-detection-engineering-lab/)**
- [Evidence register](docs/evidence-register.md)
- [Logical topology source (Mermaid)](docs/assets/topology/lab-topology.mmd)
- [Rendered topology fallback (SVG)](docs/assets/topology/lab-topology.svg)

## Demonstrated scope

LibreOffice ODT macro execution launched PowerShell; the exercises covered domain discovery, a planted-file collection and archive, controlled HTTP callbacks and uploads, user Run-key logon persistence, Windows firewall impairment and restoration, and credential-access investigation. Privilege escalation and lateral movement were **not** performed. The report distinguishes process creation, permitted network connections, HTTP transactions, receiver receipts, investigation queries, and proposed detections.

Screenshots are evidence aids, not a substitute for full event records. Captions describe the narrow conclusion each image supports. Kali operator logs and upload receipts remained on the operator and were not shipped to Elasticsearch.

## Repository layout

```text
docs/
├── index.md                     # Full case study and investigation queries
├── evidence-register.md         # Source-to-figure map and interpretation
└── assets/
    ├── evidence/                # 17 selected original Kibana screenshots
    └── topology/                # Mermaid source and rendered SVG
```

## Reproducibility and evidence boundaries

The case study documents the supplied lab records and exercise report. It does not claim production deployment, alert rates, false-positive rates, credential-capture success, privilege escalation, lateral movement, or full end-to-end automation. Queries are documented as hunting/investigation queries, not deployed detection rules. Some field mappings and query results depend on the captured index schema and time range.

## Author

Prince Leshan · [GitHub](https://github.com/Leshan3D) · [Portfolio](https://leshan3d.github.io/Leshan3d-github.io/)
