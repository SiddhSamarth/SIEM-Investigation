# Cloud SIEM Incident Investigation: Solorigate Supply-Chain Backdoor Triage

An incident triage walkthrough using Microsoft Sentinel (Azure Sentinel), the Advanced Security Information Model (ASIM), and Kusto Query Language (KQL) to investigate a simulated Solorigate (SUNBURST) supply-chain backdoor beacon.

---

## Scope & Lab Environment

* **Lab Scenario:** Solorigate supply-chain backdoor triage and endpoint hunting.
* **Platform:** Microsoft Sentinel on Azure Log Analytics.
* **Data Sources:** Cisco Umbrella DNS normalized through ASIM (`_Im_Dns`), Windows endpoint events (`DeviceFileEvents`).

---

## Investigation Workflow & Key Steps

```
[ Ingested Alert: Solorigate Network Beacon ]
                     │
                     ▼
[ ASIM Normalization: Cisco Umbrella DNS ]
                     │
                     ▼
[ Log Analytics Drill-Down: avsvmcloud.com ]
                     │
                     ▼
[ KQL Proactive Threat Hunting: Endpoint DLLs ]
                     │
                     ▼
[ Entity Expansion: AdminPc, ClientPc, VictimPc ]
                     │
                     ▼
[ CTI Enrichment: IOC Ingestion (17.81.146.1) ]
                     │
                     ▼
[ Incident Documentation & Forensic Handover ]
```

---

## Detailed Investigation Steps & Telemetry

### 1. Incident Assignment & Initial Scoping
Navigate to Microsoft Sentinel → **Incidents** and locate the high-severity alert titled **"Solorigate Network Beacon"**. Assign the incident to the investigating analyst.

<p align="center">
  <img src="./images/1_1.png" alt="Solorigate Incident Selection" width="750" />
</p>

<p align="center">
  <img src="./images/2_2.png" alt="Assigning Incident" width="750" />
</p>

### 2. Triage & Domain IOC Verification
Inspect the incident summary. The alert indicates that internal host `ClientPC` performed outbound DNS resolution to the confirmed Solorigate C2 domain `avsvmcloud.com`.

<p align="center">
  <img src="./images/3_3.png" alt="Incident Description" width="750" />
</p>

<p align="center">
  <img src="./images/step_4.png" alt="Incident Entity View" width="750" />
</p>

### 3. Log Analytics Drill-Down via ASIM
Click on **Link to Log Analytics** to inspect the underlying raw event. Sentinel normalizes telemetry from Cisco Umbrella DNS using the **Advanced Security Information Model (ASIM)** DNS parser (`_Im_Dns`).

<p align="center">
  <img src="./images/4_5.png" alt="Link to Log Analytics" width="750" />
</p>

<p align="center">
  <img src="./images/Screenshot_2024-03-08_234033_6.png" alt="Raw Event Query" width="750" />
</p>

<p align="center">
  <img src="./images/Screenshot_2024-03-08_234130_7.png" alt="ASIM Normalization Details" width="750" />
</p>

#### Extracted KQL Detection Query (ASIM Normalized DNS):
```kql
// Advanced Security Information Model (ASIM) DNS Inspection
_Im_Dns(domain_has_any=dynamic(['avsvmcloud.com']))
| extend DNS_Query = DnsQuery
| project TimeGenerated, SrcIpAddr, DnsQuery, EventVendor, EventProduct
```

---

### 4. Proactive Threat Hunting for Compromised Endpoints
To determine if other hosts on the domain are infected with the malicious backdoor binary, navigate to **Sentinel → Hunting** and execute the **Solorigate Inventory check** hunting query.

<p align="center">
  <img src="./images/5_8.png" alt="Hunting Blade" width="750" />
</p>

<p align="center">
  <img src="./images/6_9.png" alt="Solorigate Queries" width="750" />
</p>

<p align="center">
  <img src="./images/7_10.png" alt="Hunting Query Results" width="750" />
</p>

#### Extracted KQL Hunting Query (Backdoor DLL & WebShell Hunt):
```kql
// Hunting across DeviceFileEvents for Sunburst DLL artifacts
DeviceFileEvents
| where FileName in~ (
    'SolarWinds.Orion.Core.BusinessLayer.dll', 
    'app_web_logoimagehandler.ashx.b6031896.dll'
)
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```

Three compromised hosts are identified:
* `AdminPc.Contoso.Azure`
* `ClientPc.Contoso.Azure`
* `VictimPc.Contoso.Azure`

### 5. Forensic Bookmarking & Incident Entity Expansion
Bookmark the three compromised endpoint records and attach them directly to the active Solorigate incident. This expands the incident graph to show all impacted host entities simultaneously.

<p align="center">
  <img src="./images/8_11.png" alt="Bookmarking Records" width="750" />
</p>

<p align="center">
  <img src="./images/Screenshot_2024-03-08_235534_12.png" alt="Bookmark Entity Mapping" width="750" />
</p>

<p align="center">
  <img src="./images/9_13.png" alt="Bookmarks Tab" width="750" />
</p>

<p align="center">
  <img src="./images/10_14.png" alt="Adding Bookmarks to Incident" width="750" />
</p>

<p align="center">
  <img src="./images/Screenshot_2024-03-09_000107_15.png" alt="Attaching Bookmarks" width="750" />
</p>

<p align="center">
  <img src="./images/Screenshot_2024-03-09_000506_16.png" alt="Updated Incident Entity Graph" width="750" />
</p>

---

### 6. Threat Intelligence Store Ingestion
Extract the external attack IP address (`17.81.146.1`) associated with the C2 traffic. Navigate to **Microsoft Sentinel → Threat Intelligence** and add a new Indicator of Compromise (IOC) record. This enables real-time automated alerting across all enterprise firewall, proxy, and DNS log feeds should any host attempt future connections.

<p align="center">
  <img src="./images/11_17.png" alt="Threat Intelligence Blade" width="750" />
</p>

<p align="center">
  <img src="./images/incident12_18.png" alt="Adding IOC to Sentinel" width="750" />
</p>

---

### 7. Documentation & Incident Handover
Document the full investigative findings in the incident **Comments** tab to ensure seamless handover to Tier 3 CIRT (Computer Incident Response Team) and Forensics teams.

<p align="center">
  <img src="./images/incident13_19.png" alt="Incident Comments Tab" width="750" />
</p>

<p align="center">
  <img src="./images/incident14_20.png" alt="Analyst Handover Notes" width="750" />
</p>

---

## Technical Summary of Findings

* **Primary Indicator of Compromise (IOC):** `avsvmcloud.com` (Solorigate DGA C2 domain).
* **Attacker Infrastructure IP:** `17.81.146.1` (ingested into Sentinel Threat Intelligence store).
* **Telemetry Telemetry Source:** Cisco Umbrella DNS parsed via ASIM (`_Im_Dns`).
* **Timestamp of First Beacon:** `2019-09-12T20:00:00.625Z`.
* **Identified Infected Hosts:**
  1. `AdminPc.Contoso.Azure`
  2. `ClientPc.Contoso.Azure`
  3. `VictimPc.Contoso.Azure`
* **Containment Action:** All 3 hosts bookmarked and slated for EDR network isolation; malicious C2 IP and domain blacklisted enterprise-wide.

---

## Attribution & Acknowledgments


---

## Author & Links

* **Author:** Siddh Samarth
* **GitHub:** [@SiddhSamarth](https://github.com/SiddhSamarth)
* **Portfolio:** [siddhsamarth.in](https://siddhsamarth.in)
* **LinkedIn:** [samarthsiddh](https://www.linkedin.com/in/siddhsamarth/)
