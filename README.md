# SOC L2 investigation lab: web server compromise (Splunk BOTS v1)

An L2-style investigation of the **imreallynotbatman.com** web server compromise in Splunk's public [Boss of the SOC v1](https://github.com/splunk/botsv1) dataset. It's treated as a real escalation, from the L1 ticket through to a report, detections and a playbook.

**Scope:** the web-defacement scenario only. The dataset's Cerber ransomware scenario is out of scope.

## What happened (findings summary)

On 2016-08-10, between 21:36 and 22:22 UTC, an external attacker:

1. **Scanned** the site with **Acunetix** from 40.80.148.42.
2. **Brute-forced** the Joomla administrator login from 23.22.63.114: 412 dictionary passwords in about 90 seconds, which found `admin` / `batman`.
3. **Logged in** as admin and uploaded a **PHP web shell** (`agent.php`) and a **reverse-shell executable** (`3791.exe`, W32/Swrort, 65/70 on VirusTotal) through a file-manager extension.
4. **Ran commands** through the web shell, started the reverse shell back to 23.22.63.114:3791, and downloaded `poisonivy-is-coming-for-you-batman.jpeg` from prankglassinebracket[.]jumpingcrab[.]com:1337.
5. **Defaced the site** with `move 2.jpeg imnotbatman.jpg`.

**Root cause:** an internet-exposed CMS admin panel with a dictionary password and no lockout or MFA.

**Contributing factors:**
- The firewall's antivirus and web filter **detected** the malware and the malicious download but were in **monitor mode**.
- There was no alerting on admin brute force or on the web server spawning shells.

**Severity:** P1 (raised from L1's P2).

Full details: [incident report](report/incident-report.md) · [timeline](investigation/timeline.md) · [IOCs](investigation/iocs.csv) · [ATT&CK mapping](investigation/attack-mapping.md) · [all 29 queries](investigation/queries.md)

## Detections

Written in Sigma, converted with `sigma-cli` through a custom field-mapping pipeline, and tested against the dataset.

| Rule | ATT&CK | Result on BOTS v1 |
|---|---|---|
| [Acunetix scanner payload marker](detections/sigma/web_acunetix_scanner_marker.yml) | T1595.002 | Fired: 277 events, one source |
| [Joomla admin brute force](detections/sigma/web_joomla_admin_bruteforce.yml) (Sigma correlation, 20 or more per 5 minutes) | T1110.001 | Fired: 412 attempts from 23.22.63.114; the attacker's single successful login correctly excluded |
| [Web server process spawns a command shell](detections/sigma/win_webserver_spawns_shell.yml) | T1505.003, T1059.003 | Fired (adapted): 17 web-shell commands; would have alerted 25 minutes before the defacement |

Test evidence, false positives and tuning notes: [`detections/test-results.md`](detections/test-results.md).

## Repository layout

```
README.md
ticket/L1-escalation.md            simulated L1 ticket that starts the case
investigation/queries.md           every SPL query, with what it found and who wrote it
investigation/timeline.md          UTC-normalized timeline and evidence gaps
investigation/iocs.csv             machine-readable IOC list
investigation/attack-mapping.md    MITRE ATT&CK mapping and control gaps
intel/enrich_iocs.py               VirusTotal + AbuseIPDB enrichment (rate-limited, keys from env vars)
intel/enrichment-results.md        enrichment output (defanged)
detections/sigma/*.yml             Sigma rules
detections/pipelines/bots-v1.yml   pySigma pipeline mapping Sigma fields to this dataset
detections/spl/*.spl               converted (and one adapted) Splunk searches
detections/test-results.md         proof each rule fires, plus tuning
report/incident-report.md          incident report and Shift Lead escalation note
playbooks/web-server-compromise.md reusable playbook with escalation criteria and SLA targets
```

## Tools

| Tool | Version |
|---|---|
| Splunk Enterprise (Windows, trial) | 10.6.1.1 |
| Dataset | BOTS v1 attack-only, pre-indexed |
| Splunk add-ons | FortiGate, Microsoft Windows, Microsoft Sysmon (archived), Stream Wire Data, URL Toolbox |
| Python | 3.12, with `requests` |
| Detection tooling | `sigma-cli` + `pysigma-backend-splunk` |
| Threat intel | VirusTotal API v3 and AbuseIPDB API v2, free tiers |

## How to reproduce

1. **Install Splunk Enterprise** (the free trial is fine).
2. **Download the attack-only dataset** listed in the BOTS v1 README: `botsv1-attack-only.tgz`, about 135 MB. SHA-256 recorded on 2026-10-19: `A52EC0F10CBD9096CF886A13C1B67ABF28756528AEB1689C5B50FF27ADFA45E3`.
3. **Inspect the archive before installing it.** It contains a Splunk app with pre-indexed buckets, and no scripts or inputs.
4. **Extract the dataset and the add-ons** into `$SPLUNK_HOME\etc\apps`, then restart Splunk once.
5. **Check the data loaded:**
   ```
   index=botsv1 earliest=0 | stats count by sourcetype
   ```
   You should see 22 sourcetypes before add-ons, and 20 after.
6. **Run the queries** in [`investigation/queries.md`](investigation/queries.md) with the time picker on **All time**.
7. **Enrichment:**
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r intel\requirements.txt
   $env:VT_API_KEY = Read-Host "VirusTotal key"
   $env:ABUSEIPDB_API_KEY = Read-Host "AbuseIPDB key"
   python intel\enrich_iocs.py
   ```
8. **Detections:**
   ```powershell
   pip install sigma-cli pysigma-backend-splunk
   sigma convert -t splunk -p detections\pipelines\bots-v1.yml detections\sigma\<rule>.yml
   ```

### Gotchas that cost time (and are worth knowing)

- **Retention.** The dataset's `indexes.conf` sets `frozenTimePeriodInSecs` to about 12 years. With Splunk's default of about 6 years, the 2016 data would be frozen (deleted) on first start.
- **Add-ons rename sourcetypes at search time.**
  - `WinEventLog:Security/Application/System` become `WinEventLog`; use `source` to tell them apart.
  - `fgt_*` becomes `fortigate_*`.
  - Sysmon becomes `xmlwineventlog`, with source `WinEventLog:Microsoft-Windows-Sysmon/Operational`.
- **The archived Sysmon add-on didn't extract fields** on Splunk 10.6 for the renamed sourcetype. The Sysmon queries parse the XML with `rex` instead.
- **Very large events aren't fully auto-extracted.** The 77 KB file-upload event was missed by field-based searches and found by a raw keyword search.
- **Four clocks.**
  - Splunk displayed UTC−4.
  - FortiGate and Suricata logged UTC−6.
  - The web server's clock was UTC−7.
  - Stream logged in UTC.
  - Everything in this repo is converted to UTC.
- **The time picker defaults to "Last 24 hours".** Use All time or `earliest=0`.

## Safety and data handling

- **No malware was downloaded, opened or run.** File indicators come from Sysmon and firewall logs; reputation comes from existing VirusTotal reports, using lookups only, with nothing submitted.
- **No Splunk data, exports or API keys are committed.** See `.gitignore`. Keys are read from environment variables only.
- **Indicators are defanged in prose** (`[.]`, `hxxp`). `iocs.csv` keeps raw values so tools can ingest it.
- **Enrichment reflects 2026 reputation, not 2016.** Both attacker IPs are now ordinary cloud addresses.

## How this was built

I set up the lab and Splunk, inspected and loaded the dataset, ran every search and exported the results, ran the enrichment with my own API keys, and converted and tested the detections.

An AI assistant (Claude) acted as coach and pair analyst:
- It wrote most of the SPL. The first few queries came after hints; I then asked it to supply the rest so I could finish in one evening.
- It interpreted the results with me.
- It drafted the write-ups, the enrichment script, the Sigma rules and the pipeline from my results.

[`investigation/queries.md`](investigation/queries.md) labels who wrote each query. All findings come from queries run against the dataset, not from published BOTS write-ups.

## Credits

Dataset: [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1), by Ryan Kovar, David Herrald and James Brodsky (CC0).
