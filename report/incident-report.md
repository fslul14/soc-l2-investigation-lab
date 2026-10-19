# Incident report: INC-0001, public website compromise and defacement

| | |
|---|---|
| Incident | INC-0001: imreallynotbatman.com defaced (escalated from L1) |
| Affected asset | Public Joomla website on IIS/PHP, host `we1149srv` (192.168.250.70) |
| Incident window | 2016-08-10 21:36:45 – 22:22:27 UTC |
| Reported | 2016-08-10 22:40 UTC (simulated, see ticket) |
| Severity | **P1 Critical** (raised from L1's P2; justification below) |
| Status | Investigation complete; containment, eradication and recovery recommended |
| Data source | Splunk Boss of the SOC v1 (attack-only), lab reconstruction |

Times are UTC. Indicators are defanged. Query numbers (Qn) refer to [`investigation/queries.md`](../investigation/queries.md).

---

## 1. Summary

An external attacker took over the company's public website in about 44 minutes:

1. They scanned it with **Acunetix**.
2. They guessed the Joomla administrator password with a **90-second dictionary attack** (`admin` / `batman`).
3. They used the admin panel to upload a **PHP web shell** (`agent.php`) and a **Metasploit-style reverse shell** (`3791.exe`).
4. They ran both on the server.
5. They replaced the site's `imnotbatman.jpg` with their own image.

The firewall's antivirus and web filter **detected both the malware upload and the malicious image download, but were set to monitor only**. The IDS raised no alert for the brute force.

The attacker had interactive command-line access to the web server, so the host should be treated as fully compromised.

## 2. Severity: P1 Critical

L1 assigned **P2** (public-facing system, compromise suspected). L2 raised it to **P1** because every P1 criterion was confirmed:

- **Confirmed compromise of a production system:** administrator takeover, code execution as the web server process, and an outbound reverse shell to the attacker (Q12, Q20, Q26).
- **Active business impact:** public website defacement, which is a reputational harm visible to customers (Q29, ticket).
- **Persistence present:** a web shell in the web root, and an unknown set of commands run through the reverse shell (Q21, Q20).
- **Exposure beyond the website is possible:** the attacker could read `configuration.php`, which holds the Joomla database credentials (eXtplorer listing in Q22b). Lateral movement wasn't investigated.

## 3. Timeline (key events)

The full timeline is in [`investigation/timeline.md`](../investigation/timeline.md).

| UTC | Event |
|---|---|
| 21:36:45 | Acunetix scan begins from 40.80.148.42 (about 20,900 requests). Suricata fires "ET SCAN Acunetix". |
| 21:45:21 – 21:46:51 | Brute force from 23.22.63.114: 412 passwords against `admin`. No IDS alert. |
| 21:48:05 | Login as `admin` / `batman` from 40.80.148.42 (a single attempt). |
| 21:50:31 – 21:51:32 | Extension installed via Joomla's installer; the eXtplorer file manager comes into use. |
| 21:52:45 | FortiGate antivirus flags `3791.exe` as W32/Swrort.C!tr, `action=monitored`. |
| 21:52:45 – 21:52:47 | `3791.exe` and `agent.php` uploaded to the web root through eXtplorer. |
| 21:55:22 | Web shell's first command (`echo 24365`) from 23.22.63.114. |
| 21:56:18 – 21:56:19 | Web shell runs `3791.exe`, which opens a reverse shell to 23.22.63.114:3791. |
| 22:06:21 – 22:19:11 | Server downloads `poisonivy-is-coming-for-you-batman.jpeg` from prankglassinebracket[.]jumpingcrab[.]com:1337. FortiGate: "Malicious Websites", allowed. |
| 22:20:10 – 22:20:33 | `move ..\1.jpeg 2.jpeg`, then `move 2.jpeg imnotbatman.jpg`. **Site defaced.** |
| 22:21:18 | Attacker views the site. |
| 22:21:34 | Web shell exits. |
| 22:40 | Employee reports the defacement to the help desk (simulated). |

## 4. Root cause

**Primary cause:** the Joomla administrator panel was reachable from the internet and protected by a dictionary-word password. There was no account lockout, rate limiting or MFA, so a 412-attempt guessing attack succeeded in 90 seconds.

**Contributing factors:**

1. **Admin access gave code execution.** Joomla admins can install extensions and upload files. PHP could write to, and execute from, the web root, and PHP was allowed to start `cmd.exe`.
2. **Preventive controls in monitor mode.** FortiGate antivirus identified the payload (`W32/Swrort.C!tr`, critical) and the web filter identified the image host as malicious. Both allowed the traffic.
3. **Detection gaps.**
   - There was no alert for repeated admin login failures.
   - There was no alert for a web server process launching a shell.
   - The Suricata scan alerts fired, but nothing reached a human before the defacement was reported.
4. **Visibility gaps in this lab.** The Sysmon add-on didn't extract fields on this Splunk version, which hid endpoint events from field-based searches until they were parsed with `rex`.

## 5. Indicators of compromise

The complete, machine-readable list is in [`investigation/iocs.csv`](../investigation/iocs.csv). Reputation lookups are in [`intel/enrichment-results.md`](../intel/enrichment-results.md).

| Type | Indicator | Role |
|---|---|---|
| IP | 40.80.148.42 | Acunetix scan, admin login, uploads (now an Azure IP; clean today) |
| IP | 23.22.63.114 | Brute force, web-shell control, reverse-shell C2 (tcp/3791), image host (tcp/1337) (now AWS; clean today) |
| Domain | prankglassinebracket[.]jumpingcrab[.]com | Defacement image host |
| URL | hxxp://prankglassinebracket[.]jumpingcrab[.]com:1337/poisonivy-is-coming-for-you-batman[.]jpeg | Defacement image |
| SHA256 | EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D | `3791.exe` (VirusTotal: 65/70 malicious, trojan.swrort, original name ab.exe) |
| MD5 | AAE3F5A29935E6ABCC2C2754D12A9AF0 | `3791.exe` |
| File | `C:\inetpub\wwwroot\joomla\agent.php` | PHP web shell |
| File | `C:\inetpub\wwwroot\joomla\3791.exe` | Reverse-shell payload |
| Behavior | `php-cgi.exe` → `cmd.exe /c "<command> 2>&1"` | Web-shell command pattern |
| String | `acunetix_wvs_security_test` | Scanner payload marker |
| Account | Joomla `admin` | Compromised credential |

**Note on IPs:** both attacker IPs belong to major cloud providers and show no current abuse. They are useful for searching historical logs, not for blocking today. The file hash is the most durable indicator.

## 6. MITRE ATT&CK

Details and evidence are in [`investigation/attack-mapping.md`](../investigation/attack-mapping.md).

| Tactic | Techniques |
|---|---|
| Reconnaissance | T1595.002 |
| Credential Access | T1110.001 |
| Initial Access | T1078 |
| Persistence | T1505.003 |
| Execution | T1059.003 |
| Command and Control | T1105, T1071.001, T1571 |
| Discovery | T1083, T1016 |
| Impact | T1491.002 |

## 7. Response actions

### Contain (within 1 hour of P1 declaration)

1. **Isolate we1149srv** at the network layer, allowing access only from the IR team, and put up a maintenance page in its place. Capture memory and a disk image **before** shutting anything down.
2. **Block outbound traffic from the web server** to the internet, except required update endpoints. The C2 and the image download were both outbound.
3. **Disable the Joomla `admin` account**, end all sessions, and restrict `/joomla/administrator/` to the VPN or an allow-list.
4. **Switch the FortiGate antivirus and web-filter profiles** on the web server policy from monitor to **block**.
5. Block 40.80.148.42, 23.22.63.114 and the domain as a short-term measure, knowing that cloud IPs change hands.

### Eradicate

1. **Rebuild the server from a known-good image.** The attacker had an interactive shell through `3791.exe`, and those commands weren't logged, so cleaning the existing server can't be trusted.
2. If a rebuild isn't possible right away:
   - Remove `agent.php`, `3791.exe` and the eXtplorer component.
   - Hunt for other web shells: any file in the web root created or modified after 2016-08-10 21:48 UTC.
   - Check for new local accounts, services and scheduled tasks.
3. **Rotate credentials:**
   - Joomla admin (with a strong, unique password plus MFA)
   - the Joomla database password in `configuration.php`
   - any service accounts on the host

### Recover

1. Restore the site from the last clean backup, from before 21:48 UTC, including the original `imnotbatman.jpg`, and confirm the page renders correctly.
2. Patch Joomla and its extensions.
3. **Harden PHP:**
   - Disable `exec`, `system`, `shell_exec` and `passthru` via `disable_functions`.
   - Make the web root read-only to the PHP process, except specific upload folders, and stop scripts from executing in upload folders.
4. **Deploy the three detections** in [`detections/`](../detections/test-results.md) and fix Sysmon field extraction.
5. Monitor closely for 30 days: any `php-cgi.exe`/`w3wp.exe` child process, admin logins from new IPs, and outbound connections from the web server.

### Follow-up hunts (open)

- Lateral movement from we1149srv to internal hosts, and database access using the exposed credentials.
- The same hash, imphash or user agents elsewhere in the environment.

## 8. SLA tracking (simulated ticket times)

| Metric | Value | Target | Met? |
|---|---|---|---|
| Time to detect: first malicious activity (21:36:45) to report (22:40) | 63 minutes | n/a (no alert reached a human) | No: detection depended on an employee report |
| Initial access (21:48:05) to report | 52 minutes | n/a | |
| Report to L1 triage (22:40 → 22:45) | 5 minutes | P2: 30 minutes | Yes |
| Report to L2 escalation (22:40 → 23:05) | 25 minutes | P2: 1 hour | Yes |
| Escalation to L2 acknowledgement (23:05 → 23:20) | 15 minutes | P2: 30 min / P1: 15 min | Yes (both) |

**The SLA gap that matters** is detection, not response. The Suricata Acunetix alerts at 21:36 and the FortiGate critical antivirus event at 21:52 should each have opened a ticket. They would have given 44 and 28 minutes' warning respectively before the defacement at 22:20:33.

## 9. Escalation note for Shift Lead / SOC Manager

> **INC-0001: P1, public website compromised and defaced (raised from P2).**
>
> **What:** An external actor guessed the Joomla admin password (`admin`, 90-second dictionary attack), uploaded a PHP web shell and a reverse-shell executable, ran commands on we1149srv, and replaced the site's main image. Activity ran 21:36–22:22 UTC on 2016-08-10.
>
> **Impact:** Confirmed code execution on a public production server; public defacement. The attacker could read the Joomla database credentials. Lateral movement is not yet assessed.
>
> **Why we missed it:** FortiGate detected both the malware upload and the malicious download but was in monitor mode. There was no alerting on admin brute force or on the web server spawning shells.
>
> **Decisions needed:**
> 1. Approve isolation and rebuild of we1149srv (the site stays on a maintenance page until it's restored).
> 2. Notify Communications/Legal about the public defacement.
> 3. Approve switching the FortiGate antivirus and web filter to block for the web DMZ.
>
> **Ready now:** IOC list, three tested detections (brute force, web-shell process, scanner marker), and an eradication checklist. Next update in 1 hour or on containment, whichever comes first.

## 10. Limitations

- This is a lab reconstruction from the BOTS v1 **attack-only** dataset, which has little benign traffic, so baselines and visitor impact can't be measured.
- The ticket, the reporter and the response timestamps are simulated.
- The commands typed inside the `3791.exe` reverse-shell sessions were not logged.
- The extension package installed at 21:50:31 is not visible in the logs.
