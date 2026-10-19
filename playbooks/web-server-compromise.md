# Playbook: suspected web server compromise

**Purpose:** a repeatable procedure for L1 and L2 analysts when a public-facing web server may be compromised: defacement, web shell, malicious upload, or code execution.

**Built from:** INC-0001 (BOTS v1 lab). Every step below maps to something that worked, or was missing, in that investigation.

**Owner:** SOC. **Review:** after every use, and at least every 6 months.

---

## 1. Triggers

Start this playbook when any of these occur:

| Trigger | Typical source |
|---|---|
| Report that the website looks wrong, defaced or unavailable | Help desk, employee, customer, social media |
| Web server process (`w3wp.exe`, `php-cgi.exe`, `httpd`) starts a shell or script host | EDR / Sysmon (detection: *Web Server Process Spawns a Command Shell*) |
| Brute force against a CMS or admin login | Web logs / SIEM (detection: *Joomla Administrator Brute Force*) |
| Vulnerability-scanner activity against the server | IDS, WAF (detection: *Acunetix Scanner Payload Marker*) |
| Antivirus detection on a file uploaded to, or written on, the web server | Firewall AV, EDR |
| Web server making outbound connections to rare destinations or non-standard ports | Firewall, proxy, Sysmon network events |

## 2. Severity and SLA targets

Use the highest row that matches. These are example targets; set your own in the SOC's service agreement.

| Priority | Criteria (any one) | Acknowledge | Triage complete | Escalate to Shift Lead | Containment started | Stakeholder updates |
|---|---|---|---|---|---|---|
| **P1 Critical** | Confirmed code execution or web shell; public defacement; confirmed data access; active attacker session | 15 min | 30 min | Immediately (≤ 15 min) | ≤ 1 h | Hourly |
| **P2 High** | Suspected compromise of a public-facing server (unexplained change, AV hit on the server, brute force followed by a successful login) | 30 min | 2 h | ≤ 1 h | ≤ 4 h | Every 4 h |
| **P3 Medium** | Scanning or failed brute force with no sign of success | 4 h | 1 business day | If it escalates | n/a | Daily |
| **P4 Low** | Informational (blocked scans, single failed logins) | 1 business day | As needed | n/a | n/a | As needed |

**Record these timestamps in the ticket** for SLA reporting: first malicious event, detected/reported, acknowledged, triage complete, escalated, contained, eradicated, recovered, closed.

They give you:
- **Time to detect:** first malicious event → detected/reported
- **Time to acknowledge:** detected → acknowledged
- **Time to contain:** acknowledged → contained
- **Time to recover:** detected → recovered

## 3. L1 triage (target: within the "Triage complete" column)

1. **Verify the report yourself.** Load the page and screenshot it with a timestamp. INC-0001's L1 skipped this; don't.
2. **Rule out an authorized change.** Ask the web or app owner whether a deployment, content change or maintenance was scheduled, and check the change calendar.
3. **Quick SIEM checks (last 24 h), copying the results into the ticket:**
   - Alerts on the server: `index=* (dest_ip=<server_ip> OR dstip=<server_ip>) (sourcetype=suricata OR sourcetype=fortigate_utm) | stats count by sourcetype, src_ip, srcip`. Field names differ by source (Suricata uses `dest_ip`/`src_ip`; FortiGate raw logs use `dstip`/`srcip`), so check them first.
   - Admin login volume: POSTs to the admin login path, counted by `src_ip`
   - Shells from the web stack: run the *Web Server Process Spawns a Command Shell* search
4. **Set the initial priority** from section 2.
5. **Escalate to L2** (section 4 criteria) with the ticket fields completed: asset, reporter, what you verified, what you checked, initial priority, and your questions for L2.

**L1 does not:** reboot the server, delete files, block IPs on their own authority, or contact the attacker.

## 4. Escalation criteria

**From L1 to L2,** if any of these apply:
- an unauthorized change is confirmed
- any security alert or AV hit on the server
- a successful login after many failures
- any shell spawned by the web stack
- or you can't rule out compromise within the triage target

**From L2 to the Shift Lead / SOC Manager, and the IR team,** if any of these apply:
- P1 criteria are confirmed
- the attacker may still be active
- credentials or data may be exposed
- other hosts may be involved
- a public or legal impact (defacement, customer data)

Communications/Legal are notified through the SOC Manager.

## 5. L2 investigation

Work in this order, and record every query in the case notes.

1. **Scope the data.** Which sourcetypes mention the site or server? Check field names before relying on them; add-ons can rename sourcetypes and fail to extract fields. Normalize every source to UTC, and write down each source's clock offset.
2. **Who is talking to it.** Top source IPs with first and last seen times. Separate scanners (high volume, injection payloads) from humans (normal browser, low volume).
3. **Authentication abuse.** Count login POSTs by source and account. A password tried from two different IPs is a strong clue for which guess worked. Confirm success with admin-only activity right after the login.
4. **Uploads and new files.** Multipart POSTs, IDS file-transfer events, and firewall AV logs. Large events may not have extracted fields, so also search the raw text for filenames.
5. **Execution on the host.** Process tree under the web server process (Sysmon event ID 1), and its command lines. Get hashes from Sysmon, never by collecting the file.
6. **Outbound connections.** Anything the web server initiated (Sysmon event ID 3, firewall, Stream). Reverse shells and second-stage downloads show up here.
7. **Impact.** What changed (defacement file, database), and what the attacker could read (config files with credentials).
8. **Timeline, IOCs and ATT&CK mapping.** Write down evidence gaps explicitly, instead of guessing.
9. **Enrich IOCs** (`intel/enrich_iocs.py`). Treat old cloud-IP reputation with caution: file hashes stay meaningful; IPs and domains decay.

**Safety:** never download, open or run suspected malware. Use hashes and existing sandbox or VirusTotal reports.

## 6. Containment, eradication and recovery checklist

**Contain**
- [ ] Preserve evidence first: memory capture and disk image (coordinate with IR).
- [ ] Isolate the server, or restrict it to IR access; put up a maintenance page.
- [ ] Block outbound internet from the server, except required endpoints.
- [ ] Disable the compromised accounts; end sessions; restrict the admin panel to VPN or an allow-list.
- [ ] Switch firewall AV and web-filter profiles for the server from monitor to block.
- [ ] Short-term blocks on attacker IPs and domains (knowing cloud IPs get reassigned).

**Eradicate**
- [ ] Rebuild from a known-good image if any interactive shell or unknown commands ran. Otherwise, remove the web shells and payloads, and hunt for other files changed after initial access.
- [ ] Check for new accounts, services, scheduled tasks and installed CMS extensions.
- [ ] Rotate credentials: CMS admins, database credentials in config files, service accounts.

**Recover**
- [ ] Restore content from a clean backup taken before initial access; verify the site.
- [ ] Patch the CMS and its extensions.
- [ ] Harden: MFA on admin, lockout or rate limiting, PHP `disable_functions` for command execution, a non-writable web root, no script execution in upload folders.
- [ ] Deploy or verify the detections in `detections/`, and confirm endpoint field extraction works.
- [ ] Heightened monitoring for 30 days.

**Close**
- [ ] SLA timestamps complete; incident report and escalation note filed.
- [ ] Lessons learned within 5 business days: control gaps, detection gaps, playbook updates.

## 7. Related content

- Detections: [`detections/test-results.md`](../detections/test-results.md)
- Example case: [`report/incident-report.md`](../report/incident-report.md)
- Query patterns: [`investigation/queries.md`](../investigation/queries.md)
