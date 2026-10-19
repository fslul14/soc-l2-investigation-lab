# Investigation queries

Every SPL query run during the investigation, in order, with one line on what it found.

Environment: Splunk Enterprise 10.6.1.1, BOTS v1 attack-only dataset, index `botsv1`. Times shown by Splunk are UTC−4 (EDT); the timeline converts everything to UTC.

**Who wrote each query** (kept honest for interviews):

- **README**: taken from the BOTS v1 dataset README
- **HINT-3**: query supplied by Claude at my request; I typed and ran it (explain-back recap pending)
- **AI-WRITTEN**: written by Claude in "fast mode" after I chose to finish in one evening; I typed/ran it in Splunk and exported the results; interpretation was done together (explain-back recap pending)

Field names were checked before use (Q6, Q14, Q15, Q19). Several add-ons renamed sourcetypes at search time, so the queries use the post-add-on names (see Q4).

---

## Setup and data checks

### Q1. Confirm the dataset loaded (README)
```spl
index=botsv1 earliest=0
```
Found: 955,807 events across 22 sourcetypes, 8 hosts and 24 sources.

### Q2. Events per sourcetype (HINT-3)
```spl
index=botsv1 earliest=0 | stats count by sourcetype | sort - count
```
Found: 22 rows, matching the 22 sourcetypes in the BOTS v1 README (before add-ons were installed).

### Q3. Lab hygiene: anything indexed outside botsv1? (HINT-3)
```spl
index=* NOT index=botsv1 earliest=0 | stats count by index, sourcetype
```
Found: no results. Splunk was not collecting logs from the host PC.

### Q4. Sourcetypes after installing add-ons (HINT-3, re-run of Q2)
```spl
index=botsv1 earliest=0 | stats count by sourcetype | sort - count
```
Found: 20 sourcetypes. The Windows add-on merged `WinEventLog:Application/Security/System` into `WinEventLog` (original name kept in `source`); the FortiGate add-on renamed `fgt_*` to `fortigate_*`; Sysmon now appears as `xmlwineventlog`.

---

## Scoping: where does the website appear?

### Q5. Which data sources mention the site (HINT-3)
```spl
index=botsv1 earliest=0 imreallynotbatman.com | stats count by sourcetype | sort - count
```
Found: 78,683 events in 4 sourcetypes: suricata 30,625; stream:http 22,200; fortigate_utm 13,918; iis 11,940.

### Q6. Check stream:http field names before using them (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | fieldsummary | search field IN (src_ip, dest_ip, site, http_method, uri, http_user_agent, status, form_data) | table field count distinct_count
```
Found: all 8 fields exist; only 2 distinct `src_ip` and 2 distinct `dest_ip` values.

### Q7. Who sends traffic to the site, and when (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count min(_time) as first_seen max(_time) as last_seen by src_ip, dest_ip | convert ctime(first_seen) ctime(last_seen) | sort - count | head 10
```
Found: web server is 192.168.250.70. 40.80.148.42 sent 20,931 requests (17:36:45–18:22:27 EDT); 23.22.63.114 sent 1,236 requests in under two minutes (17:45:09–17:46:53 EDT).

---

## Question 1: who scanned the site, and with what tool?

### Q8. IDS alerts against the web server (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=suricata event_type=alert dest_ip=192.168.250.70 | stats count by src_ip, alert.signature | sort - count | head 20
```
Found: 552 alerts, almost all from 40.80.148.42, including **"ET SCAN Acunetix Version 6 (Free Edition) Scan Detected" (45)** plus XSS, SQL injection, XXE, Shellshock (CVE-2014-6271) and PHP-config probes. No alerts at all from 23.22.63.114. (First run returned 0 because the `WEB_SERVER_IP` placeholder was left in.)

### Q9. User agents per source (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip, http_user_agent | sort - count | head 15
```
Found: 40.80.148.42 used a Chrome/41 user agent (20,792 requests) and fuzzed the User-Agent header with payloads containing `acunetix_wvs_security_test`; it also made 78 requests with an Internet Explorer 11 user agent. 23.22.63.114 used `Python-urllib/2.7`.

---

## Question 2: the brute force, and which credential worked

### Q10. Where POST requests went (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST | stats count by src_ip, uri | sort - count | head 10
```
Found: the site runs Joomla. 23.22.63.114 sent all 412 of its POSTs to the admin login `/joomla/administrator/index.php`.

### Q11a. What a login submission contains (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=23.22.63.114 http_method=POST | table _time uri form_data | head 5
```
Found: parameters are `username` and `passwd`; username `admin`, a different dictionary password each time, several per second.

### Q11b. Brute-force statistics (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*passwd* | rex field=form_data "username=(?<user>[^&]+)" | rex field=form_data "passwd=(?<pass>[^&]+)" | stats count dc(pass) as distinct_passwords min(_time) as first max(_time) as last by src_ip, user | convert ctime(first) ctime(last)
```
Found: 23.22.63.114 tried 412 distinct passwords for `admin` in about 90 seconds (17:45:21–17:46:51 EDT). 40.80.148.42 made exactly one login attempt, at 17:48:05 EDT.

### Q12. Which password worked (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*passwd* | rex field=form_data "passwd=(?<pass>[^&]+)" | stats count dc(src_ip) as num_sources values(src_ip) as sources by pass | where num_sources > 1
```
Found: `batman` is the only password seen from two IPs (23.22.63.114 and 40.80.148.42). Corroborated by Q13 and Q23.

### Q13. The attacker's browser session after the login (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=40.80.148.42 http_user_agent="*Trident*" | stats min(_time) as first count by http_method, uri | sort first | convert ctime(first)
```
Found: login at 17:48:05 EDT followed by admin-only requests (`com_ajax`, `com_installer` update checks), so the login succeeded. Then Extension Manager (17:49:28), an extension-install POST (17:50:31), and first use of the eXtplorer file manager (17:51:32).

---

## Question 3: what was uploaded, and from where

### Q14. File-upload fields in the attacker's POSTs (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 src_ip=40.80.148.42 http_method=POST | fieldsummary | search field="part*" OR field="*filename*" | table field count distinct_count values
```
Found: `part_filename` = `agent.php` in one event (the 17:50:31 install request). The main upload event was missed here because it was too large for auto-extraction (see Q22b).

### Q15. Check Sysmon field names (AI-WRITTEN)
```spl
index=botsv1 earliest=0 source="*Sysmon*" EventCode=1 | fieldsummary | search field IN (host, Image, ParentImage, CommandLine, Hashes, User) | table field count distinct_count
```
Found: no results. Sysmon fields such as `EventCode` were not being extracted for the renamed sourcetype (diagnosed in Q19).

### Q16. Processes launched by the web stack (AI-WRITTEN)
```spl
index=botsv1 earliest=0 source="*Sysmon*" EventCode=1 (ParentImage="*php*" OR ParentImage="*w3wp*") | stats count min(_time) as first values(Hashes) as hashes by host, ParentImage, Image, CommandLine | convert ctime(first) | sort first
```
Found: no results, for the same reason as Q15. Re-done with `rex` in Q20.

### Q17. Upload and use of agent.php (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http (part_filename="agent.php" OR uri="*agent.php*") | table _time src_ip dest_ip http_method uri status | sort _time
```
Found: from 17:55:22 EDT, 23.22.63.114 requested `/joomla/agent.php` repeatedly, all with status 200.

### Q18. Executables seen by the IDS (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=suricata event_type=fileinfo fileinfo.filename="*.exe" (src_ip=192.168.250.70 OR dest_ip=192.168.250.70) | stats count values(fileinfo.md5) as md5 by src_ip, dest_ip, fileinfo.filename
```
Found: `3791.exe` transferred from 40.80.148.42 to the web server. Other `.exe` rows are scanner probe paths. Suricata had no MD5 (file hashing not enabled).

### Q19. Every log that mentions 3791.exe (AI-WRITTEN)
```spl
index=botsv1 earliest=0 3791.exe | stats count by sourcetype, source, host
```
Found: web server hostname is `we1149srv`. Sysmon events (69) have sourcetype `xmlwineventlog` and source `WinEventLog:Microsoft-Windows-Sysmon/Operational`; also seen in FortiGate, Stream, Suricata and Windows Security logs.

### Q20. Execution chain and hashes, parsing Sysmon XML with rex (AI-WRITTEN)
```spl
index=botsv1 earliest=0 3791.exe | rex "<EventID>(?<EventID>\d+)</EventID>" | rex "<Data Name='Image'>(?<Image>[^<]+)</Data>" | rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>" | rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>" | rex "<Data Name='Hashes'>(?<Hashes>[^<]+)</Data>" | search EventID=1 | table _time host Image ParentImage CommandLine Hashes
```
Found: at 17:56:18 EDT `php-cgi.exe` ran `cmd.exe /c "3791.exe 2>&1"`, which started `C:\inetpub\wwwroot\joomla\3791.exe` (SHA256 `EC78C938…C47FA45D`). 3791.exe then spawned `cmd.exe` at 17:58:23 and 18:08:13 EDT.

### Q21. How long agent.php was used (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http uri="/joomla/agent.php" | stats count min(_time) as first max(_time) as last by src_ip, http_method, status | convert ctime(first) ctime(last)
```
Found: 193 GET requests from 23.22.63.114, 17:55:22–18:21:34 EDT.

### Q22. Suricata detail for 3791.exe (AI-WRITTEN, not run)
```spl
index=botsv1 earliest=0 sourcetype=suricata event_type=fileinfo fileinfo.filename="3791.exe" | table _time src_ip dest_ip http.url http.http_user_agent fileinfo.size fileinfo.state
```
Not run (superseded by Q22b).

### Q22b. Raw network events for 3791.exe (AI-WRITTEN)
```spl
index=botsv1 earliest=0 3791.exe (sourcetype=stream:http OR sourcetype=suricata OR sourcetype=fortigate_utm) | table _time sourcetype _raw | sort _time
```
Found: at 17:52:45 EDT FortiGate antivirus flagged `3791.exe` as **W32/Swrort.C!tr** (critical) with `action=monitored`, so it was not blocked; the firewall's SHA256 matches Sysmon's. The same request uploaded **both `3791.exe` and `agent.php` through eXtplorer** and the server replied "Upload successful!". This 77 KB event was missed by field-based searches because Splunk auto-extracts fields only from the start of very long events.

---

## Question 4: how the site was defaced, and the attacker's infrastructure

### Q23. Web requests made by the web server (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=192.168.250.70 | stats count min(_time) as first by dest_ip, site, uri | convert ctime(first) | sort first
```
Found: at 18:06:21 EDT the server downloaded `/poisonivy-is-coming-for-you-batman.jpeg` from `prankglassinebracket[.]jumpingcrab[.]com:1337` (23.22.63.114). The only other outbound requests were normal Joomla update checks at 17:48:09, triggered by the admin login.

### Q24. Firewall view of the server's outbound traffic (AI-WRITTEN)
```spl
index=botsv1 earliest=0 sourcetype=fortigate_utm srcip=192.168.250.70 | stats count min(_time) as first by dstip, hostname, url, catdesc, action | convert ctime(first) | sort first
```
Found: FortiGate categorized the image host as **"Malicious Websites"** and **allowed** it (3 events from 18:06:21 EDT).

### Q25. Sysmon events naming the image (AI-WRITTEN)
```spl
index=botsv1 earliest=0 source="*Sysmon*" "poisonivy-is-coming-for-you-batman.jpeg" | rex "<EventID>(?<EventID>\d+)</EventID>" | rex "<Data Name='Image'>(?<Image>[^<]+)</Data>" | rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>" | rex "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>" | table _time EventID Image CommandLine TargetFilename | sort _time
```
Found: no results. Sysmon did not record the image's file name (evidence gap; see timeline).

### Q26. Where 3791.exe connected (AI-WRITTEN)
```spl
index=botsv1 earliest=0 source="*Sysmon*" 3791.exe | rex "<EventID>(?<EventID>\d+)</EventID>" | search EventID=3 | rex "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>" | rex "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>" | stats count min(_time) as first max(_time) as last by DestinationIp, DestinationPort | convert ctime(first) ctime(last)
```
Found: one outbound connection to **23.22.63.114:3791** at 17:56:19 EDT, one second after execution: a reverse shell.

### Q27. Every server process that connected to 23.22.63.114 (AI-WRITTEN)
```spl
index=botsv1 earliest=0 source="*Sysmon*" 23.22.63.114 | rex "<EventID>(?<EventID>\d+)</EventID>" | rex "<Data Name='Image'>(?<Image>[^<]+)</Data>" | rex "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>" | stats count min(_time) as first max(_time) as last by EventID, Image, DestinationPort | convert ctime(first) ctime(last)
```
Found: **`php-cgi.exe` connected to 23.22.63.114:1337** three times (18:06:22–18:19:11 EDT), so PHP code on the server (the web shell) fetched the defacement image. `3791.exe` connected to port 3791 once. The other 1,430 rows are the attacker's inbound HTTP sessions handled by the Windows kernel HTTP stack (`System`), 17:45:09–18:21:35 EDT.

### Q28. Every log mentioning the image (AI-WRITTEN)
```spl
index=botsv1 earliest=0 "poisonivy-is-coming-for-you-batman.jpeg" | stats count min(_time) as first max(_time) as last by sourcetype, src_ip, dest_ip | convert ctime(first) ctime(last)
```
Found: only the server's own downloads from 23.22.63.114 (fortigate_utm 3, stream:http 2, suricata 3 + 1 reply), 18:06:21–18:19:11 EDT. No visitor requests for the image were captured, so the logs show the image being pulled, not the page being viewed.

---

## Follow-up hunt from detection testing

### Q29. Every command the web shell ran (AI-WRITTEN; the adapted Rule 3 search from `detections/`)
```spl
index="botsv1" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ("php-cgi.exe" OR "php.exe" OR "w3wp.exe" OR "httpd.exe")
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search EventID=1 ParentImage IN ("*\\php-cgi.exe", "*\\php.exe", "*\\w3wp.exe", "*\\httpd.exe") Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe")
| table _time host ParentImage Image CommandLine
```
Found: 17 commands, all `php-cgi.exe` → `cmd.exe /c "<command> 2>&1"` on we1149srv, 17:55:22–18:21:34 EDT:
- **Tests and reconnaissance:** `echo 24365`, `dir`, `ls`, `ifconfig`, `echo 63059`.
- **Payload execution:** `3791.exe`.
- **Directory listings:** `dir`, repeatedly.
- **The defacement:** `move ..\1.jpeg 2.jpeg` (18:20:10) and **`move 2.jpeg imnotbatman.jpg`** (18:20:33).
- **Cleanup:** `exit` twice.

This shows exactly how the site image was replaced, which closes most of the evidence gap left by Q25.
