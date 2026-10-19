# MITRE ATT&CK mapping

Techniques mapped from observed evidence only (ATT&CK Enterprise). Query numbers refer to [`queries.md`](queries.md); times are UTC on 2016-08-10.

Confidence:
- **High:** directly shown in at least two sources.
- **Medium:** shown in one source, or inferred from strong context.

| Tactic | Technique | What happened | Evidence | Confidence |
|---|---|---|---|---|
| Reconnaissance | **T1595.002** Active Scanning: Vulnerability Scanning | 40.80.148.42 ran Acunetix against the site (21:36–22:22): about 20,900 requests fuzzing for XSS, SQLi, XXE, Shellshock and PHP misconfigurations. | Q8 (Suricata "ET SCAN Acunetix"), Q9 (`acunetix_wvs_security_test` payloads) | High |
| Credential Access | **T1110.001** Brute Force: Password Guessing | 23.22.63.114 tried 412 dictionary passwords for `admin` on the Joomla admin login in about 90 seconds. | Q10, Q11a, Q11b | High |
| Initial Access | **T1078** Valid Accounts | The guessed credential (`admin`/`batman`) was used from 40.80.148.42 to log in to the CMS admin panel. | Q12, Q13, Q23 (update check on dashboard load) | High |
| Persistence | **T1505.003** Server Software Component: Web Shell | `agent.php` was uploaded to the web root and called 193 times by 23.22.63.114. PHP then launched commands and outbound connections. | Q17, Q21, Q22b, Q20 (php-cgi → cmd), Q27 | High |
| Command and Control | **T1105** Ingress Tool Transfer | `3791.exe` and `agent.php` were uploaded to the server, and the server later pulled the defacement image from attacker infrastructure. | Q18, Q22b, Q23, Q27 | High |
| Execution | **T1059.003** Command and Scripting Interpreter: Windows Command Shell | `php-cgi.exe` ran `cmd.exe /c "3791.exe 2>&1"`, and `3791.exe` later spawned `cmd.exe` twice. | Q20 | High |
| Command and Control | **T1071.001** Application Layer Protocol: Web Protocols | The web shell was controlled over HTTP GET requests to `/joomla/agent.php`. | Q17, Q21 | High |
| Command and Control | **T1571** Non-Standard Port | Reverse shell to 23.22.63.114 on tcp/3791; image server on tcp/1337. | Q23, Q24, Q26, Q27 | High |
| Discovery | **T1083** File and Directory Discovery | The attacker listed the web root through eXtplorer (`getdircontents`, dir=/joomla). | Q22b | Medium |
| Impact | **T1491.002** Defacement: External Defacement | The web shell fetched `poisonivy-is-coming-for-you-batman.jpeg` from prankglassinebracket[.]jumpingcrab[.]com:1337, matching the reported defacement. | Q23, Q24, Q27, Q28, ticket INC-0001 | High (fetch) / Medium (page change; see evidence gaps) |

## Considered and not mapped

- **T1190 Exploit Public-Facing Application.** The scanner probed for vulnerabilities, but access came from a guessed password, not an exploit. Nothing in the data shows a successful exploit.
- **Lateral movement and exfiltration.** Neither was looked for beyond the web server in this investigation. Out of scope for this report; noted as a follow-up hunt.

## Control gaps observed (for detection engineering)

| Stage | Control | What it did |
|---|---|---|
| Brute force | Suricata IDS | No alert for 412 failed logins in 90 seconds (Q8). |
| Malware upload | FortiGate antivirus | Detected `W32/Swrort.C!tr` but `action=monitored`, so the file was delivered (Q22b). |
| Defacement fetch | FortiGate web filter | Categorized the destination as "Malicious Websites" but allowed it (Q24). |
| Admin login | Joomla | No account lockout, rate limiting or MFA visible. The admin panel was reachable from the internet. |
