# Incident timeline: imreallynotbatman.com compromise (2016-08-10)

All times are **UTC**, with the Splunk display time (EDT, UTC−4) alongside. Query numbers refer to [`queries.md`](queries.md).

**Clock normalization.** The sources logged in four different time zones:

| Source | Logged in |
|---|---|
| Splunk display | UTC−4 |
| Stream JSON (`endtime`/`timestamp`) | UTC |
| FortiGate and Suricata device logs | UTC−6 |
| Web server local clock (eXtplorer file listing) | UTC−7 |

Each event below was checked against at least one source with an explicit offset before conversion. Sysmon times have one-second precision.

Indicators are defanged in prose (`[.]`, `hxxp`).

| UTC | EDT | Actor | Event | Evidence |
|---|---|---|---|---|
| 21:36:45 | 17:36:45 | 40.80.148.42 | First request to the site. Start of an Acunetix vulnerability scan (about 20,900 requests; XSS, SQLi, XXE, Shellshock, PHP-config probes). | Q7, Q8, Q9 |
| 21:45:09 | 17:45:09 | 23.22.63.114 | First request from a `Python-urllib/2.7` client. | Q7, Q9 |
| 21:45:21 – 21:46:51 | 17:45:21 – 17:46:51 | 23.22.63.114 | **Brute force** against the Joomla admin login (`/joomla/administrator/index.php`): 412 distinct passwords for `admin` in about 90 seconds. No IDS alert fired. | Q10, Q11a, Q11b, Q8 |
| 21:48:00 | 17:48:00 | 40.80.148.42 (IE11) | Opens the admin login page in a real browser. | Q13 |
| 21:48:05 | 17:48:05 | 40.80.148.42 (IE11) | **Logs in as `admin` / `batman`**: a single attempt using the password found by the brute force. | Q11b, Q12, Q13 |
| 21:48:07 – 21:48:11 | 17:48:07 – 17:48:11 | 40.80.148.42 → web server | Admin dashboard loads; admin-only AJAX calls succeed; the server makes its normal Joomla update check to update[.]joomla[.]org. Login confirmed. | Q13, Q23 |
| 21:49:28 | 17:49:28 | 40.80.148.42 | Opens Joomla's Extension Manager. | Q13 |
| 21:50:31 | 17:50:31 | 40.80.148.42 | Submits an extension install (`com_installer&view=install`); the request carried a file named `agent.php`. | Q13, Q14, Q17 |
| 21:51:32 | 17:51:32 | 40.80.148.42 | First-ever use of the **eXtplorer** file manager component. Most likely installed in the previous step; the package itself isn't visible in the logs. | Q13 |
| 21:52:45 | 17:52:45 | FortiGate | Antivirus detects `3791.exe` in an upload as **W32/Swrort.C!tr** (critical), `action=monitored`. **Not blocked.** | Q22b |
| 21:52:45 – 21:52:47 | 17:52:45 – 17:52:47 | 40.80.148.42 | **Uploads `3791.exe` and `agent.php`** to the web root (`C:\inetpub\wwwroot\joomla\`) through eXtplorer. The server replies "Upload successful!" | Q18, Q22b |
| 21:52:48 | 17:52:48 | 40.80.148.42 | Lists the `/joomla` directory; both new files are present (3791.exe 72.07 KB, agent.php 1.47 KB). | Q22b |
| 21:55:22 | 17:55:22 | 23.22.63.114 | Starts calling the web shell `/joomla/agent.php` (193 requests until 22:21:34). | Q17, Q21 |
| 21:56:18 | 17:56:18 | we1149srv | **`php-cgi.exe` → `cmd.exe /c "3791.exe 2>&1"` → `3791.exe` runs.** The web shell executes the uploaded payload. | Q20 |
| 21:56:19 | 17:56:19 | we1149srv → 23.22.63.114 | `3791.exe` opens a **reverse shell** to 23.22.63.114:**3791**. | Q26, Q27 |
| 21:58:23 | 17:58:23 | we1149srv | `3791.exe` spawns `cmd.exe` (interactive shell). | Q20 |
| 22:06:21 | 18:06:21 | we1149srv → 23.22.63.114 | **Defacement:** `php-cgi.exe` (the web shell) downloads `poisonivy-is-coming-for-you-batman.jpeg` from hxxp://prankglassinebracket[.]jumpingcrab[.]com:1337. FortiGate categorizes the site as "Malicious Websites" and **allows** it. | Q23, Q24, Q27, Q28 |
| 22:08:13 | 18:08:13 | we1149srv | `3791.exe` spawns `cmd.exe` again. | Q20 |
| 22:13:46 | 18:13:46 | we1149srv → 23.22.63.114 | Second download of the defacement image. | Q28 |
| 22:19:10 – 22:19:11 | 18:19:10 – 18:19:11 | we1149srv → 23.22.63.114 | Third download of the image (last `php-cgi.exe` connection to port 1337). | Q27, Q28 |
| 22:21:18 | 18:21:18 | 40.80.148.42 (IE11) | Attacker views the public site `/joomla/`, likely checking the defacement. | Q13 |
| 22:21:34 | 18:21:34 | 23.22.63.114 | Last web-shell request. | Q21 |
| 22:22:27 | 18:22:27 | 40.80.148.42 | Last traffic from the scanner/operator IP. | Q7 |

## Duration

- **Scan to admin access:** 11 minutes 20 seconds (21:36:45 → 21:48:05).
- **Brute force:** about 90 seconds.
- **Admin access to code execution:** 8 minutes 13 seconds (21:48:05 → 21:56:18).
- **First request to defacement:** about 29.5 minutes.

## Evidence gaps (stated, not guessed)

- **Which extension package the 17:50:31 install used.** The request recorded a file named `agent.php`, and eXtplorer appears a minute later. The logs don't show the package itself.
- **How the image was placed on the page.** Sysmon recorded `php-cgi.exe` connecting to port 1337 but logged no file-write event naming the image (Q25). Network logs prove the server pulled the image; they don't show which page file was changed.
- **What was typed in the 3791.exe shells.** Sysmon shows `cmd.exe` launched at 21:58:23 and 22:08:13 UTC. The commands inside the reverse shell aren't logged.
- **Visitor-side impact.** This is the attack-only dataset with little benign traffic, so there are no logged visitor requests for the defaced page (Q28).
