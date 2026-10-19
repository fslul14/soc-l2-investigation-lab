# Detection test results

Three detections written in Sigma, converted to Splunk SPL with `sigma-cli`, and run against the BOTS v1 data in this lab.

## How they were converted

```powershell
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p detections\pipelines\bots-v1.yml detections\sigma\<rule>.yml -o detections\spl\<rule>.spl
```

- **Tool versions:** recorded in [`versions.txt`](versions.txt), captured with `pip show sigma-cli pysigma pysigma-backend-splunk` on the machine that ran the tests.
- **Field mapping:** the Splunk backend refuses to convert without a processing pipeline. [`pipelines/bots-v1.yml`](pipelines/bots-v1.yml) maps generic Sigma field names (`cs-method`, `cs-uri-stem`, `cs-user-agent`, `c-ip`, …) to this dataset's Splunk Stream field names. It also adds the right index and sourcetype or source.
- **Adaptation:** the Sysmon rule needed a manual fix after conversion (see Rule 3).

Times below are UTC. Splunk displays them as UTC−4.

---

## Rule 1: Acunetix scanner payload marker

| | |
|---|---|
| Sigma | [`sigma/web_acunetix_scanner_marker.yml`](sigma/web_acunetix_scanner_marker.yml) |
| SPL | [`spl/web_acunetix_scanner_marker.spl`](spl/web_acunetix_scanner_marker.spl) (sigma-cli output, unchanged) |
| ATT&CK | T1595.002 |
| Expected | Fires only on 40.80.148.42, starting about 21:36 UTC on 2016-08-10. The scanner fuzzed the User-Agent header with `acunetix_wvs_security_test` payloads (queries.md Q9). |
| Test search | Converted SPL, followed by `\| stats count min(_time) as first max(_time) as last by src_ip \| convert ctime(first) ctime(last)` |
| **Actual** | **277 events, all from 40.80.148.42**, first 21:36:45 UTC, last 21:51:20 UTC (17:36:45–17:51:20 EDT) |
| Fired? | **Yes** |
| Evidence | Result counts above, from the Splunk run on 2026-10-19 (screenshot optional: `detections/screenshots/rule1.png`) |

**False positives and tuning**
- **Authorized scans** by your own team will match. Allow-list the approved scanner IPs, or route their hits to a low-severity "authorized scan" queue.
- **Coverage gap:** this only catches the marker. Acunetix's normal requests used a plain Chrome user agent, so the rule sees a small share of the scan. Pair it with a request-rate rule (for example, more than 500 requests from one IP in 5 minutes) to catch scanners that don't label their payloads.
- **Cost:** `*acunetix*` is a leading-wildcard match, which is slow on large indexes. In production, run it over a short time range or against an accelerated data model.

---

## Rule 2: Joomla admin brute force (Sigma correlation rule)

| | |
|---|---|
| Sigma | [`sigma/web_joomla_admin_bruteforce.yml`](sigma/web_joomla_admin_bruteforce.yml): a base rule for one login attempt, plus an `event_count` correlation of 20 or more attempts per source IP in 5 minutes |
| SPL | [`spl/web_joomla_admin_bruteforce.spl`](spl/web_joomla_admin_bruteforce.spl) (sigma-cli output, unchanged) |
| ATT&CK | T1110.001 |
| Expected | One row: 23.22.63.114 with about 412 attempts in the bucket starting 21:45 UTC (queries.md Q11b). **Negative test:** the attacker's single successful login from 40.80.148.42 must *not* appear, because one attempt is below the threshold. |
| **Actual** | **One row: 23.22.63.114, event_count 412**, in the bucket starting 21:45 UTC (17:45 EDT). Without the threshold, the same bucket also shows 40.80.148.42 with 1 attempt. |
| Fired? | **Yes** |
| Negative test passed (40.80.148.42 absent)? | **Yes**: the single successful login was filtered out by the `>= 20` threshold |
| Evidence | Result counts above, from the Splunk run on 2026-10-19 (screenshot optional: `detections/screenshots/rule2.png`) |

**False positives and tuning**
- **Threshold:** 20 per 5 minutes is far above human typing errors and far below this attack's roughly 270 per minute. Lower it for internet-facing admin panels that should get almost no logins.
- **Window type:** `bin _time span=5m` uses fixed 5-minute buckets, so an attack that straddles a bucket boundary is split in two. A sliding window (`streamstats time_window=5m`) avoids that.
- **What it misses:** a slow, spread-out brute force (a few attempts per hour from many IPs). Add a second rule that counts distinct source IPs failing against the same account over 24 hours.
- **The control that matters more:** the IDS had no signature for this attack. Account lockout or rate limiting, plus restricting `/administrator/` to a VPN or allow-list, prevents it outright.

---

## Rule 3: Web server process spawns a command shell

| | |
|---|---|
| Sigma | [`sigma/win_webserver_spawns_shell.yml`](sigma/win_webserver_spawns_shell.yml) |
| SPL (converted) | [`spl/win_webserver_spawns_shell.spl`](spl/win_webserver_spawns_shell.spl) (sigma-cli output: **returns nothing in this lab**, see below) |
| SPL (adapted) | [`spl/win_webserver_spawns_shell.adapted.spl`](spl/win_webserver_spawns_shell.adapted.spl) |
| ATT&CK | T1505.003, T1059.003 |
| Expected | At least one event: `php-cgi.exe` → `cmd.exe /c "3791.exe 2>&1"` on we1149srv at 21:56:18 UTC (queries.md Q20) |
| **Actual** | Converted SPL: **0 events** (as predicted). Adapted SPL: **17 events**, all `php-cgi.exe` → `cmd.exe` on we1149srv, 21:55:22–22:21:34 UTC. Command lines: `echo 24365`, `dir`, `ls`, `ifconfig`, `3791.exe`, `echo 63059`, `dir` ×7, `move ..\1.jpeg 2.jpeg`, `move 2.jpeg imnotbatman.jpg`, `exit` ×2 |
| Fired? | **Yes** (adapted version) |
| Evidence | Result counts and command lines above, from the Splunk run on 2026-10-19 (screenshot optional: `detections/screenshots/rule3.png`) |

**Why it needed adapting.** In this lab, the Sysmon add-on did not extract fields like `EventID`, `ParentImage` and `Image` for the renamed `xmlwineventlog` sourcetype (queries.md Q15 and Q19). The converted search filters on those fields, so it finds nothing.

The adapted version keeps the same detection logic, but:
1. pulls the fields out of the raw XML with `rex` first,
2. then applies the converted conditions with `| search`,
3. and adds a raw keyword pre-filter so `rex` runs on fewer events.

In production the right fix is to repair field extraction in the add-on configuration, not to keep `rex` in every rule.

**False positives and tuning**
- **Legitimate shell-outs:** some web applications run shell commands for backups, image processing or update checks. Baseline the command lines that `php-cgi.exe` and `w3wp.exe` normally run, and allow-list exact command lines rather than whole parent processes.
- **Extend the child list:** add `wscript.exe`, `cscript.exe`, `certutil.exe` and `bitsadmin.exe`.
- **Severity:** the first match (21:55:22 UTC, `echo 24365`) came **25 minutes before the defacement** (22:20:33 UTC). High severity is justified.
- **Bonus finding:** testing this rule recovered every web-shell command, including the `move` that overwrote `imnotbatman.jpg`. That's now Q29 in the investigation.

---

## Summary

| Rule | Converted cleanly | Adapted | Fired on BOTS v1 | Notes |
|---|---|---|---|---|
| Acunetix marker | Yes | No | **Yes**: 277 events, 1 source | Catches the marked payloads only, about 1% of the scanner's ~20,900 requests |
| Joomla admin brute force (correlation) | Yes | No | **Yes**: 412 attempts, 1 source | Negative test passed |
| Web server spawns shell | Yes | Yes (rex, broken add-on extraction) | **Yes**: 17 events (adapted); 0 (converted) | Would have alerted 25 minutes before the defacement |
