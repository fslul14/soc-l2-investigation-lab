# IOC enrichment results

Generated 2026-10-19 23:37 UTC by `intel/enrich_iocs.py`.

Sources: VirusTotal API v3 (lookups only, nothing submitted) and AbuseIPDB API v2 `check`.

**Read with care:** reputation reflects the run date, not the 2016 incident. Cloud IPs get reassigned and domains expire, so a clean result today does not clear the indicator, and a dirty one may describe a later tenant. Indicators are defanged.

| Type | Indicator | VT malicious / suspicious / harmless / undetected | VT detail | AbuseIPDB score | AbuseIPDB reports (365 d) | Country / ISP | Status |
|---|---|---|---|---|---|---|---|
| ip | 40[.]80[.]148[.]42 | 1 / 0 / 55 / 36 | US; Microsoft Corporation | 0 | 0 | US / Microsoft Corporation | VT: ok; AbuseIPDB: ok |
| ip | 23[.]22[.]63[.]114 | 0 / 0 / 55 / 37 | US; Amazon.com, Inc. | 0 | 0 | US / Amazon Data Services Northern Virginia | VT: ok; AbuseIPDB: ok |
| domain | prankglassinebracket[.]jumpingcrab[.]com | 3 / 0 / 54 / 35 | reputation -1; Porkbun LLC |  |  |  | VT: ok |
| url | hxxp://prankglassinebracket[.]jumpingcrab[.]com:1337/poisonivy-is-coming-for-you-batman[.]jpeg | 4 / 0 / 63 / 31 | reputation 0 |  |  |  | VT: ok |
| sha256 | EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D | 65 / 0 / 0 / 5 | Win32 EXE; trojan.swrort/cryptz; ab.exe |  |  |  | VT: ok |
