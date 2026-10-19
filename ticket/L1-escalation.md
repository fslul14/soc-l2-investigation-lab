# INC-0001: Public website defaced (escalated to L2)

> Simulated ticket written to frame this lab. The premise (imreallynotbatman.com was defaced) comes from Splunk's BOTS v1 scenario. The reporter, L1 actions and severity are realistic choices, not dataset facts. Timestamps are anchored to the dataset: they were set after the investigation established when the defacement happened.

| Field | Value |
|---|---|
| Ticket ID | INC-0001 |
| Status | Escalated to L2 |
| Affected asset | imreallynotbatman.com (public web server) |
| Reported by / channel | Employee, via help desk phone call |
| Reported at | 2016-08-10 22:40 UTC (18:40 EDT) |
| L1 triaged at | 2016-08-10 22:45 UTC |
| Escalated to L2 at | 2016-08-10 23:05 UTC |
| L2 acknowledged at | 2016-08-10 23:20 UTC (15 min; within the P2 30-min target) |
| Initial severity (L1) | P2 High |
| SLA target | Acknowledge within 30 min; updates every 4 h |

## Summary
An employee reported that the company's public website, imreallynotbatman.com, is showing unfamiliar content instead of its normal homepage. The web team confirmed that no change or deployment was planned or approved. That makes this an unauthorized change to a public-facing production server and a likely compromise. Escalated to L2 at P2 to find out how the attacker got in, whether they still have access, and what was changed.

## What L1 observed
An employee called the help desk to report that the company's public homepage was showing unfamiliar content instead of the normal page. The help desk opened a ticket and routed it to the SOC.

## What L1 checked before escalating
- Contacted the web team, who confirmed no website change or deployment was planned or approved.

## Why this was escalated
An unauthorized change to a public-facing production system meets the escalation criterion for suspected compromise. L1 assigned P2: the system is public-facing and compromise is likely but not yet confirmed.

## Questions for L2
1. How did the attacker get in?
2. Are they still in, or did they leave anything behind?
3. What was changed or taken?
4. How do we prevent a repeat?

## L2 outcome
Investigated and raised to **P1 Critical**. See [`report/incident-report.md`](../report/incident-report.md).
