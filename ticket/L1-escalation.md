\# INC-0001: Public website defaced (escalated to L2)



> Simulated ticket written to frame this lab. The premise (imreallynotbatman.com was defaced) comes from Splunk's BOTS v1 scenario. The reporter, L1 actions and severity are realistic choices, not dataset facts. Timestamps are anchored to the dataset once the investigation establishes the timeline.



| Field | Value |

|---|---|

| Ticket ID | INC-0001 |

| Status | Escalated to L2 |

| Affected asset | imreallynotbatman.com (public web server) |

| Reported by / channel | Employee, via help desk phone call |

| Reported at | \[TBD: anchor to dataset] |

| L1 triaged at | \[TBD] |

| Escalated to L2 at | \[TBD] |

| L2 acknowledged at | \[TBD] |

| Initial severity (L1) | P2 High |

| SLA target | Acknowledge within 30 min; updates every 4 h |



\## Summary

\[YOUR 2–3 SENTENCES HERE]



\## What L1 observed

An employee called the help desk to report that the company's public homepage was showing unfamiliar content instead of the normal page. The help desk opened a ticket and routed it to the SOC.



\## What L1 checked before escalating

\- Contacted the web team, who confirmed no website change or deployment was planned or approved.



\## Why this was escalated

An unauthorized change to a public-facing production system meets the escalation criterion for suspected compromise. L1 assigned P2: the system is public-facing and compromise is likely but not yet confirmed.



\## Questions for L2

1\. How did the attacker get in?

2\. Are they still in, or did they leave anything behind?

3\. What was changed or taken?

4\. How do we prevent a repeat?

