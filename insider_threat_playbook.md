# Insider Threat Detection Playbook – Financial Services

## Introduction and Problem Statement

Financial services institutions continue to suffer from insider threats: rogue traders diverting funds, departing employees downloading proprietary data and administrators abusing access to customer accounts.  The challenge is compounded because insiders already possess legitimate credentials and understand the organisation’s infrastructure.  A 2026 industry blog notes that insiders “don’t need to break in; they simply need to log in”【877349132402730†L65-L75】.  Traditional perimeter defences and signature‑based tools often miss such threats because the activity looks like normal work【877349132402730†L65-L75】.  Detecting insider risk therefore requires behavioural analysis and coordination across security, HR and legal functions.

## Common Insider‑Threat Scenarios

Understanding typical insider behaviours helps define detection logic.  According to Congruity360’s insider‑risk guide, three scenarios are particularly common【877349132402730†L116-L141】:

- **Data exfiltration** – unauthorised transfer of data to personal storage (e.g., uploading gigabytes of proprietary code or forwarding sensitive emails to private accounts).  Exfiltration often spikes during resignation periods【877349132402730†L124-L128】.
- **Privilege misuse** – using legitimate access for unauthorised purposes, such as a database administrator viewing salary tables without a business justification【877349132402730†L130-L135】.
- **Accidental exposure** – negligence, such as misconfigured cloud storage or emailing spreadsheets with PII to the wrong recipient【877349132402730†L138-L144】.

These scenarios manifest as behavioural indicators that can be monitored in logs: bulk downloads, unusual database queries, and access to systems outside a user’s normal job scope.  High‑fidelity signals include access anomalies (impossible travel or off‑hours logins), “collection behaviour” (high‑volume file copying or creation of encrypted archives) and egress signals (use of unapproved cloud storage or large attachments)【877349132402730†L189-L207】.  Focusing on these high‑signal events reduces alert fatigue.

## Building an Insider‑Risk Program

Technology alone cannot solve insider risk.  A formal Insider Risk Management (IRM) program facilitates coordination between **security**, **HR** and **legal** teams, ensuring there is a clear workflow to decide whether a technical indicator requires a security response, a legal hold or an HR intervention【877349132402730†L178-L182】.  Before monitoring employees, organisations must establish policies that comply with privacy laws and labour agreements; alignment with HR and Legal is “non‑negotiable” to avoid liability【877349132402730†L215-L220】.  The National Insider Threat Task Force guide also recommends including the Office of the General Counsel in the insider‑threat working group; legal advice and participation at every stage are essential【27025682229351†L427-L437】.  HR should be an early and engaged stakeholder because it often has access to behavioural information that can identify potential insider problems【759819931559721†L14-L31】; HR engagement, combined with security and leadership support, enables proactive, holistic mitigation【759819931559721†L20-L37】.

## Automation Script Overview

The Python script `insider_threat_detection.py` accompanies this playbook.  It processes log events (e.g., Windows Event Logs, database audit logs, file server logs) stored in `sample_events.json` and enriches flagged events with context from `hr_lookup.json`.  The script implements three detection rules:

1. **Bulk data downloads** – events where downloaded bytes exceed 100 MB.  This reflects “collection behaviour” leading to exfiltration【877349132402730†L198-L203】.
2. **Unauthorized resource access** – when a user accesses a resource not listed in their authorised scope.  Privilege misuse is a common insider‑threat scenario【877349132402730†L189-L196】.
3. **After‑hours database queries** – database queries outside 08:00–18:00.  Off‑hours access anomalies are high‑signal indicators【877349132402730†L189-L194】.

Each flagged event is enriched with simulated HR attributes (days since last performance review, resignation‑notice status, recent access changes).  The script calculates a risk score: each indicator adds 30 points; an active resignation notice adds 20; performance reviews older than six months add 10; and recent privilege changes add 10.  Risk bands are defined as **Low** (< 40), **Medium** (40–69) and **High** (≥ 70).  For each alert, the script generates a structured triage report with the indicators, HR context, risk score and recommended next actions.

## Incident Response Workflow

This playbook outlines the steps SOC analysts should follow when a potential insider threat is detected.  The workflow integrates technical detection, HR/Legal coordination and evidence preservation:

### 1 Detection and Alerting

- Use the `insider_threat_detection.py` script or a SIEM pipeline to continuously monitor logs for high‑signal insider‑threat indicators (bulk downloads, unauthorised access, off‑hours queries, etc.).  Correlate events across data sources to identify patterns (e.g., failed login attempts followed by a successful login and a massive data download)【877349132402730†L170-L174】.
- Prioritise alerts based on risk score.  High‑risk alerts require immediate action, while medium‑risk alerts warrant SOC review and HR consultation.

### 2 HR Enrichment and Context Gathering

- Pull HR attributes for the user from internal systems (e.g., days since last performance review, notice of resignation, recent job changes).  HR often has access to information that helps identify potential insider problems and should be engaged early【759819931559721†L14-L33】.
- Review the user’s role, recent performance issues and any known grievances.  Consider whether the access aligns with business need.

### 3 Triage and Scoring

- Combine behavioural indicators with HR context to calculate a risk score.  Document the indicators, HR factors and reasoning in a triage report.  Continuous evaluation of behavioural and human factors is necessary because insiders often exhibit warning signs weeks or months before an incident【759819931559721†L14-L24】.
- Assign a risk band (Low/Medium/High) to guide the response.  Maintain logs of all triage actions for audit purposes.

### 4 Escalation and Response

- **High Risk**: Immediately inform the incident response (IR) team, disable the user’s access, and initiate a coordinated response with HR and legal.  Determine whether the behaviour warrants disciplinary or legal action.  Teramind’s incident‑response guidance emphasises that containment, investigation and appropriate disciplinary or legal actions are essential, and that HR, legal and IT security must be involved【578650224228556†L520-L526】.
- **Medium Risk**: Have a SOC analyst review the context with HR.  Monitor the user more closely, gather additional evidence and prepare to escalate if further anomalies occur.
- **Low Risk**: Record the incident, notify the user’s manager if appropriate and continue monitoring.

### 5 Evidence Preservation and Legal Hold

- As soon as it becomes reasonably foreseeable that the investigation could lead to disciplinary action or litigation, issue a **legal hold**.  Organisations have a duty to preserve relevant electronically stored information (ESI) once litigation is anticipated【910616557401335†L14-L33】.  A legal hold is a written notice directing employees to preserve potentially responsive information【910616557401335†L25-L33】.  Best practices include clear, consistent communication describing the nature of the matter, the types of information to preserve and the custodians’ responsibilities【910616557401335†L35-L39】.
- Collaborate with IT and records management to identify where relevant data resides—email systems, mobile devices, cloud storage and backups【910616557401335†L44-L48】.  Preservation efforts must be reasonable and proportionate【910616557401335†L48-L50】.
- Maintain a defensible audit trail documenting when the legal hold was issued, which custodians were notified and what steps were taken to preserve data【910616557401335†L53-L56】.

### 6 Interview and Coordination

- Conduct an internal interview with the user, accompanied by HR and, if necessary, legal counsel.  Ensure all questions are consistent with internal policies and respect civil liberties.  The NITTF guide emphasises that legal participation is essential at every stage【27025682229351†L427-L437】.
- If the matter involves an external investigation or potential prosecution, engage the Office of General Counsel and, if necessary, external law enforcement.  Always respect jurisdictional laws and data privacy regulations.

### 7 Resolution and Continuous Improvement

- Document the outcome (e.g., disciplinary action, termination, remediation).  Close the legal hold only when counsel determines it is safe to do so.
- Review the incident with the insider‑threat working group to identify gaps in detection or response.  Congruity360 recommends regular “tabletop exercises” to test and refine detection logic and policy enforcement【877349132402730†L244-L247】.
- Update baselines and detection thresholds to reduce false positives.  Continuous tuning and learning are critical to adapt to evolving insider tactics【877349132402730†L228-L233】.

## Conclusion

Insider threats remain one of the most challenging risks in financial services because legitimate access can mask malicious intent.  A successful programme combines behavioural analytics with human context and clear procedures.  This playbook, together with the accompanying Python script, demonstrates how to:

* Detect high‑signal insider‑threat indicators such as bulk data downloads, unauthorised access and off‑hours activity.
* Enrich technical alerts with HR data to produce a risk score and triage report.
* Coordinate response across security, HR and legal functions, invoking legal hold and preserving evidence when necessary.
* Conduct structured interviews and continuous improvement exercises to strengthen the programme.

By following these steps and aligning detection logic with organisational policies and laws, security teams can move beyond purely technical controls and demonstrate a mature, proactive insider‑risk capability.
