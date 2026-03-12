"""
insider_threat_detection.py
================================

This script provides a simple framework for detecting potential
insider‑threat behaviour within simulated log data.  It is designed
for demonstration purposes and should not be treated as a complete
production solution.  The goal is to showcase how a SOC analyst can
combine behavioural indicators with context from HR systems to
automatically triage alerts and produce a risk score.

The script expects two JSON files:

* ``sample_events.json`` – a list of events.  Each event should
  contain at minimum the following keys:
  ``timestamp`` (ISO‑8601 string), ``user`` (user ID), ``action``
  (e.g. ``"file_download"`` or ``"db_query""), ``resource`` (the
  system or dataset accessed) and any other action‑specific fields
  such as ``bytes`` for download size.
* ``hr_lookup.json`` – a mapping from user IDs to HR attributes.
  For each user you can include keys like ``days_since_review``
  (integer), ``resignation_notice`` (boolean), and
  ``recent_access_change`` (number of privilege changes in the last
  month).  In a real environment these values would be obtained via
  API calls to an HR system such as Workday or SAP.

The script defines a set of simple detection rules:

* **Bulk data downloads** – if a user downloads more than
  ``BULK_DOWNLOAD_THRESHOLD`` bytes (default 100 MB) within a single
  event, the event is flagged.  Large downloads are common during
  legitimate workflows, so this indicator alone is not conclusive but
  contributes to the risk score.  Congruity360’s insider threat blog
  notes that “collection behaviour” often includes high‑volume file
  copying or aggregation of files into a single location【877349132402730†L198-L203】.
* **Unauthorized resource access** – the script includes a simple
  ``AUTHORIZED_RESOURCES`` mapping to illustrate how job scope can be
  enforced.  If a user accesses a resource not listed in their
  allowed resources, the event is flagged.  Privilege misuse, such
  as accessing systems without a business justification, is a common
  insider‑threat scenario【877349132402730†L189-L196】.
* **After‑hours database queries** – events with the ``action``
  ``"db_query"`` that occur outside normal business hours (08:00–18:00)
  are flagged.  Congruity360 emphasises monitoring off‑hours access
  anomalies【877349132402730†L189-L194】.

Each flagged event is enriched with HR context from ``hr_lookup.json``
and a simple risk score is calculated.  The score starts at zero and
receives:

* +30 points for each behavioural indicator triggered.
* +20 points if the user has an active resignation notice (employees
  preparing to leave often pose heightened risk【759819931559721†L14-L24】).
* +10 points if the last performance review was more than 180 days ago.
* +10 points if the user recently had access changes (an indicator of
  changing job scope).

Risk bands are defined as:

* **Low risk** – score < 40: log and monitor.
* **Medium risk** – 40 ≤ score < 70: SOC review and consider HR
  consultation.
* **High risk** – score ≥ 70: immediate escalation to incident response,
  involve HR and legal counsel, and preserve evidence for potential
  legal hold【877349132402730†L178-L182】【910616557401335†L24-L56】.

Finally, a triage report is produced for each flagged event.  Reports
are written to ``triage_reports.json`` and printed to stdout for
transparency.

Usage::

    python insider_threat_detection.py

"""

import json
from datetime import datetime, time
from typing import Any, Dict, List

# Threshold for what constitutes a bulk download (100 MB)
BULK_DOWNLOAD_THRESHOLD = 100 * 1024 * 1024

# Business hours definition (08:00‑18:00)
BUSINESS_START = 8
BUSINESS_END = 18

# Mapping of users to the resources they are allowed to access.  In a
# real system this would come from an IAM/identity database.
AUTHORIZED_RESOURCES: Dict[str, List[str]] = {
    "jdoe": ["customer_db", "analytics_dashboard"],
    "asmith": ["hr_portal", "finance_db"],
    "bwilson": ["customer_db", "marketing_reports"],
}

def load_json(path: str) -> Any:
    """Load JSON from a file and return the resulting object."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def is_after_hours(ts: str) -> bool:
    """Return True if the ISO‑8601 timestamp is outside business hours."""
    dt = datetime.fromisoformat(ts)
    return dt.hour < BUSINESS_START or dt.hour >= BUSINESS_END

def calculate_risk_score(indicators: List[str], hr_context: Dict[str, Any]) -> int:
    """Compute a simple risk score based on triggered indicators and HR data."""
    score = 0
    # Each indicator contributes 30 points
    score += 30 * len(indicators)
    # HR factors
    if hr_context.get("resignation_notice"):
        score += 20
    if hr_context.get("days_since_review", 0) > 180:
        score += 10
    if hr_context.get("recent_access_change", 0) > 0:
        score += 10
    return score

def risk_band(score: int) -> str:
    """Return a textual risk band based on the numeric score."""
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

def detect_events(events: List[Dict[str, Any]], hr_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Iterate through events and generate triage reports for flagged events."""
    reports = []
    for event in events:
        user = event.get("user")
        if not user:
            continue
        indicators: List[str] = []
        # Bulk data download detection
        if event.get("action") == "file_download":
            bytes_downloaded = event.get("bytes", 0)
            if bytes_downloaded >= BULK_DOWNLOAD_THRESHOLD:
                indicators.append("bulk_download")
        # Unauthorized resource access detection
        allowed_resources = AUTHORIZED_RESOURCES.get(user, [])
        resource = event.get("resource")
        if resource and allowed_resources and resource not in allowed_resources:
            indicators.append("unauthorized_access")
        # After‑hours database queries
        if event.get("action") == "db_query" and is_after_hours(event["timestamp"]):
            indicators.append("after_hours_query")
        # If no indicators, skip generating a report
        if not indicators:
            continue
        # Enrich with HR context (default to empty dict)
        hr_context: Dict[str, Any] = hr_data.get(user, {})
        # Calculate risk score and band
        score = calculate_risk_score(indicators, hr_context)
        band = risk_band(score)
        # Recommended next actions based on risk
        if band == "High":
            recommendation = (
                "Escalate to IR team, disable user’s access, consult HR and legal counsel, "
                "and place relevant data under legal hold."
            )
        elif band == "Medium":
            recommendation = (
                "SOC analyst review, coordinate with HR to verify user’s role and business need. "
                "Consider temporary monitoring and prepare for potential escalation."
            )
        else:
            recommendation = "Monitor and document. No immediate action required."
        report = {
            "timestamp": event["timestamp"],
            "user": user,
            "resource": resource,
            "action": event.get("action"),
            "indicators": indicators,
            "hr_context": hr_context,
            "risk_score": score,
            "risk_band": band,
            "recommendation": recommendation,
        }
        reports.append(report)
    return reports

def main() -> None:
    # Load event log and HR data.  If the files are missing or malformed,
    # an exception will be raised.
    events = load_json("sample_events.json")
    hr_data = load_json("hr_lookup.json")
    reports = detect_events(events, hr_data)
    # Write triage reports to a file and print them
    with open("triage_reports.json", "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)
    # Print to stdout for demonstration
    print(json.dumps(reports, indent=2))

if __name__ == "__main__":
    main()
