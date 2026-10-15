from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

SAMPLE_LOGS = [
    {"timestamp": "2026-10-14 09:00:01", "username": "arun", "source_ip": "10.0.0.21", "event": "login", "status": "success"},
    {"timestamp": "2026-10-14 09:02:15", "username": "meena", "source_ip": "10.0.0.22", "event": "login", "status": "success"},
    {"timestamp": "2026-10-14 09:10:03", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:10:09", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:10:15", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:10:21", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:10:27", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:10:33", "username": "admin", "source_ip": "203.0.113.44", "event": "login", "status": "success"},
    {"timestamp": "2026-10-14 09:14:10", "username": "kavi", "source_ip": "198.51.100.73", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:14:18", "username": "kavi", "source_ip": "198.51.100.73", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:14:25", "username": "kavi", "source_ip": "198.51.100.73", "event": "login", "status": "failed"},
    {"timestamp": "2026-10-14 09:20:00", "username": "root", "source_ip": "192.0.2.90", "event": "privilege_change", "status": "success"},
    {"timestamp": "2026-10-14 09:22:00", "username": "arun", "source_ip": "10.0.0.21", "event": "file_access", "status": "success"},
]

def _normalise(row):
    return {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}

def analyze_logs(rows: Iterable[dict]):
    logs = [_normalise(row) for row in rows]
    alerts = []
    failed_by_ip = Counter()
    failed_by_user = Counter()
    successful_by_ip = Counter()
    for row in logs:
        event = row.get("event", "").lower()
        status = row.get("status", "").lower()
        ip = row.get("source_ip") or row.get("ip") or "unknown"
        user = row.get("username") or row.get("user") or "unknown"
        if status in {"failed", "failure", "denied", "error"} or "fail" in event:
            failed_by_ip[ip] += 1
            failed_by_user[(user, ip)] += 1
        if status in {"success", "successful", "allowed"}:
            successful_by_ip[ip] += 1

    for ip, count in failed_by_ip.items():
        if count >= 5:
            same_ip_success = successful_by_ip[ip] > 0
            alerts.append({
                "id": f"BRUTE-{len(alerts)+1:03d}",
                "title": "Possible brute-force login",
                "severity": "High" if same_ip_success else "Medium",
                "risk_score": min(98, 55 + count * 5 + (15 if same_ip_success else 0)),
                "source_ip": ip,
                "evidence": f"{count} failed login events from this IP" + (" followed by a successful login." if same_ip_success else "."),
                "recommendation": "Validate the account owner, inspect surrounding events, and consider temporary rate-limiting or blocking under your response policy.",
                "mitre": "T1110 · Brute Force",
            })

    for (user, ip), count in failed_by_user.items():
        if count >= 3 and not any(a["source_ip"] == ip and "brute-force" in a["title"].lower() for a in alerts):
            alerts.append({
                "id": f"AUTH-{len(alerts)+1:03d}",
                "title": "Repeated authentication failures",
                "severity": "Medium",
                "risk_score": min(85, 40 + count * 8),
                "source_ip": ip,
                "evidence": f"{count} failed attempts for account '{user}'.",
                "recommendation": "Check whether the failures are expected and review authentication logs for the account.",
                "mitre": "T1110 · Brute Force",
            })

    for row in logs:
        event = row.get("event", "").lower()
        if any(token in event for token in ("privilege_change", "privilege escalation", "admin_grant", "sudo")):
            alerts.append({
                "id": f"PRIV-{len(alerts)+1:03d}",
                "title": "Privilege change event",
                "severity": "High",
                "risk_score": 78,
                "source_ip": row.get("source_ip") or row.get("ip") or "unknown",
                "evidence": f"Privilege-related event for '{row.get('username') or row.get('user') or 'unknown'}' at {row.get('timestamp') or 'an unknown time'}.",
                "recommendation": "Verify the change against an approved request and review the actor's recent activity.",
                "mitre": "T1098 · Account Manipulation",
            })

    # Deduplicate repeated privilege events / keep most relevant findings.
    seen = set()
    unique = []
    for a in alerts:
        key = (a["title"], a["source_ip"], a["evidence"])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    unique.sort(key=lambda a: a["risk_score"], reverse=True)

    severities = Counter(a["severity"] for a in unique)
    return {
        "summary": {
            "total_logs": len(logs),
            "total_alerts": len(unique),
            "high": severities.get("High", 0),
            "medium": severities.get("Medium", 0),
            "low": severities.get("Low", 0),
            "unique_ips": len({r.get("source_ip") or r.get("ip") for r in logs if r.get("source_ip") or r.get("ip")}),
            "failed_logins": sum(failed_by_ip.values()),
        },
        "alerts": unique,
        "timeline": [
            {
                "timestamp": row.get("timestamp") or "Unknown time",
                "username": row.get("username") or row.get("user") or "unknown",
                "source_ip": row.get("source_ip") or row.get("ip") or "unknown",
                "event": row.get("event") or "unknown",
                "status": row.get("status") or "unknown",
            }
            for row in logs[-30:]
        ],
        "note": "Rule-based demo analysis. Validate alerts against real environment context before taking action."
    }
