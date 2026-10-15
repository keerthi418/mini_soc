# 🛡️ SentinelX — Consent-Aware Network Security & SOC Monitoring Platform

**See the signal. Understand the risk. Respect the user.**

SentinelX is a lightweight Security Operations Center (SOC) platform designed to help security teams investigate suspicious login activity, review network device discovery results, analyze security logs, and maintain transparent access-decision records through a unified dashboard.

Unlike traditional log dashboards that focus only on alerts, SentinelX aims to combine **security visibility, human-reviewed decisions, and accountability** in one place.

> **Project focus:** Network visibility + threat detection + consent-based access workflows + auditability.

---

## 🚨 The Problem

Small labs, college networks, and learning environments often lack a simple, centralized way to review suspicious authentication events and investigate potential security risks.

Security alerts alone do not explain what happened, why an action was approved or denied, or what evidence supports the decision.

SentinelX addresses this problem by bringing log analysis, alert prioritization, device discovery, and decision records into one interface.

## 💡 Our Solution

SentinelX provides a centralized security dashboard that helps users:

- Analyze authentication and system-event logs.
- Identify suspicious patterns using rule-based detection.
- Review discovered network devices and their available metadata.
- Record access requests and human decisions with explanations.
- Maintain investigation history using a local SQLite database.
- Prepare for future cloud-backed storage and authorized endpoint monitoring.

## ✨ Key Features

### 1. 📊 Security Operations Dashboard

A centralized view of security events and investigation metrics.

- Total log events analyzed.
- Detected alerts and severity distribution.
- Failed-login statistics.
- Visual threat analytics.
- Dedicated navigation for individual investigation pages.

### 2. 🔍 Rule-Based Threat Detection

SentinelX analyzes structured CSV logs to identify suspicious patterns, including:

- Repeated authentication failures.
- Potential brute-force activity.
- Privilege-related events.
- High-priority events requiring human investigation.

Each finding can include evidence, a risk score, severity, and a recommended investigation step.

**Important:** Alerts are investigation leads, not proof that a user is malicious.

### 3. 🌐 Network Device Discovery

The planned network-visibility workflow helps identify devices visible through authorized local network discovery.

- Available IP address information.
- MAC address information when available.
- Discovery status and timestamps.
- Device inventory for investigation.

Device visibility depends on network configuration, permissions, and available system data. Discovery does not reveal another laptop's screen, applications, or private activity.

### 4. 🤝 Consent-Aware Access Decisions

SentinelX is designed around a transparent request-and-review workflow.

1. An access request is submitted with its purpose.
2. The request is presented for review.
3. An authorized reviewer chooses **Accept** or **Deny**.
4. A reason is recorded for the decision.
5. The decision and timestamp are retained for audit purposes.

The decision record helps answer:

- What was requested?
- Why was it requested?
- Who made the decision?
- Was the request accepted or denied?
- What explanation supports the decision?

**Scope note:** A recorded approval is not equivalent to enforcing access permissions on another device. Actual endpoint consent notifications and access enforcement require additional authorized client software and security controls.

### 5. 🗃️ SQLite Database

SentinelX uses SQLite as its local database foundation.

Potential records include:

- Device discovery history.
- Access requests and decisions.
- Security events and audit records.

SQLite is suitable for a lightweight prototype because it does not require a separate database server.

### 6. ☁️ Cloud Storage Roadmap

The architecture can be extended to support secure cloud-backed investigation records.

Planned improvements include:

- Private cloud storage.
- Encrypted data transfer.
- Secure credential management.
- Retention policies and access controls.
- Backup and recovery.

Cloud storage requires an actual provider integration and configuration; displaying cloud setup information alone does not mean uploads are active.

### 7. 🧭 Investigation-Focused Navigation

The interface is organized into separate workspace pages, making it easier to move between the dashboard, alerts, event timeline, log analysis, and other supported modules.

---

## 🔄 How SentinelX Works

```text
          Security Log CSV
                 |
                 v
       Log Parsing & Validation
                 |
                 v
       Rule-Based Detection
                 |
                 v
       Risk & Severity Ranking
                 |
                 v
        SOC Investigation UI
                 |
                 v
        Human Review & Action
                 |
                 v
      Decision / Audit Records
                 |
                 v
          SQLite Database
```

Network device discovery and consent-request workflows are complementary modules. They do not automatically provide endpoint activity monitoring or enforce operating-system access controls.

---

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Backend | Python |
| Web framework | FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Data analysis | CSV parsing and rule-based detection |
| Database | SQLite |
| API testing | FastAPI Swagger UI |
| Visualization | Chart.js |
| Runtime | Uvicorn |

---

## 🖥️ Getting Started

### Prerequisites

- Windows 10 or Windows 11.
- Python 3.10 or a compatible version supported by the project dependencies.
- PowerShell.
- A web browser.

### 1. Download the project

Download or clone the repository, then open the project folder in PowerShell.

### 2. Create a virtual environment

```powershell
py -3 -m venv venv
```

### 3. Activate the environment

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Start the application

Run this command from the directory containing the `app` and `static` folders:

```powershell
python -m uvicorn app.main:app --reload
```

### 6. Open SentinelX

| Resource | URL |
|---|---|
| Dashboard | http://127.0.0.1:8000 |
| API documentation | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/api/health |

Keep the PowerShell terminal running while using the application.

---

## 📁 Project Structure

```text
SentinelX/
├── app/
│   ├── __init__.py
│   ├── main.py
│   └── detector.py
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   └── test_detector.py
├── requirements.txt
├── .gitignore
└── README.md
```

- `main.py` — FastAPI application and API routes.
- `detector.py` — sample security events and detection logic.
- `index.html` — dashboard structure.
- `style.css` — visual design and responsive layout.
- `app.js` — dashboard interactions, API calls, and chart rendering.
- `tests/` — detection-related tests.

---

## 🧪 Example Use Case

A security analyst uploads a CSV containing repeated failed logins followed by a successful authentication.

SentinelX processes the records, identifies a pattern that matches its configured rules, and presents an alert with supporting evidence and a suggested investigation step.

The analyst reviews the evidence and decides what to investigate next rather than allowing the detection engine to automatically blame or block a user.

---

## 🔐 Security & Privacy Principles

SentinelX is intended for authorized security monitoring and educational use.

- Monitor only systems and networks you are authorized to assess.
- Do not collect private endpoint activity without appropriate authorization and informed consent.
- Treat alerts as indicators requiring investigation.
- Protect audit records and credentials.
- Use authentication, authorization, and encrypted communication before deploying beyond a trusted local environment.
- Do not expose the development server directly to the public internet.

---

## 🚀 Future Enhancements

- [ ] Live endpoint agent with visible monitoring status.
- [ ] Secure, real-time consent notifications to authorized client devices.
- [ ] Strong authentication and role-based access control.
- [ ] Persistent SQLite storage for all investigation modules.
- [ ] Cloud storage provider integration.
- [ ] Device inventory enrichment and discovery history.
- [ ] Improved audit reports and investigation exports.
- [ ] Automated tests for API endpoints and database operations.
- [ ] Secure deployment configuration for a multi-device environment.

---

## 🎯 What Makes SentinelX Different?

SentinelX brings three ideas together:

**Visibility** — understand security events and discoverable network devices.

**Explainability** — connect alerts to evidence and investigation recommendations.

**Accountability** — record human decisions and their reasons instead of treating an automated alert as a final verdict.

The goal is not simply to detect suspicious activity. It is to make security investigations easier to understand, review, and audit.

---

## ⚠️ Project Status

SentinelX is a prototype intended for learning, development, and controlled testing. Feature availability depends on the implementation included in the current version. Endpoint monitoring, real-time cross-device consent notifications, enforced access control, and cloud uploads require additional implementation and validation.

## 👩‍💻 Author

**Keerthisri D.**

Cybersecurity | Security Operations | Python Development

GitHub: [keerthi418](https://github.com/keerthi418)

---

*SentinelX — Security visibility with human accountability.*
