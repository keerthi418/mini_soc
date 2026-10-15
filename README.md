# SentinelX — SOC Dashboard + Consent-Based Device Inventory

SentinelX is an educational FastAPI SOC dashboard. This version adds a local SQLite database, a best-effort local network device inventory, consent-request records, an audit trail, and page-style navigation with a Back button.

## Important safety and technical limits
- **Wi-Fi inventory is best-effort:** the Scan button reads the server laptop's operating-system ARP cache. It does not guarantee every connected device is listed; some devices will appear only after normal network traffic.
- **No spying/remote activity monitoring:** an IP/MAC address cannot reveal what someone is doing on another laptop. SentinelX does not capture screens, files, keystrokes, app usage, or private traffic.
- **Consent requests are stored in SQLite:** the server cannot magically show a notification on another laptop. For a real cross-device prompt, an owner-approved client app/agent must be installed and connected on that device. The current request page is a workflow/demo, not a remote push-notification system.
- **Accept/Deny requires a reason**, and the decision is written to the audit log. A decision is a record of consent, not remote access to the device.
- **Cloud storage is not enabled/configured.** The Storage page shows SQLite status and a secure setup checklist. Choose a provider, create a private bucket, configure least-privilege credentials in environment variables, encryption and retention before adding a cloud connector.
- This is a lab/demo, not a production SIEM. Do not expose it to the public internet without authentication, authorization, TLS, CSRF protections, secure secret management and a security review. Use only on networks and devices you are authorized to administer.

## Features
- SOC overview, threat alerts, event timeline and CSV log analysis (up to 5 MB)
- Local ARP-cache inventory scan and device history in SQLite
- Consent request records with Accept/Deny + mandatory rationale
- SQLite audit trail for scans, CSV analyses and decisions
- Storage status page and cloud-hardening checklist
- Page-style sidebar navigation and Back button
- FastAPI Swagger docs

## Requirements
- Python 3.10+
- Windows PowerShell
- Internet for initial dependency installation

## Run on Windows PowerShell
Open PowerShell in the extracted `SentinelX` folder (the folder containing `README.md`):

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

If activation is blocked:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

If `py` is unavailable, try `python -m venv venv` instead.

Open:
- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/health

Stop with `Ctrl+C`. The SQLite file `sentinelx.db` is created automatically in the project folder.

## Local network use
Only use the device inventory on a network you own or are authorized to administer. To let another laptop access the dashboard on a trusted home/lab LAN, the server must be configured to listen on its LAN interface and Windows Firewall must allow the port; do this only on a trusted network. The present consent workflow does not deliver a notification to another laptop.

## CSV format
```csv
timestamp,username,source_ip,event,status
2026-10-14 09:10:03,admin,203.0.113.44,login,failed
```

## Cloud storage
Cloud uploads are intentionally not activated by default. Before enabling them, select a provider and implement its SDK integration with a private bucket, server-side encryption, access logs, least-privilege IAM, lifecycle retention, and backup/restore testing. Never place access keys in source code or commit them to Git.
