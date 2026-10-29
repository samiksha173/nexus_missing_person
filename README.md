# NEXUS - Case Management

1. `pip install -r requirements.txt`
2. `python app.py`
3. Open http://127.0.0.1:5000 and sign in with `admin` / `Admin@12345` (you must change it on first login).

Folder layout: `app.py`, `templates/`, `static/css/style.css`, `static/js/app.js`.
An old `instance/nexus.db` with a different layout is renamed automatically to `nexus_old_*.db`.
Roles: Officer (cases, matches, transfers requests), Supervisor (+ reports, approvals, scans), Admin (+ users, audit log).
