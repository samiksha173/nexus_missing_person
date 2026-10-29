"""NEXUS - Case management for missing-person investigations.

Run:  pip install -r requirements.txt  &&  python app.py
Open: http://127.0.0.1:5000   (first login: admin / Admin@12345, you must change it)
"""
import csv
import io
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime
from difflib import SequenceMatcher
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DATABASE = INSTANCE_DIR / "nexus.db"


def load_secret_key():
    """Use NEXUS_SECRET_KEY, or create and keep a random key on first run."""
    env_key = os.environ.get("NEXUS_SECRET_KEY")
    if env_key:
        return env_key
    key_file = INSTANCE_DIR / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NEXUS_HTTPS") == "1",
)
logging.basicConfig(level=logging.INFO)

STATUSES = ["Open", "Under Investigation", "Found", "Closed"]
CATEGORIES = ["Missing Person", "Unidentified Person", "Trafficking"]
GENDERS = ["Female", "Male", "Other", "Unknown"]
ROLES = ["Officer", "Supervisor", "Admin"]
MATCH_STATUSES = ["Pending", "Reviewed", "Rejected", "Confirmed"]
TRANSFER_REASONS = ["Jurisdiction", "Investigative coordination",
                    "Related case review", "Other approved reason"]
TRANSFER_FLOW = {"Pending": {"Approved", "Rejected"},
                 "Approved": {"Completed", "Rejected"}}
PAGE_SIZE = 20

# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Officer',
    active INTEGER NOT NULL DEFAULT 1,
    must_change INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL UNIQUE,
    case_reference TEXT,
    category TEXT NOT NULL DEFAULT 'Missing Person',
    full_name TEXT NOT NULL,
    age INTEGER,
    gender TEXT,
    height INTEGER,
    identifying_features TEXT,
    clothing TEXT,
    district TEXT NOT NULL,
    police_station TEXT,
    date_missing TEXT,
    date_reported TEXT,
    last_seen_location TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    reported_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    matched_case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    similarity REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Pending',
    reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, matched_case_id)
);
CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    from_district TEXT,
    to_district TEXT NOT NULL,
    reason TEXT NOT NULL,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'Pending',
    requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_district ON cases(district);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    rows = get_db().execute(sql, params).fetchall()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur


def schema_is_current():
    """False when an old database from an earlier version of NEXUS is present."""
    if not DATABASE.exists() or DATABASE.stat().st_size == 0:
        return True
    db = sqlite3.connect(DATABASE)
    try:
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "users" not in tables:
            return not tables          # empty db is fine, unknown tables are not
        cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        return {"username", "password_hash", "role", "must_change"} <= cols
    finally:
        db.close()


def init_db():
    if not schema_is_current():
        backup = DATABASE.with_name(f"nexus_old_{datetime.now():%Y%m%d_%H%M%S}.db")
        DATABASE.rename(backup)
        logging.warning("Old database layout found. Saved it as %s and created a new one.",
                        backup.name)
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        password = os.environ.get("NEXUS_ADMIN_PASSWORD", "Admin@12345")
        db.execute(
            "INSERT INTO users (username, full_name, password_hash, role) "
            "VALUES (?, ?, ?, 'Admin')",
            ("admin", "System Administrator", generate_password_hash(password)),
        )
        logging.warning("Created default admin account: admin / %s", password)
    db.commit()
    db.close()


def audit(action, details=""):
    user = g.get("user")
    execute(
        "INSERT INTO audit_log (user_id, username, action, details, ip) "
        "VALUES (?, ?, ?, ?, ?)",
        (user["id"] if user else None, user["username"] if user else None,
         action, details, request.remote_addr),
    )


# ---------------------------------------------------- security and sessions

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def load_user_and_protect():
    g.user = None
    if session.get("user_id"):
        user = query("SELECT * FROM users WHERE id = ? AND active = 1",
                     (session["user_id"],), one=True)
        if user:
            g.user = user
        else:
            session.clear()

    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400)

    if (g.user and g.user["must_change"]
            and request.endpoint not in {"account", "logout", "static"}):
        flash("Please set a new password before continuing.", "warning")
        return redirect(url_for("account"))


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


FAILED_LOGINS = {}
LOCK_AFTER, LOCK_SECONDS = 5, 600


def is_locked(key):
    now = time.time()
    attempts = [t for t in FAILED_LOGINS.get(key, []) if now - t < LOCK_SECONDS]
    FAILED_LOGINS[key] = attempts
    return len(attempts) >= LOCK_AFTER


def valid_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain letters and numbers."
    return None


@app.context_processor
def inject_globals():
    return {
        "current_user": g.get("user"),
        "csrf_input": lambda: Markup(
            f'<input type="hidden" name="_csrf" value="{csrf_token()}">'),
        "STATUSES": STATUSES, "CATEGORIES": CATEGORIES, "GENDERS": GENDERS,
        "ROLES": ROLES, "MATCH_STATUSES": MATCH_STATUSES,
        "TRANSFER_REASONS": TRANSFER_REASONS,
        "year": datetime.now().year,
    }


# ----------------------------------------------------------------- helpers

def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def to_int(value, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if low <= number <= high else None


def parse_case_form(form):
    text_fields = ["full_name", "gender", "identifying_features", "clothing",
                   "district", "police_station", "case_reference",
                   "last_seen_location", "notes", "category", "status"]
    d = {k: (form.get(k) or "").strip() for k in text_fields}
    d["date_missing"] = (form.get("date_missing") or "").strip()
    d["date_reported"] = (form.get("date_reported") or "").strip()
    d["age"] = (form.get("age") or "").strip()
    d["height"] = (form.get("height") or "").strip()
    errors = []

    if d["category"] not in CATEGORIES:
        d["category"] = "Missing Person"
    if d["status"] not in STATUSES:
        d["status"] = "Open"
    if d["gender"] and d["gender"] not in GENDERS:
        d["gender"] = ""
    if not d["full_name"]:
        if d["category"] == "Unidentified Person":
            d["full_name"] = "Unidentified"
        else:
            errors.append("Full name is required.")
    if not d["district"]:
        errors.append("Reporting district is required.")

    age = None
    if d["age"]:
        age = to_int(d["age"], 0, 125)
        if age is None:
            errors.append("Age must be a number between 0 and 125.")
    elif d["category"] != "Unidentified Person":
        errors.append("Age is required (an approximate value is fine).")
    d["age_value"] = age

    height = None
    if d["height"]:
        height = to_int(d["height"], 20, 300)
        if height is None:
            errors.append("Height must be between 20 and 300 cm.")
    d["height_value"] = height

    missing = parse_date(d["date_missing"])
    if not missing:
        errors.append("Date last seen is required.")
    elif missing > date.today():
        errors.append("Date last seen cannot be in the future.")
    if d["date_reported"] and not parse_date(d["date_reported"]):
        errors.append("Date reported is not a valid date.")
    if not d["date_reported"]:
        d["date_reported"] = date.today().isoformat()
    return d, errors


def norm(text):
    return re.sub(r"\s+", " ", (text or "").strip().casefold())


def words(text):
    return {w for w in re.findall(r"[a-z0-9]+", norm(text)) if len(w) > 2}


def similarity_score(a, b):
    """Record-comparison score (0-100). A lead only, never proof of identity."""
    score = 0.0
    na, nb = norm(a["full_name"]), norm(b["full_name"])
    if na and nb and "unidentified" not in (na, nb):
        score += 40 * SequenceMatcher(None, na, nb).ratio()
    if a["age"] is not None and b["age"] is not None:
        diff = abs(a["age"] - b["age"])
        score += 20 if diff <= 2 else 10 if diff <= 5 else 0
    ga, gb = norm(a["gender"]), norm(b["gender"])
    if ga and ga == gb and ga != "unknown":
        score += 10
    if a["height"] and b["height"]:
        diff = abs(a["height"] - b["height"])
        score += 10 if diff <= 5 else 5 if diff <= 10 else 0
    if norm(a["district"]) and norm(a["district"]) == norm(b["district"]):
        score += 5
    fa, fb = words(a["identifying_features"]), words(b["identifying_features"])
    if fa and fb:
        score += 15 * len(fa & fb) / len(fa | fb)
    return round(min(score, 100), 1)


def score_label(score):
    return "High" if score >= 75 else "Medium" if score >= 55 else "Low"


def pretty_date(value):
    parsed = parse_date((value or "")[:10])
    return parsed.strftime("%d %b %Y") if parsed else "—"


def slug(value):
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


app.jinja_env.filters["score_label"] = score_label
app.jinja_env.filters["pretty_date"] = pretty_date
app.jinja_env.filters["slug"] = slug


def save_match(id_a, id_b, score):
    low, high = sorted((id_a, id_b))
    cur = execute(
        "INSERT OR IGNORE INTO matches (case_id, matched_case_id, similarity) "
        "VALUES (?, ?, ?)", (low, high, score))
    return cur.rowcount > 0


def get_case_or_404(case_id):
    case = query("SELECT * FROM cases WHERE id = ?", (case_id,), one=True)
    if not case:
        abort(404)
    return case


def find_case(identifier):
    identifier = (identifier or "").strip()
    if not identifier:
        return None
    return query("SELECT * FROM cases WHERE case_number = ? COLLATE NOCASE "
                 "OR case_reference = ? COLLATE NOCASE",
                 (identifier, identifier), one=True)


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else None


# -------------------------------------------------------------------- auth

@app.route("/")
def home():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        key = (request.remote_addr, username)
        if is_locked(key):
            flash("Too many failed attempts. Try again in 10 minutes.", "error")
            return render_template("login.html"), 429
        user = query("SELECT * FROM users WHERE lower(username) = ? AND active = 1",
                     (username,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            FAILED_LOGINS.pop(key, None)
            session.clear()
            session["user_id"] = user["id"]
            g.user = user
            audit("login")
            return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
        FAILED_LOGINS.setdefault(key, []).append(time.time())
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not check_password_hash(g.user["password_hash"], current):
            error = "Current password is incorrect."
        elif new != confirm:
            error = "New passwords do not match."
        elif new == current:
            error = "Choose a password different from the current one."
        else:
            error = valid_password(new)
        if error:
            flash(error, "error")
        else:
            execute("UPDATE users SET password_hash = ?, must_change = 0 WHERE id = ?",
                    (generate_password_hash(new), g.user["id"]))
            audit("password_changed")
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("account.html")


# --------------------------------------------------------------- dashboard

@app.route("/dashboard")
@login_required
def dashboard():
    def one(sql, p=()):
        return query(sql, p, one=True)[0]

    stats = {
        "total": one("SELECT COUNT(*) FROM cases"),
        "open": one("SELECT COUNT(*) FROM cases WHERE status IN ('Open','Under Investigation')"),
        "found": one("SELECT COUNT(*) FROM cases WHERE status = 'Found'"),
        "matches": one("SELECT COUNT(*) FROM matches WHERE status = 'Pending'"),
        "transfers": one("SELECT COUNT(*) FROM transfers WHERE status IN ('Pending','Approved')"),
    }
    recent = query("SELECT * FROM cases ORDER BY id DESC LIMIT 6")
    by_status = {s: one("SELECT COUNT(*) FROM cases WHERE status = ?", (s,)) for s in STATUSES}
    return render_template("dashboard.html", stats=stats, recent=recent,
                           by_status=by_status,
                           max_status=max(by_status.values() or [1]) or 1)


# ------------------------------------------------------------------- cases

@app.route("/cases")
@login_required
def cases():
    q = (request.args.get("q") or "").strip()
    category = request.args.get("category") or ""
    status = request.args.get("status") or ""
    page = to_int(request.args.get("page"), 1, 100000) or 1

    where, params = ["1=1"], []
    if q:
        where.append("(full_name LIKE ? OR case_number LIKE ? OR case_reference LIKE ? "
                     "OR district LIKE ? OR police_station LIKE ?)")
        params += [f"%{q}%"] * 5
    if category in CATEGORIES:
        where.append("category = ?")
        params.append(category)
    else:
        category = ""
    if status in STATUSES:
        where.append("status = ?")
        params.append(status)
    else:
        status = ""

    clause = " AND ".join(where)
    total = query(f"SELECT COUNT(*) FROM cases WHERE {clause}", params, one=True)[0]
    pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    page = min(page, pages)
    rows = query(f"SELECT * FROM cases WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                 params + [PAGE_SIZE, (page - 1) * PAGE_SIZE])
    base_args = {k: v for k, v in {"q": q, "category": category, "status": status}.items() if v}
    return render_template("cases.html", cases=rows, total=total, page=page, pages=pages,
                           q=q, category=category, status=status, base_args=base_args)


def insert_case(d):
    db = get_db()
    cur = db.execute(
        """INSERT INTO cases (case_number, case_reference, category, full_name,
           age, gender, height, identifying_features, clothing, district,
           police_station, date_missing, date_reported, last_seen_location,
           notes, status, reported_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (f"TMP-{secrets.token_hex(6)}", d["case_reference"] or None, d["category"],
         d["full_name"], d["age_value"], d["gender"], d["height_value"],
         d["identifying_features"], d["clothing"], d["district"],
         d["police_station"], d["date_missing"], d["date_reported"],
         d["last_seen_location"], d["notes"], d["status"], g.user["id"]))
    case_id = cur.lastrowid
    number = f"NX-{datetime.now():%Y}-{case_id:05d}"
    db.execute("UPDATE cases SET case_number = ? WHERE id = ?", (number, case_id))
    db.commit()
    return case_id, number


@app.route("/cases/new", methods=["GET", "POST"])
@login_required
def new_case():
    category = request.args.get("category", "Missing Person")
    form = {"category": category if category in CATEGORIES else "Missing Person",
            "status": "Open", "date_reported": date.today().isoformat()}
    if request.method == "POST":
        d, errors = parse_case_form(request.form)
        form = d
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            case_id, number = insert_case(d)
            audit("case_created", number)
            flash(f"Case {number} saved.", "success")
            return redirect(url_for("case_detail", case_id=case_id))
    return render_template("case_form.html", form=form, editing=False)


@app.route("/cases/<int:case_id>/edit", methods=["GET", "POST"])
@login_required
def edit_case(case_id):
    case = get_case_or_404(case_id)
    form = dict(case)
    if request.method == "POST":
        d, errors = parse_case_form(request.form)
        form = d
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            execute(
                """UPDATE cases SET case_reference=?, category=?, full_name=?, age=?, gender=?,
                   height=?, identifying_features=?, clothing=?, district=?, police_station=?,
                   date_missing=?, date_reported=?, last_seen_location=?, notes=?, status=?
                   WHERE id=?""",
                (d["case_reference"] or None, d["category"], d["full_name"], d["age_value"],
                 d["gender"], d["height_value"], d["identifying_features"], d["clothing"],
                 d["district"], d["police_station"], d["date_missing"], d["date_reported"],
                 d["last_seen_location"], d["notes"], d["status"], case_id))
            audit("case_edited", case["case_number"])
            flash("Case updated.", "success")
            return redirect(url_for("case_detail", case_id=case_id))
    return render_template("case_form.html", form=form, editing=True, case=case)


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    case = get_case_or_404(case_id)
    reporter = query("SELECT full_name FROM users WHERE id = ?", (case["reported_by"],), one=True)
    linked = query(
        """SELECT m.*, a.case_number AS an, a.full_name AS aname,
                  b.case_number AS bn, b.full_name AS bname
           FROM matches m JOIN cases a ON a.id = m.case_id JOIN cases b ON b.id = m.matched_case_id
           WHERE m.case_id = ? OR m.matched_case_id = ? ORDER BY m.similarity DESC""",
        (case_id, case_id))
    transfers = query("SELECT * FROM transfers WHERE case_id = ? ORDER BY id DESC", (case_id,))
    existing = {r["matched_case_id"] if r["case_id"] == case_id else r["case_id"] for r in linked}
    suggestions = []
    for other in query("SELECT * FROM cases WHERE id != ? ORDER BY id DESC LIMIT 500", (case_id,)):
        if other["id"] in existing:
            continue
        score = similarity_score(case, other)
        if score >= 40:
            suggestions.append((score, other))
    suggestions.sort(key=lambda s: s[0], reverse=True)
    return render_template("case_detail.html", case=case, reporter=reporter, linked=linked,
                           transfers=transfers, suggestions=suggestions[:5])


@app.route("/cases/<int:case_id>/status", methods=["POST"])
@login_required
def update_case_status(case_id):
    case = get_case_or_404(case_id)
    status = request.form.get("status", "")
    if status not in STATUSES:
        abort(400)
    execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
    audit("case_status", f"{case['case_number']}: {case['status']} -> {status}")
    flash("Case status updated.", "success")
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<int:case_id>/note", methods=["POST"])
@login_required
def add_note(case_id):
    case = get_case_or_404(case_id)
    note = (request.form.get("note") or "").strip()[:2000]
    if not note:
        flash("Write a note first.", "warning")
    else:
        stamp = f"[{datetime.now():%Y-%m-%d %H:%M} {g.user['username']}] {note}"
        combined = ((case["notes"] or "") + "\n\n" + stamp).strip()
        execute("UPDATE cases SET notes = ? WHERE id = ?", (combined, case_id))
        audit("case_note", case["case_number"])
        flash("Note added.", "success")
    return redirect(url_for("case_detail", case_id=case_id))


# ----------------------------------------------------------------- matches

@app.route("/matches")
@login_required
def matches():
    status = request.args.get("status", "")
    status = status if status in MATCH_STATUSES else ""
    rows = query(
        """SELECT m.*, a.case_number AS an, a.full_name AS aname, a.district AS adistrict,
                  a.id AS aid, b.case_number AS bn, b.full_name AS bname,
                  b.district AS bdistrict, b.id AS bid
           FROM matches m JOIN cases a ON a.id = m.case_id JOIN cases b ON b.id = m.matched_case_id
           WHERE (? = '' OR m.status = ?) ORDER BY m.similarity DESC, m.id DESC""",
        (status, status))
    return render_template("matches.html", rows=rows, status=status)


@app.route("/matches/scan", methods=["POST"])
@roles_required("Supervisor", "Admin")
def scan_matches():
    all_cases = query("SELECT * FROM cases ORDER BY id DESC LIMIT 500")
    added = 0
    for i, a in enumerate(all_cases):
        for b in all_cases[i + 1:]:
            score = similarity_score(a, b)
            if score >= 60 and save_match(a["id"], b["id"], score):
                added += 1
    audit("match_scan", f"{added} new")
    flash(f"Scan complete: {added} new potential match(es) queued for review.", "success")
    return redirect(url_for("matches"))


@app.route("/matches/add", methods=["POST"])
@login_required
def add_match():
    a = get_case_or_404(to_int(request.form.get("case_id"), 1, 10**9) or 0)
    b = get_case_or_404(to_int(request.form.get("matched_case_id"), 1, 10**9) or 0)
    if a["id"] == b["id"]:
        abort(400)
    if save_match(a["id"], b["id"], similarity_score(a, b)):
        audit("match_saved", f"{a['case_number']} / {b['case_number']}")
        flash("Saved for review.", "success")
    else:
        flash("This pair is already in the review queue.", "warning")
    return redirect(url_for("case_detail", case_id=a["id"]))


@app.route("/matches/<int:match_id>/status", methods=["POST"])
@roles_required("Supervisor", "Admin")
def update_match_status(match_id):
    status = request.form.get("status", "")
    if status not in MATCH_STATUSES:
        abort(400)
    cur = execute("UPDATE matches SET status = ?, reviewed_by = ? WHERE id = ?",
                  (status, g.user["id"], match_id))
    if cur.rowcount == 0:
        abort(404)
    audit("match_status", f"match {match_id} -> {status}")
    flash("Match status updated.", "success")
    return redirect(safe_next(request.form.get("next")) or url_for("matches"))


# ----------------------------------------------------------------- compare

COMPARE_FIELDS = [("Case number", "case_number"), ("Category", "category"),
                  ("Name", "full_name"), ("Age", "age"), ("Gender", "gender"),
                  ("Height (cm)", "height"), ("District", "district"),
                  ("Police station", "police_station"), ("Date last seen", "date_missing"),
                  ("Last-seen location", "last_seen_location"),
                  ("Identifying features", "identifying_features"),
                  ("Clothing", "clothing"), ("Status", "status")]


@app.route("/compare")
@login_required
def compare():
    a_id = (request.args.get("a") or "").strip()
    b_id = (request.args.get("b") or "").strip()
    result = None
    if a_id and b_id:
        a, b = find_case(a_id), find_case(b_id)
        if not a or not b:
            flash("One or both case numbers were not found.", "error")
        elif a["id"] == b["id"]:
            flash("Choose two different cases.", "error")
        else:
            result = {"a": a, "b": b, "score": similarity_score(a, b),
                      "fields": COMPARE_FIELDS}
    options = query("SELECT case_number, full_name FROM cases ORDER BY id DESC LIMIT 500")
    return render_template("compare.html", result=result, a_id=a_id, b_id=b_id, options=options)


# --------------------------------------------------------------- transfers

@app.route("/transfers", methods=["GET", "POST"])
@login_required
def transfers():
    if request.method == "POST":
        case = find_case(request.form.get("case_number"))
        to_district = (request.form.get("to_district") or "").strip()
        reason = (request.form.get("reason") or "").strip()
        notes = (request.form.get("notes") or "").strip()[:2000]
        if not case:
            error = "Case number not found."
        elif not to_district or reason not in TRANSFER_REASONS:
            error = "Receiving district and a valid reason are required."
        elif norm(to_district) == norm(case["district"]):
            error = "The receiving district must differ from the current district."
        elif query("SELECT 1 FROM transfers WHERE case_id = ? AND status IN ('Pending','Approved')",
                   (case["id"],), one=True):
            error = "This case already has an open transfer request."
        else:
            error = None
        if error:
            flash(error, "error")
        else:
            execute("INSERT INTO transfers (case_id, from_district, to_district, reason, notes, "
                    "requested_by) VALUES (?,?,?,?,?,?)",
                    (case["id"], case["district"], to_district, reason, notes, g.user["id"]))
            audit("transfer_requested", f"{case['case_number']} -> {to_district}")
            flash("Transfer request submitted.", "success")
            return redirect(url_for("transfers"))
    rows = query("""SELECT t.*, c.case_number, c.full_name, u.full_name AS requester
                    FROM transfers t JOIN cases c ON c.id = t.case_id
                    LEFT JOIN users u ON u.id = t.requested_by ORDER BY t.id DESC""")
    options = query("SELECT case_number, full_name, district FROM cases "
                    "WHERE status != 'Closed' ORDER BY id DESC LIMIT 500")
    return render_template("transfers.html", rows=rows, options=options,
                           prefill=request.args.get("case", ""))


@app.route("/transfers/<int:transfer_id>/status", methods=["POST"])
@roles_required("Supervisor", "Admin")
def update_transfer_status(transfer_id):
    transfer = query("SELECT * FROM transfers WHERE id = ?", (transfer_id,), one=True)
    if not transfer:
        abort(404)
    status = request.form.get("status", "")
    if status not in TRANSFER_FLOW.get(transfer["status"], set()):
        flash(f"A {transfer['status'].lower()} transfer cannot be set to "
              f"{status or 'that status'}.", "error")
        return redirect(url_for("transfers"))
    db = get_db()
    db.execute("UPDATE transfers SET status = ?, decided_by = ? WHERE id = ?",
               (status, g.user["id"], transfer_id))
    if status == "Completed":
        db.execute("UPDATE cases SET district = ? WHERE id = ?",
                   (transfer["to_district"], transfer["case_id"]))
    db.commit()
    audit("transfer_status", f"transfer {transfer_id} -> {status}")
    flash("Transfer updated.", "success")
    return redirect(url_for("transfers"))


# ----------------------------------------------------------------- reports

@app.route("/reports")
@roles_required("Supervisor", "Admin")
def reports():
    by_status = query("SELECT status AS label, COUNT(*) AS n FROM cases GROUP BY status ORDER BY n DESC")
    by_category = query("SELECT category AS label, COUNT(*) AS n FROM cases GROUP BY category ORDER BY n DESC")
    by_district = query("SELECT district AS label, COUNT(*) AS n FROM cases GROUP BY district ORDER BY n DESC LIMIT 10")
    by_month = query("SELECT substr(date_reported,1,7) AS label, COUNT(*) AS n FROM cases "
                     "GROUP BY label ORDER BY label DESC LIMIT 12")
    total = query("SELECT COUNT(*) FROM cases", one=True)[0]
    return render_template("reports.html", total=total, sections=[
        ("By status", by_status), ("By category", by_category),
        ("Top districts", by_district), ("Reported per month", by_month)])


def safe_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text and text[0] in "=+-@\t\r" else text


@app.route("/reports/export.csv")
@roles_required("Supervisor", "Admin")
def export_csv():
    rows = query("SELECT * FROM cases ORDER BY id")
    out = io.StringIO()
    writer = csv.writer(out)
    columns = ["case_number", "case_reference", "category", "full_name", "age", "gender",
               "height", "district", "police_station", "date_missing", "date_reported",
               "last_seen_location", "status"]
    writer.writerow(columns)
    for r in rows:
        writer.writerow([safe_cell(r[c]) for c in columns])
    audit("export_csv", f"{len(rows)} rows")
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=nexus_cases.csv"})


# ------------------------------------------------------------- admin pages

@app.route("/admin/users", methods=["GET", "POST"])
@roles_required("Admin")
def users():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        full_name = (request.form.get("full_name") or "").strip()
        role = request.form.get("role", "Officer")
        password = request.form.get("password") or ""
        if not re.fullmatch(r"[a-z0-9._-]{3,30}", username):
            error = "Username: 3-30 characters, letters, numbers, dot, dash or underscore."
        elif not full_name:
            error = "Full name is required."
        elif role not in ROLES:
            error = "Invalid role."
        else:
            error = valid_password(password)
        if not error and query("SELECT 1 FROM users WHERE username = ?", (username,), one=True):
            error = "That username already exists."
        if error:
            flash(error, "error")
        else:
            execute("INSERT INTO users (username, full_name, password_hash, role) VALUES (?,?,?,?)",
                    (username, full_name, generate_password_hash(password), role))
            audit("user_created", f"{username} ({role})")
            flash("User created. They must change the password at first sign-in.", "success")
            return redirect(url_for("users"))
    return render_template("users.html", rows=query("SELECT * FROM users ORDER BY id"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@roles_required("Admin")
def toggle_user(user_id):
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    if user["id"] == g.user["id"]:
        flash("You cannot deactivate your own account.", "error")
    else:
        new_state = 0 if user["active"] else 1
        execute("UPDATE users SET active = ? WHERE id = ?", (new_state, user_id))
        audit("user_active", f"{user['username']} -> {new_state}")
        flash("User updated.", "success")
    return redirect(url_for("users"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@roles_required("Admin")
def reset_user_password(user_id):
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    password = request.form.get("password") or ""
    error = valid_password(password)
    if error:
        flash(error, "error")
    else:
        execute("UPDATE users SET password_hash = ?, must_change = 1 WHERE id = ?",
                (generate_password_hash(password), user_id))
        audit("user_password_reset", user["username"])
        flash("Password reset. The user must change it at next sign-in.", "success")
    return redirect(url_for("users"))


@app.route("/admin/audit")
@roles_required("Admin")
def audit_log():
    return render_template("audit.html",
                           rows=query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300"))


@app.route("/health")
def health():
    query("SELECT 1")
    return {"status": "ok"}


# ------------------------------------------------------------------ errors

def error_page(code, title, message):
    return render_template("error.html", code=code, title=title, message=message), code


@app.errorhandler(400)
def bad_request(_e):
    return error_page(400, "Request not accepted",
                      "The request was invalid or your session expired. Go back and try again.")


@app.errorhandler(403)
def forbidden(_e):
    return error_page(403, "Access denied", "Your role does not allow this action.")


@app.errorhandler(404)
def not_found(_e):
    return error_page(404, "Page not found", "The page or record you requested does not exist.")


@app.errorhandler(500)
def server_error(_e):
    app.logger.exception("Server error on %s", request.path)
    return error_page(500, "Something went wrong", "The error was logged. Please try again.")


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000,
            debug=os.environ.get("NEXUS_DEBUG") == "1")
