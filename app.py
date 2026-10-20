"""DevisPro — gestion de devis (Flask + SQLite)."""
import hashlib
import io
import math
import os
import secrets
import shutil
import sqlite3
import tempfile
import time
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from icons import ICONS

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE, exist_ok=True)

DB_PATH = os.environ.get("DEVISPRO_DB", os.path.join(INSTANCE, "devispro.sqlite"))
CURRENCY = os.environ.get("DEVISPRO_CURRENCY", "Ar")
# Ariary : pas de centimes ; autres devises : 2 décimales (modifiable avec DEVISPRO_DECIMALS)
DECIMALS = int(os.environ.get("DEVISPRO_DECIMALS", 0 if CURRENCY.upper() in ("AR", "MGA") else 2))
COMPANY = {
    "name": os.environ.get("DEVISPRO_COMPANY", "Honey Group Madagascar"),
    "address": os.environ.get("DEVISPRO_ADDRESS", "Lot IVB 48 Andravoahangy, Antananarivo"),
    "email": os.environ.get("DEVISPRO_EMAIL", ""),
}

STATUS = {
    "brouillon": {"label": "Brouillon", "cls": "draft", "color": "#8A8578"},
    "envoye": {"label": "Envoyé", "cls": "sent", "color": "#3B6FA0"},
    "accepte": {"label": "Accepté", "cls": "accepted", "color": "#0E6E55"},
    "refuse": {"label": "Refusé", "cls": "refused", "color": "#B3452C"},
}
ROLES = ("admin", "employe")


def _secret_key():
    env = os.environ.get("DEVISPRO_SECRET")
    if env:
        return env
    path = os.path.join(INSTANCE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
)

# ---------------------------------------------------------------- base de données
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT,
  role TEXT NOT NULL DEFAULT 'employe',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, company TEXT, email TEXT, phone TEXT, address TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, description TEXT,
  unit_price REAL NOT NULL DEFAULT 0, unit TEXT DEFAULT 'unité',
  tva_rate REAL NOT NULL DEFAULT 20,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS quotes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quote_number TEXT UNIQUE NOT NULL,
  client_id INTEGER NOT NULL,
  user_id INTEGER,
  issue_date TEXT NOT NULL, validity_date TEXT,
  status TEXT NOT NULL DEFAULT 'brouillon',
  subtotal REAL NOT NULL DEFAULT 0, tva_amount REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0, notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS quote_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quote_id INTEGER NOT NULL, product_id INTEGER,
  description TEXT NOT NULL,
  quantity REAL NOT NULL DEFAULT 1, unit_price REAL NOT NULL DEFAULT 0,
  tva_rate REAL NOT NULL DEFAULT 20, line_total REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_quotes_client ON quotes(client_id);
CREATE INDEX IF NOT EXISTS idx_items_quote ON quote_items(quote_id);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def q(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def q1(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def run(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur


def like(s):
    """Motif LIKE sûr (échappe % et _ saisis par l'utilisateur)."""
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        username = os.environ.get("DEVISPRO_ADMIN_USER", "admin")
        password = os.environ.get("DEVISPRO_ADMIN_PASSWORD", "admin123")
        conn.execute(
            "INSERT INTO users(username,password_hash,full_name,email,role) VALUES (?,?,?,?,'admin')",
            (username, generate_password_hash(password), "Administrateur", ""),
        )
        conn.commit()
        print(f"[DevisPro] Compte administrateur créé : « {username} ». "
              "Changez son mot de passe dans Profil dès la première connexion.")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- mots de passe
def _legacy_hash(pw):
    """Ancien format (version HTML) : SHA-256 avec sel fixe."""
    return hashlib.sha256(("devispro::salt::" + pw).encode()).hexdigest()


def check_pw(user, pw):
    h = user["password_hash"]
    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        ok = secrets.compare_digest(h, _legacy_hash(pw))
        if ok:  # migration transparente vers un hash moderne
            run("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pw), user["id"]))
        return ok
    return check_password_hash(h, pw)


# ---------------------------------------------------------------- session / sécurité
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def load_user_and_check_csrf():
    if request.endpoint == "static":
        return
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = q1("SELECT * FROM users WHERE id=?", (uid,))
        if g.user is None:
            session.clear()
    if request.method == "POST":
        tok = request.form.get("csrf_token", "")
        if not tok or not secrets.compare_digest(tok, session.get("csrf", "")):
            abort(400, "Session expirée ou formulaire invalide. Rechargez la page et réessayez.")


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if g.user is None:
            nxt = request.full_path.rstrip("?") if request.method == "GET" else None
            return redirect(url_for("login", next=nxt))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if g.user["role"] != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard")


FAILS = {}


def throttled(key):
    now = time.time()
    FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 300]
    return len(FAILS[key]) >= 5


# ---------------------------------------------------------------- templates
@app.context_processor
def inject():
    return {
        "STATUS": STATUS, "COMPANY": COMPANY, "CURRENCY": CURRENCY, "DECIMALS": DECIMALS,
        "csrf_token": csrf_token,
        "csrf_field": lambda: Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'),
        "icon": lambda n: Markup(
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">{ICONS.get(n, "")}</svg>'),
    }


@app.template_filter("money")
def money(n):
    s = f"{float(n or 0):,.{DECIMALS}f}".replace(",", "\u00a0").replace(".", ",")
    return f"{s}\u00a0{CURRENCY}"


@app.template_filter("fdate")
def fdate(s):
    try:
        return date.fromisoformat(s).strftime("%d/%m/%Y")
    except (TypeError, ValueError):
        return s or "—"


@app.template_filter("num")
def num_fmt(n):
    n = float(n or 0)
    return str(int(n)) if n == int(n) else f"{n:g}"


@app.template_filter("initials")
def initials(name):
    parts = (name or "").split()[:2]
    return "".join(p[0].upper() for p in parts) or "?"


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(e):
    return render_template("error.html", code=e.code, message=e.description), e.code


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr, username.lower())
        if throttled(key):
            error = "Trop de tentatives. Réessayez dans quelques minutes."
        else:
            user = q1("SELECT * FROM users WHERE username=?", (username,))
            if user and check_pw(user, password):
                FAILS.pop(key, None)
                session.clear()
                session.permanent = True
                session["uid"] = user["id"]
                first = (user["full_name"].split() or [""])[0]
                flash(f"Bienvenue, {first} 👋", "success")
                return redirect(safe_next(request.form.get("next")))
            FAILS.setdefault(key, []).append(time.time())
            error = "Identifiant ou mot de passe incorrect."
    return render_template("login.html", error=error,
                           next=request.args.get("next") or request.form.get("next") or "")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- tableau de bord
@app.route("/")
@login_required
def dashboard():
    counts = {r["status"]: r["c"] for r in q("SELECT status, COUNT(*) c FROM quotes GROUP BY status")}
    total_quotes = sum(counts.values())
    stats = {
        "total": total_quotes,
        "clients": q1("SELECT COUNT(*) c FROM clients")["c"],
        "revenue": q1("SELECT COALESCE(SUM(total),0) s FROM quotes WHERE status='accepte'")["s"],
        "counts": {k: counts.get(k, 0) for k in STATUS},
    }
    stats["max"] = max([1] + list(stats["counts"].values()))
    recent = q("""SELECT q.*, COALESCE(c.name,'(client supprimé)') client_name FROM quotes q
                  LEFT JOIN clients c ON c.id=q.client_id ORDER BY q.id DESC LIMIT 5""")
    return render_template("dashboard.html", stats=stats, recent=recent)


# ---------------------------------------------------------------- devis : calculs
def to_num(v, default=0.0):
    try:
        x = float(str(v).replace("\u00a0", "").replace(",", ".").strip())
    except ValueError:
        return default
    return x if math.isfinite(x) else default


def parse_items(form):
    """Retourne (lignes, erreur). Les totaux sont toujours recalculés côté serveur."""
    keys = ("product_id", "description", "quantity", "unit_price", "tva_rate")
    items, err = [], None
    for pid, desc, qty, price, tva in zip(*(form.getlist(k) for k in keys)):
        desc = desc.strip()
        it = {"product_id": int(pid) if pid.isdigit() else None, "description": desc,
              "quantity": to_num(qty), "unit_price": to_num(price), "tva_rate": to_num(tva)}
        if not desc and it["unit_price"] == 0:
            continue  # ligne vide ignorée
        items.append(it)
        if not desc:
            err = err or "Une ligne a un prix mais pas de désignation."
        elif it["quantity"] <= 0:
            err = err or f"La quantité de « {desc} » doit être supérieure à 0."
        elif it["unit_price"] < 0 or it["tva_rate"] < 0:
            err = err or f"Prix et TVA de « {desc} » ne peuvent pas être négatifs."
    if not items and not err:
        err = "Ajoutez au moins une ligne (désignation et quantité)."
    return items, err


def compute(items):
    sub = tva = 0.0
    for it in items:
        it["line_total"] = round(it["quantity"] * it["unit_price"], DECIMALS)
        sub += it["line_total"]
        tva += round(it["line_total"] * it["tva_rate"] / 100, DECIMALS)
    return round(sub, DECIMALS), round(tva, DECIMALS), round(sub + tva, DECIMALS)


def next_quote_number(db):
    year = date.today().year
    biggest = 0
    for r in db.execute("SELECT quote_number FROM quotes WHERE quote_number LIKE ?", (f"DEV-{year}-%",)):
        try:
            biggest = max(biggest, int(r["quote_number"].split("-")[2]))
        except (IndexError, ValueError):
            pass
    return f"DEV-{year}-{biggest + 1:04d}"


def write_items(db, qid, items):
    db.executemany(
        "INSERT INTO quote_items(quote_id,product_id,description,quantity,unit_price,tva_rate,line_total)"
        " VALUES (?,?,?,?,?,?,?)",
        [(qid, i["product_id"], i["description"], i["quantity"], i["unit_price"], i["tva_rate"],
          i["line_total"]) for i in items])


def create_quote(db, client_id, user_id, issue, validity, status, notes, items):
    sub, tva, total = compute(items)
    for _ in range(5):  # réessaie si deux devis prennent le même numéro en même temps
        try:
            cur = db.execute(
                "INSERT INTO quotes(quote_number,client_id,user_id,issue_date,validity_date,status,"
                "subtotal,tva_amount,total,notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (next_quote_number(db), client_id, user_id, issue, validity, status, sub, tva, total, notes))
            break
        except sqlite3.IntegrityError:
            db.rollback()
    else:
        raise RuntimeError("Impossible de générer un numéro de devis unique.")
    write_items(db, cur.lastrowid, items)
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------- devis : vues
@app.route("/quotes")
@login_required
def quotes():
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "all")
    sql = """SELECT q.*, COALESCE(c.name,'(client supprimé)') client_name, c.company client_company
             FROM quotes q LEFT JOIN clients c ON c.id=q.client_id WHERE 1=1"""
    params = []
    if search:
        sql += " AND (q.quote_number LIKE ? ESCAPE '\\' OR c.name LIKE ? ESCAPE '\\' OR c.company LIKE ? ESCAPE '\\')"
        params += [like(search)] * 3
    if status in STATUS:
        sql += " AND q.status=?"
        params.append(status)
    rows = q(sql + " ORDER BY q.id DESC", params)
    return render_template("quotes.html", quotes=rows, search=search, status=status)


@app.route("/quotes/<int:qid>")
@login_required
def quote_detail(qid):
    quote = q1("SELECT * FROM quotes WHERE id=?", (qid,)) or abort(404, "Devis introuvable.")
    client = q1("SELECT * FROM clients WHERE id=?", (quote["client_id"],))
    items = q("SELECT * FROM quote_items WHERE quote_id=? ORDER BY id", (qid,))
    author = q1("SELECT full_name FROM users WHERE id=?", (quote["user_id"],)) if quote["user_id"] else None
    return render_template("quote_detail.html", quote=quote, client=client, items=items, author=author)


def _quote_form(qid=None):
    db = get_db()
    quote = None
    if qid:
        quote = q1("SELECT * FROM quotes WHERE id=?", (qid,)) or abort(404, "Devis introuvable.")
    clients = q("SELECT * FROM clients ORDER BY name COLLATE NOCASE")
    if not clients:
        return render_template("quote_form.html", quote=quote, no_clients=True)
    products = q("SELECT * FROM products ORDER BY name COLLATE NOCASE")
    blank = {"product_id": None, "description": "", "quantity": 1, "unit_price": 0, "tva_rate": 20}

    if request.method == "POST":
        items, err = parse_items(request.form)
        form = {"client_id": to_num(request.form.get("client_id"), 0),
                "issue_date": request.form.get("issue_date", "").strip(),
                "validity_date": request.form.get("validity_date", "").strip(),
                "notes": request.form.get("notes", "").strip()}
        form["client_id"] = int(form["client_id"])
        try:
            issue = date.fromisoformat(form["issue_date"])
        except ValueError:
            issue, err = None, err or "La date d'émission est obligatoire."
        if form["validity_date"]:
            try:
                if issue and date.fromisoformat(form["validity_date"]) < issue:
                    err = err or "La date de validité ne peut pas précéder la date d'émission."
            except ValueError:
                err = err or "Date de validité invalide."
        if not q1("SELECT 1 FROM clients WHERE id=?", (form["client_id"],)):
            err = err or "Client introuvable."
        if not err:
            if quote:
                sub, tva, total = compute(items)
                db.execute("UPDATE quotes SET client_id=?,issue_date=?,validity_date=?,subtotal=?,"
                           "tva_amount=?,total=?,notes=? WHERE id=?",
                           (form["client_id"], form["issue_date"], form["validity_date"] or None,
                            sub, tva, total, form["notes"], qid))
                db.execute("DELETE FROM quote_items WHERE quote_id=?", (qid,))
                write_items(db, qid, items)
                db.commit()
                new_id = qid
            else:
                new_id = create_quote(db, form["client_id"], g.user["id"], form["issue_date"],
                                      form["validity_date"] or None, "brouillon", form["notes"], items)
            flash("Devis mis à jour" if quote else "Devis créé", "success")
            return redirect(url_for("quote_detail", qid=new_id))
        flash(err, "error")
    elif quote:
        form = dict(quote)
        items = q("SELECT * FROM quote_items WHERE quote_id=? ORDER BY id", (qid,))
    else:
        form = {"client_id": None, "issue_date": date.today().isoformat(),
                "validity_date": (date.today() + timedelta(days=30)).isoformat(),
                "notes": "Merci de votre confiance."}
        items = []
    return render_template("quote_form.html", quote=quote, form=form, items=items or [blank],
                           blank=blank, clients=clients, products=products)


@app.route("/quotes/new", methods=["GET", "POST"])
@login_required
def quote_new():
    return _quote_form()


@app.route("/quotes/<int:qid>/edit", methods=["GET", "POST"])
@login_required
def quote_edit(qid):
    return _quote_form(qid)


@app.route("/quotes/<int:qid>/status", methods=["POST"])
@login_required
def quote_status(qid):
    status = request.form.get("status")
    if status not in STATUS:
        abort(400, "Statut invalide.")
    if not q1("SELECT 1 FROM quotes WHERE id=?", (qid,)):
        abort(404, "Devis introuvable.")
    run("UPDATE quotes SET status=? WHERE id=?", (status, qid))
    flash(f"Statut mis à jour : {STATUS[status]['label']}", "success")
    return redirect(safe_next(request.form.get("next")))


@app.route("/quotes/<int:qid>/delete", methods=["POST"])
@login_required
def quote_delete(qid):
    db = get_db()
    db.execute("DELETE FROM quote_items WHERE quote_id=?", (qid,))
    db.execute("DELETE FROM quotes WHERE id=?", (qid,))
    db.commit()
    flash("Devis supprimé", "success")
    return redirect(url_for("quotes"))


# ---------------------------------------------------------------- clients
@app.route("/clients")
@login_required
def clients():
    search = request.args.get("q", "").strip()
    sql = "SELECT c.*, (SELECT COUNT(*) FROM quotes WHERE client_id=c.id) nb FROM clients c"
    params = []
    if search:
        sql += " WHERE c.name LIKE ? ESCAPE '\\' OR c.company LIKE ? ESCAPE '\\' OR c.email LIKE ? ESCAPE '\\'"
        params = [like(search)] * 3
    return render_template("clients.html", clients=q(sql + " ORDER BY c.name COLLATE NOCASE", params), search=search)


def _client_form(cid=None):
    client = None
    if cid:
        client = q1("SELECT * FROM clients WHERE id=?", (cid,)) or abort(404, "Client introuvable.")
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("name", "company", "email", "phone", "address")}
        if not f["name"]:
            flash("Le nom est obligatoire", "error")
            return render_template("client_form.html", client=f, editing=bool(cid))
        if cid:
            run("UPDATE clients SET name=?,company=?,email=?,phone=?,address=? WHERE id=?",
                (f["name"], f["company"], f["email"], f["phone"], f["address"], cid))
        else:
            run("INSERT INTO clients(name,company,email,phone,address) VALUES (?,?,?,?,?)",
                (f["name"], f["company"], f["email"], f["phone"], f["address"]))
        flash("Client mis à jour" if cid else "Client ajouté", "success")
        return redirect(url_for("clients"))
    return render_template("client_form.html", client=client, editing=bool(cid))


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def client_new():
    return _client_form()


@app.route("/clients/<int:cid>/edit", methods=["GET", "POST"])
@login_required
def client_edit(cid):
    return _client_form(cid)


@app.route("/clients/<int:cid>/delete", methods=["POST"])
@login_required
def client_delete(cid):
    if q1("SELECT COUNT(*) c FROM quotes WHERE client_id=?", (cid,))["c"]:
        flash("Impossible de supprimer : ce client a des devis associés.", "error")
    else:
        run("DELETE FROM clients WHERE id=?", (cid,))
        flash("Client supprimé", "success")
    return redirect(url_for("clients"))


# ---------------------------------------------------------------- produits
@app.route("/products")
@login_required
def products():
    search = request.args.get("q", "").strip()
    sql, params = "SELECT * FROM products", []
    if search:
        sql += " WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'"
        params = [like(search)] * 2
    return render_template("products.html", products=q(sql + " ORDER BY name COLLATE NOCASE", params), search=search)


def _product_form(pid=None):
    product = None
    if pid:
        product = q1("SELECT * FROM products WHERE id=?", (pid,)) or abort(404, "Produit introuvable.")
    if request.method == "POST":
        f = {"name": request.form.get("name", "").strip(),
             "description": request.form.get("description", "").strip(),
             "unit_price": to_num(request.form.get("unit_price")),
             "unit": request.form.get("unit", "").strip() or "unité",
             "tva_rate": to_num(request.form.get("tva_rate"))}
        err = ("Le nom est obligatoire" if not f["name"]
               else "Prix et TVA ne peuvent pas être négatifs" if f["unit_price"] < 0 or f["tva_rate"] < 0 else None)
        if err:
            flash(err, "error")
            return render_template("product_form.html", product=f, editing=bool(pid))
        vals = (f["name"], f["description"], f["unit_price"], f["unit"], f["tva_rate"])
        if pid:
            run("UPDATE products SET name=?,description=?,unit_price=?,unit=?,tva_rate=? WHERE id=?", vals + (pid,))
        else:
            run("INSERT INTO products(name,description,unit_price,unit,tva_rate) VALUES (?,?,?,?,?)", vals)
        flash("Produit mis à jour" if pid else "Produit ajouté", "success")
        return redirect(url_for("products"))
    return render_template("product_form.html", product=product or {"unit": "unité", "tva_rate": 20, "unit_price": 0},
                           editing=bool(pid))


@app.route("/products/new", methods=["GET", "POST"])
@login_required
def product_new():
    return _product_form()


@app.route("/products/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def product_edit(pid):
    return _product_form(pid)


@app.route("/products/<int:pid>/delete", methods=["POST"])
@login_required
def product_delete(pid):
    db = get_db()
    db.execute("UPDATE quote_items SET product_id=NULL WHERE product_id=?", (pid,))
    db.execute("DELETE FROM products WHERE id=?", (pid,))
    db.commit()
    flash("Produit supprimé", "success")
    return redirect(url_for("products"))


# ---------------------------------------------------------------- utilisateurs (admin)
def admin_count():
    return q1("SELECT COUNT(*) c FROM users WHERE role='admin'")["c"]


@app.route("/users")
@admin_required
def users():
    return render_template("users.html", users=q("SELECT * FROM users ORDER BY full_name COLLATE NOCASE"))


def _user_form(uid=None):
    user = None
    if uid:
        user = q1("SELECT * FROM users WHERE id=?", (uid,)) or abort(404, "Utilisateur introuvable.")
    if request.method == "POST":
        f = {"full_name": request.form.get("full_name", "").strip(),
             "username": request.form.get("username", "").strip(),
             "email": request.form.get("email", "").strip(),
             "role": request.form.get("role", "employe")}
        pw = request.form.get("password", "")
        err = None
        if not f["full_name"] or not f["username"]:
            err = "Nom et identifiant sont obligatoires"
        elif f["role"] not in ROLES:
            err = "Rôle invalide"
        elif q1("SELECT 1 FROM users WHERE username=? AND id!=?", (f["username"], uid or -1)):
            err = "Cet identifiant est déjà utilisé"
        elif (not uid or pw) and len(pw) < 4:
            err = "Le mot de passe doit contenir au moins 4 caractères"
        elif uid and user["role"] == "admin" and f["role"] != "admin" and admin_count() <= 1:
            err = "Impossible de retirer le rôle du dernier administrateur"
        if err:
            flash(err, "error")
            return render_template("user_form.html", user=f, editing=bool(uid))
        if uid:
            run("UPDATE users SET full_name=?,username=?,email=?,role=? WHERE id=?",
                (f["full_name"], f["username"], f["email"], f["role"], uid))
            if pw:
                run("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pw), uid))
        else:
            run("INSERT INTO users(username,password_hash,full_name,email,role) VALUES (?,?,?,?,?)",
                (f["username"], generate_password_hash(pw), f["full_name"], f["email"], f["role"]))
        flash("Utilisateur mis à jour" if uid else "Utilisateur ajouté", "success")
        return redirect(url_for("users"))
    return render_template("user_form.html", user=user or {"role": "employe"}, editing=bool(uid))


@app.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    return _user_form()


@app.route("/users/<int:uid>/edit", methods=["GET", "POST"])
@admin_required
def user_edit(uid):
    return _user_form(uid)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def user_delete(uid):
    user = q1("SELECT * FROM users WHERE id=?", (uid,)) or abort(404, "Utilisateur introuvable.")
    if uid == g.user["id"]:
        flash("Vous ne pouvez pas supprimer votre propre compte", "error")
    elif user["role"] == "admin" and admin_count() <= 1:
        flash("Impossible de supprimer le dernier administrateur", "error")
    else:
        db = get_db()
        db.execute("UPDATE quotes SET user_id=NULL WHERE user_id=?", (uid,))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
        flash("Utilisateur supprimé", "success")
    return redirect(url_for("users"))


# ---------------------------------------------------------------- profil
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name, email = request.form.get("full_name", "").strip(), request.form.get("email", "").strip()
        if not name:
            flash("Le nom est obligatoire", "error")
        else:
            run("UPDATE users SET full_name=?,email=? WHERE id=?", (name, email, g.user["id"]))
            flash("Profil mis à jour", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html")


@app.route("/profile/password", methods=["POST"])
@login_required
def profile_password():
    current, new = request.form.get("current", ""), request.form.get("new", "")
    if not check_pw(g.user, current):
        flash("Mot de passe actuel incorrect", "error")
    elif len(new) < 4:
        flash("Le nouveau mot de passe doit contenir au moins 4 caractères", "error")
    else:
        run("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), g.user["id"]))
        flash("Mot de passe modifié", "success")
    return redirect(url_for("profile"))


# ---------------------------------------------------------------- sauvegarde (admin)
REQUIRED = {
    "users": {"username", "password_hash", "full_name", "role"},
    "clients": {"name"},
    "products": {"name", "unit_price", "tva_rate"},
    "quotes": {"quote_number", "client_id", "issue_date", "status", "subtotal", "tva_amount", "total"},
    "quote_items": {"quote_id", "description", "quantity", "unit_price", "tva_rate"},
}


def validate_backup(path):
    """Retourne un message d'erreur, ou None si la sauvegarde est exploitable."""
    conn = None
    try:
        conn = sqlite3.connect(path)
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            return "La base est corrompue."
        for table, cols in REQUIRED.items():
            have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if not have:
                return f"Table « {table} » manquante : ce n'est pas une sauvegarde DevisPro."
            if cols - have:
                return f"Colonnes manquantes dans « {table} » : {', '.join(sorted(cols - have))}."
        if conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] < 1:
            return "La sauvegarde ne contient aucun administrateur : import refusé pour éviter tout blocage."
    except sqlite3.DatabaseError:
        return "Fichier invalide : impossible de lire cette base de données."
    finally:
        if conn:
            conn.close()
    return None


@app.route("/admin/export")
@admin_required
def export_db():
    fd, tmp = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(tmp)
    src.backup(dst)
    src.close()
    dst.close()
    with open(tmp, "rb") as f:
        data = io.BytesIO(f.read())
    os.remove(tmp)
    return send_file(data, as_attachment=True, mimetype="application/x-sqlite3",
                     download_name=f"devispro-sauvegarde-{date.today().isoformat()}.sqlite")


@app.route("/admin/import", methods=["POST"])
@admin_required
def import_db():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choisissez un fichier .sqlite à importer", "error")
        return redirect(url_for("users"))
    fd, tmp = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        upload.save(tmp)
        err = validate_backup(tmp)
        if err:
            flash(err, "error")
            return redirect(url_for("users"))
        # copie de sécurité de la base actuelle avant remplacement
        backups = os.path.join(INSTANCE, "backups")
        os.makedirs(backups, exist_ok=True)
        get_db().close()
        g.pop("db", None)
        cur = sqlite3.connect(DB_PATH)
        bak = sqlite3.connect(os.path.join(backups, f"avant-import-{datetime.now():%Y%m%d-%H%M%S}.sqlite"))
        cur.backup(bak)
        bak.close()
        cur.close()
        # remplacement du contenu
        src, dst = sqlite3.connect(tmp), sqlite3.connect(DB_PATH)
        src.backup(dst)
        src.close()
        dst.close()
        init_db()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    session.clear()
    flash("Base de données importée. Reconnectez-vous avec les comptes de la sauvegarde.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------- données de démonstration (optionnel)
@app.cli.command("seed-demo")
def seed_demo():
    """Ajoute quelques clients, produits et devis d'exemple : flask --app app seed-demo"""
    db = get_db()
    ins = lambda sql, p: db.execute(sql, p).lastrowid
    c1 = ins("INSERT INTO clients(name,company,email,phone,address) VALUES (?,?,?,?,?)",
             ("Julien Dupont", "Dupont Menuiserie", "contact@dupont-menuiserie.fr", "01 42 55 10 20", "12 rue des Artisans, 75011 Paris"))
    c2 = ins("INSERT INTO clients(name,company,email,phone,address) VALUES (?,?,?,?,?)",
             ("Sophie Martin", "Martin BTP", "s.martin@martin-btp.fr", "04 78 33 44 12", "5 avenue de la République, 69003 Lyon"))
    p1 = ins("INSERT INTO products(name,description,unit_price,unit,tva_rate) VALUES (?,?,?,?,?)",
             ("Prestation de conseil", "Accompagnement et audit", 85, "heure", 20))
    p2 = ins("INSERT INTO products(name,description,unit_price,unit,tva_rate) VALUES (?,?,?,?,?)",
             ("Installation électrique", "Pose et mise en service", 450, "forfait", 20))
    db.commit()
    admin = q1("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")["id"]
    day = lambda n: (date.today() + timedelta(days=n)).isoformat()
    line = lambda pid, d, qty, pr: {"product_id": pid, "description": d, "quantity": qty, "unit_price": pr, "tva_rate": 20}
    create_quote(db, c1, admin, day(-20), day(10), "accepte", "Merci de votre confiance.",
                 [line(p2, "Installation électrique", 1, 450), line(p1, "Prestation de conseil", 2, 85)])
    create_quote(db, c2, admin, day(-6), day(24), "envoye", "Merci de votre confiance.",
                 [line(p1, "Prestation de conseil", 6, 85)])
    print("Données de démonstration ajoutées.")


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", 5000)))
