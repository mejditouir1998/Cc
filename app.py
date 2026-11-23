import os, secrets, sqlite3
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("يجب ضبط SECRET_KEY قبل تشغيل التطبيق")
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "users.db"))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")

def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def init_db():
    with app.app_context():
        db().execute("""CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL)""")
        db().commit()
        email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("ADMIN_PASSWORD", "")
        if email and password and not db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            db().execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
              (os.environ.get("ADMIN_NAME", "مدير النظام"), email, generate_password_hash(password),
               "admin", datetime.now(timezone.utc).isoformat(timespec="seconds")))
            db().commit()

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token, sent = session.get("_csrf"), request.form.get("_csrf", "")
        if not token or not secrets.compare_digest(token, sent): abort(400, description="تعذر التحقق من الطلب. أعد تحميل الصفحة.")

@app.context_processor
def inject_csrf():
    def csrf_token():
        if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]
    return {"csrf_token": csrf_token}

def current_user():
    uid = session.get("user_id")
    return db().execute("SELECT id,name,email,role,created_at FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user(): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        u = current_user()
        if not u: return redirect(url_for("login"))
        if u["role"] != "admin": abort(403)
        return fn(*a, **kw)
    return wrapped

@app.route("/")
def home():
    u = current_user()
    return redirect(url_for("admin" if u and u["role"] == "admin" else "dashboard" if u else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email = request.form.get("name","").strip(), request.form.get("email","").strip().lower()
        password, confirm = request.form.get("password",""), request.form.get("confirm","")
        if len(name) < 2 or len(password) < 8 or password != confirm or "@" not in email:
            flash("تحقق من البيانات وكلمة المرور (8 أحرف على الأقل).", "error")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                  (name,email,generate_password_hash(password),"user",datetime.now(timezone.utc).isoformat(timespec="seconds")))
                db().commit()
                flash("تم إنشاء الحساب. يمكنك تسجيل الدخول الآن.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("هذا البريد الإلكتروني مسجل بالفعل.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email","").strip().lower(), request.form.get("password","")
        u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u["password_hash"], password):
            session.clear()
            session["user_id"] = u["id"]
            return redirect(url_for("home"))
        flash("البريد الإلكتروني أو كلمة المرور غير صحيحة.", "error")
    return render_template("auth.html", mode="login")

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return redirect(url_for("admin")) if u["role"] == "admin" else render_template("user.html", user=u)

@app.route("/admin")
@admin_required
def admin():
    users = db().execute("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC").fetchall()
    return render_template("admin.html", users=users, user=current_user())

@app.post("/admin/user/<int:user_id>/role")
@admin_required
def change_role(user_id):
    role = request.form.get("role")
    if user_id == session["user_id"] or role not in ("admin","user"): abort(400)
    if not db().execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone(): abort(404)
    db().execute("UPDATE users SET role=? WHERE id=?", (role,user_id)); db().commit()
    flash("تم تحديث الصلاحية.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/user/<int:user_id>/delete")
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]: abort(400)
    db().execute("DELETE FROM users WHERE id=?", (user_id,)); db().commit()
    flash("تم حذف الحساب إن كان موجوداً.", "success")
    return redirect(url_for("admin"))

@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def error_page(error):
    messages = {400:"طلب غير صالح.",403:"ليست لديك صلاحية للوصول إلى هذه الصفحة.",404:"الصفحة غير موجودة."}
    msg = error.description if error.code == 400 and getattr(error,"description",None) else messages[error.code]
    return render_template("error.html", code=error.code, message=msg), error.code

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")))
