"""Local administrator authentication for the standalone router."""
import fcntl
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from flask import request, session, redirect, url_for, render_template, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash


def install(app):
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=256 * 1024)
    app.config.setdefault("AUTH_DIRECTORY", os.environ.get("ROUTER_AUTH_DIRECTORY", "/data/auth"))

    @contextmanager
    def database():
        directory = Path(app.config["AUTH_DIRECTORY"])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (directory / "init.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = directory / "admin.sqlite3"
            db = sqlite3.connect(path, timeout=10)
            os.chmod(path, 0o600)
            db.row_factory = sqlite3.Row
            db.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, password TEXT NOT NULL, version TEXT NOT NULL, initial INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS attempts (ip TEXT PRIMARY KEY, failures INTEGER, start REAL)")
            if not db.execute("SELECT 1 FROM admin WHERE id=1").fetchone():
                db.execute("INSERT INTO admin VALUES (1, ?, ?, 1)", (generate_password_hash("admin"), secrets.token_hex(24)))
                db.commit()
            fcntl.flock(lock, fcntl.LOCK_UN)
            try:
                yield db
                db.commit()
            finally:
                db.close()

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def current_admin():
        with database() as db:
            return dict(db.execute("SELECT * FROM admin WHERE id=1").fetchone())

    @app.before_request
    def protect():
        if request.endpoint == "static":
            return
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            token = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
            if not token or not hmac.compare_digest(token, session.get("csrf", "")):
                abort(400, "Sessão do formulário expirou. Recarregue a página.")
        if request.endpoint == "login":
            return
        admin = current_admin()
        if session.get("admin_version") != admin["version"]:
            session.clear()
            return redirect(url_for("login"))
        if admin["initial"] and request.endpoint not in ("system_page", "change_password", "logout"):
            return redirect(url_for("system_page"))

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            with database() as db:
                db.execute("DELETE FROM attempts WHERE start < ?", (time.time() - 900,))
                attempt = db.execute("SELECT * FROM attempts WHERE ip=?", (ip,)).fetchone()
                if attempt and attempt["failures"] >= 5:
                    return render_template("login.html", error="Muitas tentativas. Aguarde 15 minutos."), 429
                admin = db.execute("SELECT * FROM admin WHERE id=1").fetchone()
                valid = check_password_hash(admin["password"], request.form.get("password", ""))
                if request.form.get("username") == "admin" and valid:
                    db.execute("DELETE FROM attempts WHERE ip=?", (ip,))
                    session.clear()
                    session["admin_version"] = admin["version"]
                    session["csrf"] = secrets.token_hex(32)
                    session.permanent = True
                    return redirect(url_for("system_page" if admin["initial"] else "dashboard"))
                db.execute("INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(ip) DO UPDATE SET failures=failures+1", (ip, time.time()))
                error = "Usuário ou senha inválidos."
        return render_template("login.html", error=error), (401 if error else 200)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.post("/system/password")
    def change_password():
        with database() as db:
            admin = db.execute("SELECT * FROM admin WHERE id=1").fetchone()
            password = request.form.get("new_password", "")
            if not check_password_hash(admin["password"], request.form.get("current_password", "")):
                flash("Senha atual incorreta.")
            elif len(password) < 10 or len(password) > 128 or password != request.form.get("confirm_password"):
                flash("Informe e confirme uma senha de 10 a 128 caracteres.")
            else:
                version = secrets.token_hex(24)
                db.execute("UPDATE admin SET password=?, version=?, initial=0 WHERE id=1", (generate_password_hash(password), version))
                session.clear()
                session["admin_version"] = version
                session["csrf"] = secrets.token_hex(32)
                session.permanent = True
                flash("Senha do painel alterada. Outras sessões foram encerradas.")
        return redirect(url_for("system_page"))

    return current_admin
